#include "ArachnePlugin.h"
#include "ClientSession.h"
#include "IniFile.h"
#include "Firewall.h"
#include "Logger.h"

#include <cstring>
#include <cstdarg>
#include <ctime>
#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_set>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>

#define URL_AUTH     "/auth"
#define URL_FIREWALL "/firewall"

static const std::string FN_IP_FORWARD("/proc/sys/net/ipv4/ip_forward");

ArachnePlugin::ArachnePlugin(const openvpn_plugin_args_open_in *in_args)
{
    _log_func = in_args->callbacks->plugin_vlog;
    time(&_startupTime);
    _logger = new Logger(this);

    _logger->levelNote();
    *_logger << "Initializing plugin..." << std::endl;

    parseOptions(in_args->argv);

    enableIpForwarding();

    _sessionCounter = 0;
}

ArachnePlugin::~ArachnePlugin()
{
    _logger->levelNote();
    *_logger << "Unloading Arachne plugin..." << std::endl;

    resetIpForwarding();
}

const char* ArachnePlugin::getenv(const char* key, const char *envp[])
{
    if (envp) {
        int i;
        int keylen = strlen(key);
        for (i = 0; envp[i]; i++) {
            if (!strncmp(envp[i], key, keylen)) {
                const char *cp = envp[i] + keylen;
                if (*cp == '=') {
                    return cp + 1;
                }
            }
        }
    }

    return "";
}

int ArachnePlugin::getFirewallWhats(boost::property_tree::ptree::value_type &node,
                                    std::vector<std::string> &whats,
                          ClientSession *session) noexcept
{
    std::string whatType = node.second.get<std::string>("whatType");

    if (whatType == "Service") {
    	BOOST_FOREACH(boost::property_tree::ptree::value_type &pp, node.second.get_child("whatService")) {
    		auto port = pp.second.get<std::string>("port");
    		auto protocol = pp.second.get<std::string>("protocol");
    		std::stringstream str;
    		str << "port port=\"" << port << "\" protocol=\"" << protocol << "\"";
    		whats.push_back(str.str());
    	}
    }
    else if (whatType == "Everything") {
        whats.push_back("");
    }
    else if (whatType == "PortListProtocol") {
        std::string protocol = node.second.get<std::string>("whatProtocol");
        boost::algorithm::to_lower(protocol);
        BOOST_FOREACH(boost::property_tree::ptree::value_type &port, node.second.get_child("whatPorts")) {
            std::stringstream str;
            str << "port port=\""  << port.second.get_value<std::string>() << "\" "
                << "protocol=\"" << protocol << "\"";
            whats.push_back(str.str());
        }
    }
    else if (whatType == "PortProtocol") {
        std::string protocol = node.second.get<std::string>("whatProtocol");
        boost::algorithm::to_lower(protocol);
        std::string port = node.second.get<std::string>("whatPort");

        std::stringstream str;
        str << "port port=\"" << port << "\" protocol=\"" << protocol << "\"";
        whats.push_back(str.str());
    }
    else if (whatType == "PortRangeProtocol") {
        std::string protocol = node.second.get<std::string>("whatProtocol");
        boost::algorithm::to_lower(protocol);
        std::string portFrom = node.second.get<std::string>("whatPortFrom");
        std::string portTo = node.second.get<std::string>("whatPortTo");

        std::stringstream str;
        str << "port port=\"" << portFrom << "-" << portTo << "\" protocol=\"" << protocol << "\"";
        whats.push_back(str.str());
    }
    else {
        session->logger().levelErr();
        session->logger() << "Invalid whatType: " << whatType << std::endl;
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::getFirewallWheres(boost::property_tree::ptree::value_type &node,
                                     std::vector<std::string> &wheres,
                          ClientSession *session) noexcept
{
    std::string whereType = node.second.get<std::string>("whereType");
    if (whereType == "Hostname") {
        std::string hostname;
        try {
            hostname = node.second.get<std::string>("whereHostname");
        }
        catch (const std::exception &ex) {
            session->logger().levelErr();
            session->logger() << "Cannot find hostname JSON reply: "
                << ex.what() << std::endl;
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
        try {
            boost::asio::io_service io_service;
            boost::asio::ip::tcp::resolver resolver(io_service);
            boost::asio::ip::tcp::resolver::query query(hostname, "");
            boost::asio::ip::tcp::resolver::iterator host = resolver.resolve(query);
            boost::asio::ip::tcp::resolver::iterator end;
            boost::asio::ip::tcp::endpoint endpoint;
            while (host != end) {
                endpoint = *host++;
                std::string address = endpoint.address().to_string();
                wheres.push_back(address);
            }
        }
        catch (const std::exception &ex) {
            session->logger().levelErr();
            session->logger() << "Cannot resolve hostname " << hostname
                << ": " << ex.what() << std::endl;
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    }
    else if (whereType == "Network") {
        try {
            std::string network = node.second.get<std::string>("whereNetwork");
            std::string mask = node.second.get<std::string>("whereMask");
            wheres.push_back(network + "/" + mask);
        }
        catch (const std::exception &ex) {
            session->logger().levelErr();
            session->logger() << "Cannot find network or mask: " << ex.what() << std::endl;
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    }
    else if (whereType == "Everywhere") {
        wheres.push_back("0.0.0.0/0");
    }
    else {
        session->logger().levelErr();
        session->logger() << "Invalid whereType: " << whereType << std::endl;
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::setupFirewall(const std::string &clientIp, ClientSession *session) noexcept
{
    Url url(_authUrl);
    url.path(_authUrl.path() + URL_FIREWALL);
    boost::property_tree::ptree json;
    try {
        session->getFirewallConfig(url, json);
    }
    catch (const std::exception &ex) {
        session->logger().levelErr();
        session->logger() << "Cannot parse json. " << ex.what() << std::endl;
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    BOOST_FOREACH(boost::property_tree::ptree::value_type &v, json.get_child("incoming"))
    {
        std::vector<std::string> wheres;
        std::vector<std::string> whats;

        int ret;
        if (ret = getFirewallWheres(v, wheres, session) != OPENVPN_PLUGIN_FUNC_SUCCESS)
            return ret;
        if (ret = getFirewallWhats(v, whats, session) != OPENVPN_PLUGIN_FUNC_SUCCESS)
            return ret;

        for (std::vector<std::string>::iterator where = wheres.begin(); where != wheres.end(); ++where) {
            for (std::vector<std::string>::iterator what = whats.begin(); what != whats.end(); ++what) {
                std::stringstream str;
                str
                    << "rule family=\"ipv4\" "
                    << "source address=\"" << clientIp << "\" "
                    << "destination address=\"" << *where << "\" "
                    << *what << " "
                    << "accept";

                session->richRules().insert(str.str());
            }
        }
    }

    session->logger().levelNote();
    session->logger() << "Adding " << session->richRules().size()
        << " rich rules to zone " << _firewallZone << std::endl;
    for (auto &it : session->richRules()) {
        try {
            session->logger().levelNote();
            session->logger() << "Rich rule >>" << it << "<<" << std::endl;
            _firewall.addRichRule(_firewallZone, it);
        }
        catch (const std::exception &ex) {
            session->logger().levelErr();
            session->logger() << "Cannot add rich rule " << ex.what() << std::endl;

            try {
                for (auto &it : session->richRules()) {
                    _firewall.removeRichRule(_firewallZone, it);
                }
            }
            catch (const std::exception &ex) {
            }

            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::clientDisconnect(const char *argv[], const char *envp[], ClientSession*session) noexcept
{
    if (_manageFirewall) {
        try {
            session->logger().levelNote();
            session->logger() << "Removing " << session->richRules().size()
                << " rich rules from zone " << _firewallZone << std::endl;
            for (auto &it : session->richRules()) {
                _firewall.removeRichRule(_firewallZone, it);
            }
        }
        catch (const std::exception &ex) {
            session->logger().levelErr();
            session->logger() << "Cannot remove rule " << ex.what() << std::endl;
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::clientConnect(const char *argv[], const char *envp[], ClientSession* session) noexcept
{
    session->logger().levelNote();
    session->logger() << "Client connected" << std::endl;

    if (_manageFirewall) {
        int ret = setupFirewall(getenv("ifconfig_pool_remote_ip", envp), session);
        if (ret != OPENVPN_PLUGIN_FUNC_SUCCESS)
            return ret;
    }
    else {
        session->logger().levelNote();
        session->logger() << "Firewall management disabled => no rules" << std::endl;
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::userAuthPassword(const char *argv[], const char *envp[],
    ClientSession* session) noexcept
{
    bool authSuccessfull = true;
    std::string username(getenv("username", envp));
    std::string password(getenv("password", envp));

    _logger->levelNote();
    session->logger() << "Trying to authenticate user " << username << "..." << std::endl;

    Url url(_authUrl);
    url.path(_authUrl.path() + URL_AUTH);
    authSuccessfull = session->authUser(url, username, password);

    if (authSuccessfull) {
        _logger->levelNote();
        session->logger() << "User " << username << " authenticated successfully" << std::endl;
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }
    else {
        _logger->levelErr();
        session->logger() << "Authentication for user " << username << " failed" << std::endl;
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

int ArachnePlugin::pluginUp(const char *argv[], const char *envp[],
    ClientSession* session) noexcept
{
    _logger->levelNote();
    session->logger() << "Opening device " << getenv("dev", envp) << "..." << std::endl;

    if (_manageFirewall) {
        try {
            _logger->levelNote();
            session->logger() << "Creating firewall zone " << _firewallZone << std::endl;
            _firewall.addZone(_firewallZone, "tun0");
            _firewall.reload();
        }
        catch (FirewallRuntimeException &ex) {
            if (ex.type() != FirewallRuntimeException::NAME_CONFLICT) {
                _logger->levelErr();
                session->logger() << "Error creating firewall zone(" << ex.type()
                    << "): " << ex.what() << std::endl;
                return OPENVPN_PLUGIN_FUNC_ERROR;
            }
            _logger->levelNote();
            session->logger() << "Zone " << _firewallZone << " already exists" << std::endl;
        }
    }
    else {
        _logger->levelNote();
        session->logger() << "No firewall zone requested" << std::endl;
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::pluginDown(const char *argv[], const char *envp[],
    ClientSession* session) noexcept
{
    _logger->levelNote();
    session->logger() << "Closing device " << getenv("dev", envp) << std::endl;

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

ClientSession *ArachnePlugin::createClientSession()
{
    ClientSession *session = new ClientSession(*this, ++_sessionCounter);

    return session;
}

void ArachnePlugin::parseOptions(const char **argv)
{
    IniFile iniFile;

    for (const char **arg = argv+1; *arg != 0; arg++) {
        std::string args(*arg);

        std::size_t found = args.find("=");
        if (found == std::string::npos) {
            std::stringstream msg;
            msg << "Key value pair expected: " << args;
            throw (PluginException(msg.str()));
        }
        std::string key = args.substr(0, found);
        std::string value = args.substr(found+1);

        if (key == "url") {
            _authUrl = value;
        }
        else if (key == "cafile") {
            _caFile = value;
        }
        else if (key == "ignoressl") {
            if (value == "1" or value == "true" or value == "yes") {
                _ignoreSsl = true;
            }
            else if (value == "0" or value == "false" or value == "no") {
                _ignoreSsl = false;
            }
            else {
                std::stringstream msg;
                msg << "Boolean value expected for parameter " << key << ": " << value;
                throw (PluginException(msg.str()));
            }
        }
        else if (key == "config") {
            std::string authUrl = _authUrl.str();
            IniFile iniFile;
            iniFile.insert("url", authUrl);
            iniFile.insert("cafile", _caFile);
            iniFile.insert("ignoressl", _ignoreSsl);
            iniFile.insert("handleipforwarding", _handleIpForwarding);
            iniFile.insert("manageFirewall", _manageFirewall);
            iniFile.insert("firewallZone", _firewallZone);

            std::ostringstream buf;
            _logger->levelNote();
            *_logger << "Reading config file " << value << std::endl;

            std::ifstream ifs;
            ifs.open (value, std::ifstream::in);
            if (!ifs.is_open()) {
                throw std::runtime_error("Cannot open config file");
            }
            iniFile.load(ifs);
            ifs.close();

            _authUrl = Url(authUrl);
        }
        else {
            std::stringstream msg;
            msg << "Invalid key: " << key;
            throw (PluginException(msg.str()));
        }
    }
}

void ArachnePlugin::enableIpForwarding()
{
    if (_handleIpForwarding) {
        _logger->levelNote();
        *_logger << "Enabling IP forwarding" << std::endl;

        std::ifstream ifs;
        ifs.open(FN_IP_FORWARD);
        if (!ifs.is_open()) {
            std::ostringstream buf;
            buf << "Cannot open " << FN_IP_FORWARD << " for reading";
            throw PluginException(buf.str());
        }
        try {
            getline(ifs, _oldIpForwarding);
            ifs.close();
        }
        catch (std::exception &ex) {
            std::ostringstream buf;
            buf << "Error reading status of IP forwarding from " << FN_IP_FORWARD;
            throw PluginException(buf.str());
        }

        std::ofstream ofs;
        ofs.open(FN_IP_FORWARD);
        if (!ofs.is_open()) {
            std::ostringstream buf;
            buf << "Cannot open " << FN_IP_FORWARD << "=> cannot activate IP forwarding";
            throw PluginException(buf.str());
        }
        ofs << "1" << std::endl;
        ofs.close();
    }
    else {
        _logger->levelNote();
        *_logger << "Leaving IP forwarding untouched"  << std::endl;
    }
}

void ArachnePlugin::resetIpForwarding()
{
    if (_handleIpForwarding) {
        _logger->levelNote();
        *_logger << "Resetting IP forwarding: " << _oldIpForwarding << std::endl;

        std::ofstream ofs;
        ofs.open(FN_IP_FORWARD);
        if (!ofs.is_open()) {
            std::ostringstream buf;
            buf << "Error reading status of IP forwarding from " << FN_IP_FORWARD << std::endl;
            throw PluginException(buf.str());
        }
        try {
            ofs << _oldIpForwarding << std::endl;
            ofs.close();
        }
        catch (std::exception &s) {
            std::ostringstream buf;
            buf << "Error resetting IP forwarding, cannot write to " << FN_IP_FORWARD << std::endl;
            throw PluginException(buf.str());
        }
    }
    else {
        _logger->levelNote();
        *_logger << "Leaving IP forwarding untouched" << std::endl;
    }
}
