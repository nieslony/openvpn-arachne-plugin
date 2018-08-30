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

static const std::string FN_IP_FORWARD("/proc/sys/net/ipv4/ip_forward");

ArachnePlugin::ArachnePlugin(const openvpn_plugin_args_open_in *in_args)
    : _ignoreSsl(false), _handleIpForwarding(false)
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

int ArachnePlugin::userAuthPassword(const char *argv[], const char *envp[],
    ClientSession* session)
{
    bool authSuccessfull = true;
    std::string username(getenv("username", envp));
    std::string password(getenv("password", envp));

    _logger->levelNote();
    session->logger() << "Trying to authenticate user " << username << "..." << std::endl;

    authSuccessfull = _http.get(_authUrl, username, password) == 200;

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
    ClientSession* session)
{
    _logger->levelNote();
    session->logger() << "Opening device " << getenv("dev", envp) << "..." << std::endl;

    Firewall firewall;
    firewall.init();

    if (_manageFirewall) {
        try {
            _logger->levelNote();
            session->logger() << "Creating firewall zone " << _firewallZone << std::endl;
            firewall.createZone(_firewallZone, "tun0");
        }
        catch (DBus::Error &ex) {
            //std::cerr << ex.what() << std::endl;
            if (ex.name() == Firewall::FIREWALLD1_EXCEPTION) {
                std::string type;
                std::string param;
                Firewall::exceptionType(ex, type, param);

                if (type == Firewall::FIREWALLD1_EX_NAME_CONFLICT) {
                    _logger->levelNote();
                    session->logger() << "Firewall zone " << _firewallZone << " already exists, reusing it";
                }
                else {
                    _logger->levelErr();
                    session->logger() << "Unhandled DBus::Error " << type << std::endl;
                    throw ex;
                }
            }
            else {
                _logger->levelErr();
                session->logger() << "Unknown exception" << std::endl;
                throw ex;
            }
        }
    }
    else {
        _logger->levelNote();
        session->logger() << "No firewall zone requested" << std::endl;
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::pluginDown(const char *argv[], const char *envp[],
    ClientSession* session)
{
    _logger->levelNote();
    session->logger() << "Closing device " << getenv("dev", envp) << std::endl;

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

void ArachnePlugin::chop(std::string &s)
{
    size_t pos;

    while ( (pos = s.find("\r")) != std::string::npos)
        s.erase(pos, 1);

    while ( (pos = s.find("\n")) != std::string::npos)
        s.erase(pos, 1);
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
            std::unordered_set<std::string> keys;
            keys.insert("url");
            keys.insert("cafile");
            keys.insert("ignoressl");
            keys.insert("handleipforwarding");
            keys.insert("manageFirewall");
            keys.insert("firewallZone");

            std::ostringstream buf;
            _logger->levelNote();
            *_logger << "Reading config file " << value << std::endl;

            std::ifstream ifs;
            ifs.open (value, std::ifstream::in);
            if (!ifs.is_open()) {
                throw std::runtime_error("Cannot open config file");
            }
            iniFile.load(ifs, keys);
            ifs.close();
        }
        else {
            std::stringstream msg;
            msg << "Invalid key: " << key;
            throw (PluginException(msg.str()));
        }
    }

    std::string s;
    if (iniFile.get("url", s))
        _authUrl = s;
    iniFile.get("cafile", _caFile);
    iniFile.get("ignoressl", _ignoreSsl);
    iniFile.get("handleipforwarding", _handleIpForwarding);
    iniFile.get("manageFirewall", _manageFirewall);
    iniFile.get("firewallZone", _firewallZone);
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
