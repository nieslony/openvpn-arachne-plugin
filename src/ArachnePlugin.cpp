#include "ArachnePlugin.h"
#include "ClientSession.h"
#include "Config.h"
#include "FirewallD1.h"

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <cerrno>
#include <fstream>
#include <sstream>
#include <numeric>

#include <ifaddrs.h>
#include <arpa/inet.h>

static const std::string FN_IP_FORWATD = "/proc/sys/net/ipv4/ip_forward";

ArachnePlugin::ArachnePlugin(const openvpn_plugin_args_open_in *in_args) :
    _logger(in_args->callbacks->plugin_vlog),
    _lastSession(0),
    _dbusConnection(sdbus::createSystemBusConnection()),
    _firewallZone(_dbusConnection),
    _firewallPolicy(_dbusConnection)
{
    _logger.note() << "Initializing" << "..." << std::flush;
    _logFunc = in_args->callbacks->plugin_vlog;

    const char* configFile = in_args->argv[1];
    if (configFile == NULL)
        throw PluginException("Please specify configuration file");
    _logger.note() << "Reading configuration from " << configFile << std::flush;

    readConfigFile(configFile);
    _authUrl = _config.get("auth-url", "");
    _enableRouting = _config.get("enable-routing");
    _enableFirewall = _config.getBool("enable-firewall", false);
    if (_enableFirewall) {
        _firewallZoneName = _config.get("firewall-zone");
        _firewallUrlUser = _config.get("firewall-url") + "/user_rules";
        _firewallUrlEverybody = _config.get("firewall-url") + "/everybody_rules";
    }
    _clientConfig = _config.get("client-config", "");
}

ArachnePlugin::~ArachnePlugin()
{
}

ClientSession *ArachnePlugin::createClientSession()
{
    return new ClientSession(*this, _logFunc, ++_lastSession);
}

std::ostream &ArachnePlugin::dumpEnv(std::ostream &os, const char *envp[])
{
    if (envp) {
        for (int i = 0; envp[i]; i++) {
            os << envp[i] << " ";
        }
    }

    return os;
}

const char* ArachnePlugin::getEnv(const char* key, const char *envp[])
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

    std::stringstream msg;
    msg << "Enviroment variable " << key << " not defined";
    throw PluginException(msg.str());
}

int ArachnePlugin::userAuthPassword(const char *envp[], ClientSession* session)
{
    std::string username(getEnv("username", envp));
    std::string password(getEnv("password", envp));

    Url url(_authUrl);
    if (session->authUser(url, username, password))
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    else
        return OPENVPN_PLUGIN_FUNC_ERROR;
}

void ArachnePlugin::readConfigFile(const char*filename)
{
    std::ifstream ifs;
    ifs.open (filename, std::ifstream::in);
    if (!ifs.is_open()) {
        throw std::runtime_error("Cannot open config file");
    }
    _config.load(ifs);
    ifs.close();
}

std::string ArachnePlugin::getRoutingStatus()
{
    std::string s;
    std::ifstream ifs;
    ifs.open (FN_IP_FORWATD);
    if (!ifs.is_open()) {
        throw std::runtime_error("Error opening " + FN_IP_FORWATD);
    }
    ifs >> s;
    ifs.close();
    _logger.note() << "Got routíng status: \"" << s << "\"" << std::flush;
    return s;
}

void ArachnePlugin::setRoutingStatus(const std::string& forward)
{
    std::ofstream ofs;
    ofs.open(FN_IP_FORWATD);
    if (!ofs.is_open()) {
        throw std::runtime_error("Cannot open " + FN_IP_FORWATD + " for reading");
    }
    _logger.note() << "echo " << forward << " > " << FN_IP_FORWATD << std::flush;
    ofs << forward << std::endl;
    ofs.close();
}

void ArachnePlugin::setRouting(ClientSession *session)
{
    if (_enableRouting == "RESTORE_ON_EXIT") {
        _savedIpForward = getRoutingStatus();
        if (_savedIpForward == "0") {
            session->getLogger().note() << "Enabling IP forwarding" << std::flush;
            setRoutingStatus("1");
        } else {
            session->getLogger().note() << "IP forwarding already enabled" << std::flush;
        }
    } else if (_enableRouting == "ENABLE") {
        session->getLogger().note() << "Enabling IP forwarding" << std::flush;
        setRoutingStatus("1");
    } else if (_enableRouting == "OFF") {
        session->getLogger().note() << "Don't enable IP forwarding" << std::flush;
    } else {
        throw PluginException("Invalid value of enable-routing: " + _enableRouting);
    }
}

void ArachnePlugin::restoreRouting(ClientSession *session)
{
    if (_savedIpForward != "1" && _savedIpForward != "") {
        session->getLogger().note() << "Restoring IP forwading to " << _savedIpForward << std::flush;
        setRoutingStatus(_savedIpForward);
    } else {
        session->getLogger().note() << "Leaving routing untouched" << std::flush;
    }
}

void ArachnePlugin::createFirewallZone(ClientSession *session)
{
    if (_enableFirewall) {
        auto connection = sdbus::createSystemBusConnection();
        FirewallD1 firewall(connection);
        FirewallD1_Config firewallConfig(connection);

        try {
            std::vector<std::string> zones = firewallConfig.getZoneNames();
            if (std::any_of(
                zones.begin(), zones.end(),
                [this](std::string s){ return s == _firewallZoneName; }
            )
            ) {
                session->getLogger().note()
                    << "Firewall Zone '" << _firewallZoneName << "' already exists"
                    << std::flush;
            }
            else {
                session->getLogger().note()
                    << "Creating firewall zone '" << _firewallZoneName << "'"
                    << std::flush;
                std::map<std::string, sdbus::Variant> settings;
                settings["target"] = "DROP";
                settings["interfaces"] = std::vector<std::string> { "arachne" };
                firewallConfig.addZone2(_firewallZoneName, settings);
            }

            std::vector<std::string> currentPolicies = firewallConfig.getPolicyNames();
            std::map<std::string, std::vector<std::string>> policies;
            policies["arachne-incoming"] = { "arachne", "public" };
            policies["arachne-outgoing"] = { "public", "arachne" };
            for (const auto&[pname, pzones] : policies) {
                if (std::any_of(
                    currentPolicies.begin(), currentPolicies.end(),
                    [pname](std::string s){ return s == pname; }
                )
                ) {
                    session->getLogger().note()
                        << "Firewall Policy '" << pname << "' already exists"
                        << std::flush;
                }
                else {
                    session->getLogger().note()
                        << "Creating firewall policy '" << pname << "'"
                        << std::flush;
                    std::map<std::string, sdbus::Variant> settings;
                    settings["ingress_zones"] = std::vector<std::string> ({
                        policies[pname].at(0)
                    });
                    settings["egress_zones"] = std::vector<std::string> ({
                        policies[pname].at(1)
                    });
                    settings["target"] = "CONTINUE";
                    firewallConfig.addPolicy(pname, settings);
                }
            }
            firewall.reload();
        }
        catch (const sdbus::Error &ex)
        {
            std::stringstream msg;
            msg << "Cannot create firewall zone " << _firewallZoneName
                << ": [" << ex.getName() << "]: "
                << ex.getMessage()
                ;
            throw PluginException(msg.str());

        }
    } else {
        _logger.note() << "Firewall is disabled" << std::flush;
    }
}

int ArachnePlugin::pluginUp(const char *argv[], const char *envp[], ClientSession*session) noexcept
{
    session->getLogger().note() << "Plugin up..." << std::flush;
    setRouting(session);
    createFirewallZone(session);
    removeAllRichRules();
    getLocalIpAddresses();

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::pluginDown(const char *argv[], const char *envp[], ClientSession* session) noexcept
{
    session->getLogger() << "Plugin down..." << std::flush;
    removeAllRichRules();
    restoreRouting(session);

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::clientConnect(
    const char *argv[],
    const char *envp[],
    ClientSession*session
) noexcept
{
    //dumpEnv(session->getLogger().note(), envp) << std::flush;
    _logger.note() << "Client connected" << std::flush;
    if (!_clientConfig.empty()) {
        try {
            session->setCommonName(getEnv("common_name", envp));
            session->setClientIp(getEnv("untrusted_ip", envp));
        }
        catch (PluginException &ex) {
            _logger.error() << ex.what() << std::flush;
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
        try {
            session->readConfigFile(_clientConfig);
            if (!session->verifyClientIp())
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }
        catch (ConfigException &ex) {
            _logger.error() << ex.what() << std::endl;
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    }

    if (_enableFirewall)
    {
        std::string clientIp(getEnv("ifconfig_pool_remote_ip", envp));
        if (!session->updateEverybodyRules() || !session->setFirewallRules(clientIp))
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::clientDisconnect(
    const char *argv[],
    const char *envp[],
    ClientSession* session
) noexcept
{
    if (_enableFirewall)
    {
        if (session->removeFirewalRules())
            return OPENVPN_PLUGIN_FUNC_SUCCESS;
        else
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

void ArachnePlugin::removeAllRichRules()
{
    if (_enableFirewall) {
        _logger.note() << "Removing all rich rules" << std::flush;
        auto connection = sdbus::createSystemBusConnection();
        FirewallD1_Zone firewallZone(connection);
        for (auto r : firewallZone.getRichRules(_firewallZoneName))
        {
            _logger.note() << "Removing rich rule " << r << std::flush;
            firewallZone.removeRichRule(_firewallZoneName, r);
        }
    }
}

void ArachnePlugin::getLocalIpAddresses()
{
    struct ifaddrs* ptr_ifaddrs = nullptr;
    auto result = getifaddrs(&ptr_ifaddrs);
    if (result != 0) {
        std::stringstream msg;
        msg << "Cannot get host's IP addresses: " << strerror(errno) << std::flush;
        throw PluginException(msg.str());
    }

    _logger.note() << "Getting local IP addresses" << std::flush;
    for(
        struct ifaddrs* ptr_entry = ptr_ifaddrs;
        ptr_entry != nullptr;
        ptr_entry = ptr_entry->ifa_next
    ) {
        if (ptr_entry->ifa_addr == nullptr) {
            continue;
        }
        sa_family_t address_family = ptr_entry->ifa_addr->sa_family;

        if( address_family == AF_INET ) {
            if( ptr_entry->ifa_addr != nullptr ){
                char buffer[INET_ADDRSTRLEN] = {0, };
                inet_ntop(
                    address_family,
                    &((struct sockaddr_in*)(ptr_entry->ifa_addr))->sin_addr,
                    buffer,
                    INET_ADDRSTRLEN
                );
                _myIps.insert(std::string(buffer));
            }
        }
    }
    freeifaddrs(ptr_ifaddrs);
    _logger.note()
        << "Local IP addresses: "
        << std::accumulate(
                std::begin(_myIps),
                std::end(_myIps),
                std::string{},
                [](const std::string& a, const std::string &b ) {
                    return a.empty() ? b : a + ", " + b;
                }
            )
        << std::flush;
}
