#include "ArachnePlugin.h"
#include "ClientSession.h"
#include "Config.h"
#include "BreakDownRootDaemon.h"
#include "FirewallD1.h"

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <cerrno>
#include <cstring>
#include <csignal>
#include <fstream>
#include <openvpn-plugin.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Types.h>
#include <sstream>
#include <tuple>
#include <numeric>

#include <sys/wait.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <pwd.h>

const std::string ArachnePlugin::FN_IP_FORWARD = "/proc/sys/net/ipv4/ip_forward";

ArachnePlugin::ArachnePlugin(const openvpn_plugin_args_open_in *in_args) :
    _logger(in_args->callbacks->plugin_vlog),
    _breakDownRootDaemon(in_args->callbacks->plugin_vlog, *this),
    _lastSession(0)
{
    _logger.note()
        << "Initializing as user " << getpwuid(getuid())->pw_name
        << ", effective " << getpwuid(geteuid())->pw_name
        << "..." << std::flush;
    _logFunc = in_args->callbacks->plugin_vlog;

    parseConfigFile(in_args);
    startBackgroundProcess();
}

void ArachnePlugin::parseConfigFile(const openvpn_plugin_args_open_in *in_args)
{
    const char* configFile = in_args->argv[1];
    if (configFile == NULL)
        throw PluginException("Please specify configuration file");
    _logger.note() << "Reading configuration from " << configFile << std::flush;

    readConfigFile(configFile);
    _loginUrl = _config.get("url-login", "");
    _authUrl = _config.get("url-auth", "");
    _enableRouting = _config.get("enable-routing");
    _enableFirewall = _config.getBool("enable-firewall", false);
    if (_enableFirewall) {
        _firewallZoneName = _config.get("firewall-zone");
        _firewallRulesPath = _config.get("firewall-rules");
        _firewallUrlUser = _config.get("url-firewall-user", "");

        _incomingPolicyName = _firewallZoneName + "-in";
        _outgoingPolicyName = _firewallZoneName + "-out";
        _toHostPolicyName = _firewallZoneName + "-to";
        _fromHostPolicyName = _firewallZoneName + "-from";
    }
    _clientConfig = _config.get("client-config", "");
}

void ArachnePlugin::startBackgroundProcess()
{
    _breakDownRootDaemon.enterCommandLoop();
}

ArachnePlugin::~ArachnePlugin()
{
    _logger.note() << "Terminating background process" << std::flush;
    try {
        execCommand(NULL, BreakDownRootCommand::EXIT);
    }
    catch (std::exception &ex) {
        _logger.warning() << "Error sending EXIT command: " << ex.what() << std::flush;
    }
    waitpid(_backgroundPid, NULL, 0);
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

void ArachnePlugin::userAuthPassword(const char *envp[], ClientSession* session)
{
    const std::string username(getEnv("username", envp));
    const std::string password(getEnv("password", envp));

    session->loginUser(_loginUrl, username, password);
    session->authUser(_authUrl);
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
    ifs.open(FN_IP_FORWARD);
    if (!ifs.is_open()) {
        throw std::runtime_error("Error opening " + FN_IP_FORWARD);
    }
    ifs >> s;
    ifs.close();
    _logger.note() << "Got routíng status: \"" << s << "\"" << std::flush;
    return s;
}

void ArachnePlugin::setRouting(ClientSession *session)
{
    if (_enableRouting == "RESTORE_ON_EXIT") {
        _savedIpForward = getRoutingStatus();
        if (_savedIpForward == "0") {
            session->logger().note() << "Enabling IP forwarding" << std::flush;
            execCommand(session, BreakDownRootCommand::SET_ROUTING_STATUS, "1");
            //setRoutingStatus("1");
        } else {
            session->logger().note() << "IP forwarding already enabled" << std::flush;
        }
    } else if (_enableRouting == "ENABLE") {
        session->logger().note() << "Enabling IP forwarding" << std::flush;
        execCommand(session, BreakDownRootCommand::SET_ROUTING_STATUS, "1");
        //setRoutingStatus("1");
    } else if (_enableRouting == "OFF") {
        session->logger().note() << "Don't enable IP forwarding" << std::flush;
    } else {
        throw PluginException("Invalid value of enable-routing: " + _enableRouting);
    }
}

void ArachnePlugin::restoreRouting(ClientSession *session)
{
    if (_savedIpForward != "1" && _savedIpForward != "") {
        session->logger().note()
            << "Restoring IP forwading to " << _savedIpForward
            << std::flush;
        execCommand(session, BreakDownRootCommand::SET_ROUTING_STATUS, _savedIpForward);
        //setRoutingStatus(_savedIpForward);
    } else {
        session->logger().note() << "Leaving routing untouched" << std::flush;
    }
}

void ArachnePlugin::createFirewallZone(ClientSession *session)
{
    session->logger().note() << "Preparing firewall zone " <<_firewallZoneName << std::flush;
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
            session->logger().note()
                << "  Firewall Zone '" << _firewallZoneName << "' already exists"
                << std::flush;
        }
        else {
            session->logger().note()
                << "Creating firewall zone '" << _firewallZoneName << "'"
                << std::flush;
            std::map<std::string, sdbus::Variant> settings;
            settings["target"] = sdbus::Variant("DROP");
            settings["interfaces"] = sdbus::Variant(std::vector<std::string> { _interface });
            firewallConfig.addZone2(_firewallZoneName, settings);
        }

        std::vector<std::string> currentPolicies = firewallConfig.getPolicyNames();
        std::map<std::string, std::vector<std::string>> policies;
        policies[_incomingPolicyName] = { _firewallZoneName, "ANY" };
        policies[_outgoingPolicyName] = { "ANY", _firewallZoneName };
        policies[_toHostPolicyName] = { _firewallZoneName, "HOST" };
        policies[_fromHostPolicyName] = { "HOST", _firewallZoneName };
        for (const auto&[pname, pzones] : policies) {
            if (std::any_of(
                currentPolicies.begin(), currentPolicies.end(),
                [pname](std::string s){ return s == pname; }
            )
            ) {
                session->logger().note()
                    << "  Firewall Policy '" << pname << "' already exists"
                    << std::flush;
            }
            else {
                session->logger().note()
                    << "  Creating firewall policy '" << pname << "'"
                    << std::flush;
                std::map<std::string, sdbus::Variant> settings;
                settings["ingress_zones"] = sdbus::Variant(
                    std::vector<std::string> ({ policies[pname].at(0) })
                );
                settings["egress_zones"] = sdbus::Variant(
                    std::vector<std::string> ({ policies[pname].at(1) })
                );
                settings["target"] = sdbus::Variant("CONTINUE");
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
}

void ArachnePlugin::pluginUp(const char *argv[], const char *envp[], ClientSession*session)
{
    dumpEnv(_logger.debug(), envp) << std::flush;
    _interface = getEnv("dev", envp);
    session->logger().note() << "Bringing plugin up..." << std::flush;

    getLocalIpAddresses(session);

    setRouting(session);

    if (_enableFirewall) {
        createFirewallZone(session);
        execCommand(session, BreakDownRootCommand::CLEANUP_POLICIES);

        std::ifstream ifs(_firewallRulesPath);
        std::stringstream firewallRules;
        firewallRules << ifs.rdbuf();
        execCommand(session, BreakDownRootCommand::UPDATE_FIREWALL_RULES, firewallRules.str());

        //loadFirewallRules(session);
        execCommand(session, BreakDownRootCommand::APPLY_PERMANENT_RULES_TO_RUNTIME);
    }
    else
        session->logger().note() << "Firewall is disabled" << std::flush;

    session->logger().note() << "Plugin is up." << '\0' << std::flush;
}

void ArachnePlugin::pluginDown(const char *argv[], const char *envp[], ClientSession* session)
{
    session->logger() << "Bringing plugin down..." << std::flush;
    execCommand(session, BreakDownRootCommand::CLEANUP_POLICIES);
    execCommand(session, BreakDownRootCommand::APPLY_PERMANENT_RULES_TO_RUNTIME);
    restoreRouting(session);
    session->logger() << "Plugin is down" << std::flush;
}

void ArachnePlugin::clientConnect(
    const char *argv[],
    const char *envp[],
    ClientSession*session
)
{
    dumpEnv(session->logger().debug(), envp) << std::flush;
    session->commonName(getEnv("common_name", envp));
    session->remoteIp(getEnv("untrusted_ip", envp));
    session->vpnIp(getEnv("ifconfig_pool_remote_ip", envp));
    session->logger().note() << "New client session:"
        << std::endl << "  common name: " << session->commonName()
        << std::endl << "  remote IP: " << session->remoteIp()
        << std::endl << "  VPN IP: " << session->vpnIp()
        << std::flush;

    if (!_clientConfig.empty()) {
        session->readConfigFile(_clientConfig);
        session->verifyClientIp();
        session->addRoutesToRemoteNetworks();
    }

    if (_enableFirewall) {
        session->addVpnIpToIpSets();
    }
}

void ArachnePlugin::clientDisconnect(
    const char *argv[],
    const char *envp[],
    ClientSession* session
)
{
    session->logger().note() << "Client " << session->commonName()
        << " from " << session->remoteIp()
        << " disconnected" << std::flush;
    if (_enableFirewall)
        session->removeVpnIpFromIpSets();
    session->removeRoutesToRemoteNetworks();
}

void ArachnePlugin::getLocalIpAddresses(ClientSession*session)
{
    struct ifaddrs* ptr_ifaddrs = nullptr;
    auto result = getifaddrs(&ptr_ifaddrs);
    if (result != 0) {
        std::stringstream msg;
        msg << "Cannot get host's IP addresses: " << strerror(errno) << std::flush;
        throw PluginException(msg.str());
    }

    session->logger().debug() << "Getting local IP addresses" << std::flush;
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
                std::string ip(buffer);
                if (!ip.starts_with("127."))
                    _myIps.insert(std::string(buffer));
            }
        }
    }
    freeifaddrs(ptr_ifaddrs);
    session->logger().debug()
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

std::string ArachnePlugin::ipSetNameSrc(long id) const
{
    std::stringstream name;
    name <<_firewallZoneName << "-" << id << "-src";
    return name.str();
}

std::string ArachnePlugin::ipSetNameDst(long id) const
{
    std::stringstream name;
    name <<_firewallZoneName << "-" << id << "-dst";
    return name.str();
}

void ArachnePlugin::execCommand(ClientSession* session, BreakDownRootCommand command, const std::string &param)
{
    _breakDownRootDaemon.execCommand(
        session != NULL ? session->logger() : _logger,
        command, param
    );
}
