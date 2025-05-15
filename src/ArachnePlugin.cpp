#include "ArachnePlugin.h"
#include "ClientSession.h"
#include "Config.h"
#include "FirewallD1.h"

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <cerrno>
#include <fstream>
#include <openvpn-plugin.h>
#include <sdbus-c++/IProxy.h>
#include <sdbus-c++/Types.h>
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
    ifs.open(FN_IP_FORWATD);
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
    ofs << forward << std::endl;
    ofs.close();
}

void ArachnePlugin::setRouting(ClientSession *session)
{
    if (_enableRouting == "RESTORE_ON_EXIT") {
        _savedIpForward = getRoutingStatus();
        if (_savedIpForward == "0") {
            session->logger().note() << "Enabling IP forwarding" << std::flush;
            setRoutingStatus("1");
        } else {
            session->logger().note() << "IP forwarding already enabled" << std::flush;
        }
    } else if (_enableRouting == "ENABLE") {
        session->logger().note() << "Enabling IP forwarding" << std::flush;
        setRoutingStatus("1");
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
        setRoutingStatus(_savedIpForward);
    } else {
        session->logger().note() << "Leaving routing untouched" << std::flush;
    }
}

void ArachnePlugin::createFirewallZone(ClientSession *session)
{
    if (_enableFirewall) {
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
                settings["target"] = "DROP";
                settings["interfaces"] = std::vector<std::string> { _interface };
                firewallConfig.addZone2(_firewallZoneName, settings);
            }

            std::vector<std::string> currentPolicies = firewallConfig.getPolicyNames();
            std::map<std::string, std::vector<std::string>> policies;
            policies[_incomingPolicyName] = { _firewallZoneName, "public" };
            policies[_outgoingPolicyName] = { "public", _firewallZoneName };
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

void ArachnePlugin::pluginUp(const char *argv[], const char *envp[], ClientSession*session)
{
    dumpEnv(_logger.debug(), envp) << std::flush;
    _interface = getEnv("dev", envp);
    session->logger().note() << "Bringing plugin up..." << std::flush;
    setRouting(session);

    createFirewallZone(session);
    cleanupPolicies(session);
    loadFirewallRules(session);
    applyPermentRulesToRuntime(session);

    getLocalIpAddresses(session);
    session->logger().note() << "Plugin is up." << std::flush;
}

void ArachnePlugin::pluginDown(const char *argv[], const char *envp[], ClientSession* session)
{
    session->logger() << "Bringing plugin down..." << std::flush;
    cleanupPolicies(session);
    applyPermentRulesToRuntime(session);
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

void ArachnePlugin::cleanupPolicies(ClientSession*session)
{
    if (_enableFirewall) {
        session->logger().note() << "Cleaning up firewall policies for zone '" <<_firewallZoneName << "'" << std::flush;
        auto connection = sdbus::createSystemBusConnection();
        FirewallD1 firewall(connection);
        FirewallD1_Config firewallConfig(connection);

        std::map<std::string, sdbus::Variant> settings;
        std::vector<std::string> noEntries;
        settings["rich_rules"] = noEntries;
        FirewallD1_Policy firewallPolicy(connection);
        firewallPolicy.setPolicySettings(incomingPolicyName(), settings);

        for (std::string policyName: firewallConfig.getPolicyNames()) {
            if (policyName.starts_with(_firewallZoneName)) {
                session->logger().note() << "  Removing all rich rules from policy '" << policyName << "'" << std::flush;
                std::vector<std::string> emptyList;
                std::map<std::string, sdbus::Variant> settings;
                settings["rich_rules"] = emptyList;

                auto policyPath = firewallConfig.getPolicyByName(policyName);
                auto policyProxy = sdbus::createProxy(std::move("org.fedoraproject.FirewallD1"), std::move(policyPath));
                policyProxy->callMethod("update")
                    .onInterface("org.fedoraproject.FirewallD1.config.policy")
                    .withArguments(settings);
            }
            else {
                session->logger().debug() << "  Ignoring policy '" << policyName << "'" << std::flush;
            }
        }

        auto ipSetNames = firewallConfig.getIPSetNames();
        session->logger().note() << "  Removing " << ipSetNames.size() << " IP sets" << std::flush;
        for (std::string ipSetName: ipSetNames) {
            if (ipSetName.starts_with(_firewallZoneName)) {
                session->logger().debug() << "  Removing IP set " << ipSetName << std::flush;
                auto ipSetPath = firewallConfig.getIPSetByName(ipSetName);
                auto ipSetProxy = sdbus::createProxy(std::move("org.fedoraproject.FirewallD1"), std::move(ipSetPath));
                ipSetProxy->callMethod("remove")
                    .onInterface("org.fedoraproject.FirewallD1.config.ipset");
            }
        }
    }
}

void ArachnePlugin::createRichRules(
    const boost::property_tree::ptree &ptree,
    const std::string icmpRules,
    std::vector<std::string> &richRules,
    std::map<std::string, std::vector<std::string>> &ipSets,
    ClientSession *session
)
{
    if (icmpRules == "ALLOW_ALL") {
        session->logger().debug() << "  Allow ping from everywhere to everywhere" << std::flush;
        richRules.push_back("rule family=\"ipv4\" icmp-type name=\"echo-request\" accept");
        richRules.push_back("rule family=\"ipv4\" icmp-type name=\"echo-reply\" accept");
    }

    for (auto &[_, value] : ptree) {
        int id = value.get<int>("id");

        auto srcList = value.get_child_optional("sources");
        std::vector<std::string> sources;
        if (srcList.has_value())
            for (auto &[_, src]: srcList.value())
                sources.push_back(src.get_value<std::string>());

        auto dstList = value.get_child_optional("destination");
        std::vector<std::string> destination;
        if (dstList.has_value())
            for (auto &[_, dst]: dstList.value())
                destination.push_back(dst.get_value<std::string>());

        std::string ipSetSrcName = ipSetNameSrc(id);
        std::string ipSetDstName = ipSetNameDst(id);

        if (icmpRules == "ALLOW_ALL_GRANTED") {
            session->logger().debug() << "  Allow ping to granted hosts" << std::flush;
            std::stringstream requestRule;
            requestRule << "rule family=\"ipv4\" ";

            std::stringstream responseRule;
            responseRule << "rule family=\"ipv4\" ";

            if (srcList.has_value()) {
                requestRule << "source ipset=\"" << ipSetSrcName << "\" ";
                responseRule << "source ipset=\"" << ipSetSrcName << "\" ";
                ipSets[ipSetSrcName] = sources;
            }
            if (dstList.has_value()) {
                requestRule << "destination ipset=\"" << ipSetDstName << "\" ";
                responseRule << "destination ipset=\"" << ipSetDstName << "\" ";
                ipSets[ipSetDstName] = destination;
            }

            requestRule << "icmp-type name=\"echo-request\" accept";
            responseRule << "icmp-type name=\"echo-reply\" accept";

            richRules.push_back(requestRule.str());
            richRules.push_back(responseRule.str());
        }

        auto srvList = value.get_child_optional("services");
        if (srvList.has_value()) {
            for (auto &[_, srv]: srvList.value()) {
                std::stringstream richrule;
                richrule << "rule family=\"ipv4\" ";
                if (srcList.has_value()) {
                    richrule << "source ipset=\"" << ipSetSrcName << "\" ";
                    ipSets[ipSetSrcName] = sources;
                }
                if (dstList.has_value()) {
                    richrule << "destination ipset=\"" <<ipSetDstName << "\" ";
                    ipSets[ipSetDstName] = destination;
                }
                richrule << "service name=\"" << srv.get_value<std::string>() << "\" ";
                richrule << "accept";
                richRules.push_back(richrule.str());
                session->logger().debug() << "  Add rich rule '" << richrule.str() << "'" << std::flush;
            }
        }
        auto prtList = value.get_child_optional("ports");
        if (prtList.has_value()) {
            for (auto &[_, prt]: prtList.value()) {
                std::vector<std::string> splitPort;
                boost::split(splitPort, prt.get_value<std::string>(), boost::is_any_of("/"));

                std::stringstream richrule;
                richrule << "rule family=\"ipv4\" ";
                if (srcList.has_value()) {
                    richrule << "source ipset=\"" << ipSetSrcName << "\" ";
                    ipSets[ipSetSrcName] = sources;
                }
                if (dstList.has_value()) {
                    richrule << "destination ipset=\"" <<ipSetDstName << "\" ";
                    ipSets[ipSetDstName] = destination;
                }
                richrule << "port "
                 << "port=\"" << splitPort[0] << "\" "
                 << "protocol=\"" <<splitPort[1] << "\" ";
                richrule << "accept";
                richRules.push_back(richrule.str());
                session->logger().debug() << "  Add rich rule '" << richrule.str() << "'" << std::flush;
            }
        }
    }
}

void ArachnePlugin::loadFirewallRules(ClientSession *session)
{
    session->logger().note() << "Loading firewall rules" << std::flush;
    unsigned noIncomingRules = 0;
    unsigned noOutgoingRules = 0;
    unsigned noIncomingRichRules = 0;
    unsigned noOutgoingRichRules = 0;
    try {
        std::ifstream ifs;
        ifs.open (_firewallRulesPath, std::ifstream::in);
        boost::property_tree::ptree pt;
        boost::property_tree::read_json(ifs, pt);
        ifs.close();

        std::vector<std::string> incomingRichRules;
        std::vector<std::string> outgoingRichRules;
        std::map<std::string, std::vector<std::string>> ipSets;
        auto incomingRules = pt.get_child("incoming");
        auto outgoingRules = pt.get_child("outgoing");
        auto icmpRules = pt.get<std::string>("icmp-rules");
        createRichRules(incomingRules, icmpRules, incomingRichRules, ipSets, session);
        createRichRules(outgoingRules, icmpRules, outgoingRichRules, ipSets, session);

        auto connection = sdbus::createSystemBusConnection();
        FirewallD1_Config firewallConfig(connection);

        for (auto &[name, entries]: ipSets) {
            sdbus::Struct<
                std::string, // version
                std::string, // name
                std::string, // description
                std::string, // type
                std::map<std::string, std::string>, // options
                std::vector<std::string> // entries
            > settings{ "1", name, "", "hash:ip", {}, entries};
            session->logger().debug() << "  Adding IPSet " << name << std::flush;
            firewallConfig.addIPSet(name, settings);
        }
        session->logger().note() << "  " << ipSets.size() << " IP sets added." << std::flush;

        auto outgoingPath = firewallConfig.getPolicyByName(_outgoingPolicyName);
        auto outgoingProxy = sdbus::createProxy(std::move("org.fedoraproject.FirewallD1"), std::move(outgoingPath));
        std::map<std::string, sdbus::Variant> outgoingSettings;
        outgoingSettings["rich_rules"] = outgoingRichRules;
        outgoingProxy->callMethod("update")
            .onInterface("org.fedoraproject.FirewallD1.config.policy")
        .   withArguments(outgoingSettings);

        auto incomingPath = firewallConfig.getPolicyByName(_incomingPolicyName);
        auto incomingProxy = sdbus::createProxy(std::move("org.fedoraproject.FirewallD1"), std::move(incomingPath));
        std::map<std::string, sdbus::Variant> incomingSettings;
        incomingSettings["rich_rules"] = incomingRichRules;
        incomingProxy->callMethod("update")
            .onInterface("org.fedoraproject.FirewallD1.config.policy")
            .withArguments(incomingSettings);

        session->logger().note()
            << "  "
            << incomingRules.size() << " incoming rules with " << incomingRichRules.size() << " resulting rich rules, "
            << outgoingRules.size() << " outgoung rules with " << outgoingRichRules.size() << " resulting rich rules "
            << "added."
            << std::flush;
    }
    catch (std::exception &ex) {
        std::stringstream str;
        str << "Error reading " << _firewallRulesPath << ": " << ex.what();
        throw PluginException(str.str());
    }
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
                _myIps.insert(std::string(buffer));
            }
        }
    }
    freeifaddrs(ptr_ifaddrs);
    session->logger().note()
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

void ArachnePlugin::applyPermentRulesToRuntime(ClientSession *session)
{
    session->logger().note() << "Reloading permanent firewall settings" << std::flush;
    auto connection = sdbus::createSystemBusConnection();
    FirewallD1 firewall(connection);
    firewall.reload();
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
