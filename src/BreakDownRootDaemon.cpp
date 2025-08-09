#include "BreakDownRootDaemon.h"
#include "ArachnePlugin.h"
#include "ClientSession.h"

#include <boost/json.hpp>
#include <boost/algorithm/string.hpp>

#include <cstdint>
#include <ostream>
#include <fstream>
#include <tuple>
#include <cstdio>
#include <cstdlib>

const char BreakDownRootDaemon::DELIM = '\x09';

#ifdef HAVE_LEGACY_BOOST
#define CASE_STR(v) case v: return # v ;

const char* enum_to_string(BreakDownRootCommand cmd, const char* defValue)
{
    switch (cmd) {
        using enum BreakDownRootCommand;
            CASE_STR(PING)
            CASE_STR(CLEANUP_POLICIES)
            CASE_STR(APPLY_PERMANENT_RULES_TO_RUNTIME)
            CASE_STR(SET_ROUTING_STATUS)
            CASE_STR(UPDATE_FIREWALL_RULES)
            CASE_STR(FORCE_IPSET_CLEANUP)
            CASE_STR(ADD_VPN_TO_IP_SETS)
            CASE_STR(REMOVE_VPN_FROM_IP_SETS)
            CASE_STR(EXIT)
        default:
            return defValue;
    }
}

const char* enum_to_string(BreakDownRootAnswer ans, const char* defValue)
{
    switch (ans) {
        using enum BreakDownRootAnswer;
            CASE_STR(SUCCESS)
            CASE_STR(DEBUG)
            CASE_STR(NOTE)
            CASE_STR(WARNING)
            CASE_STR(ERROR)
            CASE_STR(EXCEPTION)
        default: return defValue;
    }
}
#else
#include <boost/describe/enum_to_string.hpp>

using boost::describe::enum_to_string;
#endif

BreakDownRootDaemon::BreakDownRootDaemon(plugin_vlog_t logFunc, const ArachnePlugin &plugin) :
    _plugin(plugin),
    _logger(logFunc, "BreakDownRootCommands")
{}

void BreakDownRootDaemon::commandLoop(int fdRead, int fdWrite)
{
    _logger.note() << "Starting event loop as user " << getpid() << std::flush;

    _reader.open(
        boost::iostreams::file_descriptor_source(fdRead, boost::iostreams::never_close_handle)
    );
    _writer.open(
        boost::iostreams::file_descriptor_sink(fdWrite, boost::iostreams::never_close_handle)
    );

    while (_reader) {
        uint8_t command;
        std::string param;

        _reader >> command;
        std::getline(_reader, param, DELIM);

        BreakDownRootCommand cmd = static_cast<BreakDownRootCommand>(command);
        _logger.debug() << "Got command: " << enum_to_string(cmd, "") << "(" << param << ")" << std::flush;
        try {
            switch (cmd) {
                using enum BreakDownRootCommand;
                case PING:
                    sendAnswer(BreakDownRootAnswer::DEBUG, "Pong: " + param);
                    break;
                case CLEANUP_POLICIES:
                    cleanupPolicies();
                    break;
                case APPLY_PERMANENT_RULES_TO_RUNTIME:
                    applyPermentRulesToRuntime();
                    break;
                case SET_ROUTING_STATUS:
                    setRoutingStatus(param);
                    break;
                case UPDATE_FIREWALL_RULES:
                    updateFirewallRules(param);
                    break;
                case FORCE_IPSET_CLEANUP:
                    forceIpSetCleanup(param);
                    break;
                case ADD_VPN_TO_IP_SETS:
                    addVpnIpToIpSets(param);
                    break;
                case REMOVE_VPN_FROM_IP_SETS:
                    removeVpnIpFromIpSets(param);
                    break;
                case EXIT:
                    _logger.note() << "Exiting event loop" << std::flush;
                    exit(EXIT_SUCCESS);
                    break;
                default:
                    _logger.warning() << "Invalid command: " << command << std::flush;
                    sendAnswer(BreakDownRootAnswer::WARNING, "Invalid command");
            }
            sendAnswer(BreakDownRootAnswer::SUCCESS);
        }
        catch (PluginException &ex) {
            _logger.warning() << "Caught exception: " << ex.what() << std::flush;
            sendAnswer(BreakDownRootAnswer::EXCEPTION, ex.what());
        }
    }
    _logger.warning() << "Event loop unexped left" << std::flush;
}

void BreakDownRootDaemon::execCommand(std::ostream &commandStream, std::istream &replyStream,
                                      ArachneLogger &logger,
                                      BreakDownRootCommand command, const std::string &param)
{
    logger.debug() << "Sending " << enum_to_string(command, "") << std::flush;
    commandStream << static_cast<uint8_t>(command)
        << param << DELIM
        << std::flush;
    while (true) {
        uint8_t reply;
        std::string replyStr;

        replyStream >> reply;
        BreakDownRootAnswer answer = static_cast<BreakDownRootAnswer>(reply);
        logger.debug() << "Got reply (" << enum_to_string(answer, "") << "): ";
        switch (answer) {
            using enum BreakDownRootAnswer;
            case SUCCESS:
                logger.debug() << "Success" << std::flush;
                return;
            case DEBUG:
                std::getline(replyStream, replyStr, DELIM);
                logger.debug() << replyStr << std::flush;
                break;
            case NOTE:
                std::getline(replyStream, replyStr, DELIM);
                logger.note() << replyStr << std::flush;
                break;
            case WARNING:
                std::getline(replyStream, replyStr, DELIM);
                logger.warning() << replyStr << std::flush;
                break;
            case ERROR:
                std::getline(replyStream, replyStr, DELIM);
                logger.error() << replyStr << std::flush;
                break;
            case EXCEPTION:
                std::getline(replyStream, replyStr, DELIM);
                throw PluginException(replyStr);
            default:
                throw PluginException("Invalid command");
        }
    }
    throw PluginException("Command stream died");
}

void BreakDownRootDaemon::sendAnswer(BreakDownRootAnswer answer)
{
    _writer
        << static_cast<uint8_t>(answer)
        << std::flush;
}
void BreakDownRootDaemon::sendAnswer(BreakDownRootAnswer answer, const std::string &msg)
{
    _writer
        << static_cast<uint8_t>(answer)
        << msg << DELIM
        << std::flush;
}

std::ostream &BreakDownRootDaemon::answer(BreakDownRootAnswer answer)
{
    _writer
        << static_cast<uint8_t>(answer);

    return _writer;
}

void BreakDownRootDaemon::cleanupPolicies()
{
    if (_plugin.enableFirewall()) {
        answer(BreakDownRootAnswer::NOTE) << "Cleaning up firewall policies for zone '" << _plugin.firewallZoneName() << "'" << flushAnswer;
        auto connection = sdbus::createSystemBusConnection();
        FirewallD1 firewall(connection);
        FirewallD1_Config firewallConfig(connection);

        std::map<std::string, sdbus::Variant> settings;
        std::vector<std::string> noEntries;
        settings["rich_rules"] = sdbus::Variant(noEntries);
        FirewallD1_Policy firewallPolicy(connection);
        firewallPolicy.setPolicySettings(_plugin.incomingPolicyName(), settings);

        for (std::string policyName: firewallConfig.getPolicyNames()) {
            if (policyName.starts_with(_plugin.firewallZoneName())) {
                answer(BreakDownRootAnswer::NOTE)
                    << "  Removing all rich rules from policy '" << policyName << "'"
                    << flushAnswer;
                std::vector<std::string> emptyList;
                std::map<std::string, sdbus::Variant> settings;
                settings["rich_rules"] = sdbus::Variant(emptyList);

                auto policyPath = firewallConfig.getPolicyByName(policyName);
                FirewallD1_Config_Policy firewalldConfigPolicy(connection, policyPath);
                firewalldConfigPolicy.update(settings);
            }
            else {
                answer(BreakDownRootAnswer::DEBUG) << "  Ignoring policy '" << policyName << "'" << flushAnswer;
            }
        }

        auto ipSetNames = firewallConfig.getIPSetNames();
        answer(BreakDownRootAnswer::NOTE) << "  Removing " << ipSetNames.size() << " IP sets" << flushAnswer;
        for (std::string ipSetName: ipSetNames) {
            if (ipSetName.starts_with(_plugin.firewallZoneName())) {
                answer(BreakDownRootAnswer::DEBUG) << "  Removing IP set " << ipSetName << flushAnswer;
                auto ipSetPath = firewallConfig.getIPSetByName(ipSetName);
                FirewallD1_Config_IpSet firewalldConfigIpSet(connection, ipSetPath);
                firewalldConfigIpSet.remove();
            }
        }
    }
}

void BreakDownRootDaemon::applyPermentRulesToRuntime()
{
    answer(BreakDownRootAnswer::NOTE) << "Reloading permanent firewall settings" << flushAnswer;
    auto connection = sdbus::createSystemBusConnection();
    FirewallD1 firewall(connection);
    firewall.reload();
}

void BreakDownRootDaemon::setRoutingStatus(const std::string &forward)
{
    std::ofstream ofs;
    ofs.open(ArachnePlugin::FN_IP_FORWARD);
    if (!ofs.is_open()) {
        throw std::runtime_error("Cannot open " + ArachnePlugin::FN_IP_FORWARD + " for reading");
    }
    ofs << forward << std::endl;
    ofs.close();
}

void BreakDownRootDaemon::updateFirewallRules(const std::string &rules)
{
    auto json = boost::json::parse(rules);

    std::vector<std::string> incomingRichRules;
    std::vector<std::string> outgoingRichRules;
    std::vector<std::string> toHostRichRules;
    std::vector<std::string> fromHostRichRules;
    std::map<std::string, std::vector<std::string>> ipSets;
    auto incomingRules = json.at("incoming");
    auto outgoingRules = json.at("outgoing");
    auto icmpRules = json.at("icmp-rules").as_string().c_str();

    createRichRules(incomingRules, icmpRules, incomingRichRules, toHostRichRules, ipSets);
    createRichRules(outgoingRules, icmpRules, outgoingRichRules, fromHostRichRules, ipSets);

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
        answer(BreakDownRootAnswer::DEBUG) << "  Adding IPSet " << name << flushAnswer;
        firewallConfig.addIPSet(name, settings);
    }
    answer(BreakDownRootAnswer::NOTE) << "  " << ipSets.size() << " IP sets added." << flushAnswer;

    std::list<std::tuple<const std::string&, std::vector<std::string>& > > t {
        { _plugin.incomingPolicyName(), incomingRichRules },
        { _plugin.outgongPolicyName(), outgoingRichRules },
        { _plugin.toHostPolicyName(), toHostRichRules },
        { _plugin.fromHostPolicyName(), fromHostRichRules }
    };
    for (auto &[name, rules]: t) {
        auto objPath = firewallConfig.getPolicyByName(name);
        std::map<std::string, sdbus::Variant> settings;
        settings["rich_rules"] = sdbus::Variant(rules);

        auto configPolicy = FirewallD1_Config_Policy(connection, objPath);
        configPolicy.update(settings);
    }

    _logger.debug()
        << "Added incoming rules: " << incomingRules
        << std::flush;
    answer(BreakDownRootAnswer::NOTE)
        << "  "
        << incomingRules.as_array().size() << " incoming rules: "
        << incomingRichRules.size() << " incoming rich rules, "
        << toHostRichRules.size() << " rich rules to localhost"
        << " added"
        << flushAnswer;
    _logger.debug()
        << "Added outgoing rules: " << outgoingRules
        << std::flush;
    answer(BreakDownRootAnswer::NOTE)
        << "  "
        << outgoingRules.as_array().size() << " outgoing rules: "
        << outgoingRichRules.size() << " outgoing rich rules, "
        << fromHostRichRules.size() << " rich rules from localhost"
        << " added"
        << flushAnswer;
}

void BreakDownRootDaemon::createRichRules(
    const boost::json::value &json,
    const std::string icmpRules,
    std::vector<std::string> &richRules,
    std::vector<std::string> &localRichRules,
    std::map<std::string, std::vector<std::string>> &ipSets
)
{
    if (icmpRules == "ALLOW_ALL") {
        answer(BreakDownRootAnswer::DEBUG) << "  Allow ping from everywhere to everywhere" << flushAnswer;
        richRules.push_back("rule family=\"ipv4\" icmp-type name=\"echo-request\" accept");
        richRules.push_back("rule family=\"ipv4\" icmp-type name=\"echo-reply\" accept");

        localRichRules.push_back("rule family=\"ipv4\" icmp-type name=\"echo-request\" accept");
        localRichRules.push_back("rule family=\"ipv4\" icmp-type name=\"echo-reply\" accept");
    }

    _logger.debug() << "Creating rich rules from " << json << std::flush;
    for (const boost::json::value &rule: json.as_array()) {
        _logger.debug() << "Processing " << rule << std::flush;
        int id = rule.at("id").as_int64();
        std::string ipSetSrcName = _plugin.ipSetNameSrc(id);
        std::string ipSetDstName = _plugin.ipSetNameDst(id);
        bool hasLocalSrc = false;
        bool hasLocalDst = false;

        auto *srcList = rule.as_object().if_contains("sources");
        std::vector<std::string> sources;
        if (srcList != NULL) {
            _logger.debug() << "Found sources: " << *srcList << std::flush;
            for (auto &src: srcList->as_array()) {
                std::string ip(src.as_string().c_str());
                if (_plugin.myIps().contains(ip))
                    hasLocalSrc = true;
                else
                    sources.push_back(ip);
            }
            ipSets[ipSetSrcName] = sources;
        }


        auto *dstList = rule.as_object().if_contains("destination");
        std::vector<std::string> destination;
        if (dstList != NULL) {
            _logger.debug() << "Found destination: " << *dstList << std::flush;
            for (auto &dst: dstList->as_array()) {
                std::string ip(dst.as_string().c_str());
                if (_plugin.myIps().contains(ip))
                    hasLocalDst = true;
                else
                    destination.push_back(ip);
            }
            ipSets[ipSetDstName] = destination;
        }

        std::vector<std::string> whats;
        if (icmpRules == "ALLOW_ALL_GRANTED") {
            whats.push_back("icmp-type name=\"echo-request\"");
            whats.push_back("icmp-type name=\"echo-reply\"");
        }

        auto srvList = rule.as_object().if_contains("services");
        if (srvList != NULL) {
            _logger.debug() << "Found services: " << *srvList << std::flush;
            for (auto &srv: srvList->as_array()) {
                boost::json::string s = srv.as_string();

                whats.push_back("service name=\"" + std::string(srv.as_string().c_str()) + "\" ");
            }
        }

        auto prtList = rule.as_object().if_contains("ports");
        if (prtList != NULL) {
            _logger.debug() << "Found ports: " << *prtList << std::flush;
            for (auto &prt: prtList->as_array()) {
                std::vector<std::string> splitPort;
                boost::split(splitPort, prt.as_string().c_str(), boost::is_any_of("/"));
                whats.push_back("port port=\"" + splitPort[0] + "\" protocol=\"" + splitPort[1] + "\" ");
            }
        }

        for (auto &what: whats) {
            std::stringstream richRule;
            richRule << "rule family=\"ipv4\" ";
            if (srcList != NULL)
                richRule << "source ipset=\"" << ipSetSrcName << "\" ";
            if (dstList != NULL)
                richRule << "destination ipset=\"" << ipSetDstName << "\" ";
            richRule << what << " accept";
            answer(BreakDownRootAnswer::DEBUG) << "  Created rich rule " << richRule.str() << flushAnswer;
            richRules.push_back(richRule.str());
        }

        if (hasLocalDst) {
            for (auto &what: whats) {
                std::stringstream richRule;
                richRule << "rule family=\"ipv4\" ";
                if (srcList != NULL)
                    richRule << "source ipset=\"" << ipSetSrcName << "\" ";
                richRule << what << " accept";
                answer(BreakDownRootAnswer::DEBUG) << "  Created rich rule (local dest) " << richRule.str() << flushAnswer;
                localRichRules.push_back(richRule.str());
            }
        }

        if (hasLocalSrc) {
            for (auto &what: whats) {
                std::stringstream richRule;
                richRule << "rule family=\"ipv4\" ";
                if (dstList != NULL)
                    richRule << "destination ipset=\"" << ipSetDstName << "\" ";
                richRule << what << " accept";
                answer(BreakDownRootAnswer::DEBUG) << "  Created rich rule (local src) " << richRule.str() << flushAnswer;
                localRichRules.push_back(richRule.str());
            }
        }
    }
    _logger.debug() << "Creating rich rules (done)" << json << std::flush;
}

void BreakDownRootDaemon::forceIpSetCleanup(const std::string &vpnIp_ipSetIds)
{
    auto param = boost::json::parse(vpnIp_ipSetIds);
    std::string vpnIp(param.at("clientIp").as_string().c_str());
    std::vector<long> incomingIds(boost::json::value_to<std::vector<long>>(param.at("incomingIds")));
    std::vector<long> outgoingIds(boost::json::value_to<std::vector<long>>(param.at("outgoingIds")));

    answer(BreakDownRootAnswer::NOTE)
        << "Something went wrong. Enforcing removal of IP " << vpnIp << " from IP sets."
        << flushAnswer;
    std::unique_ptr<sdbus::IConnection> connection;
    try {
        connection = sdbus::createSystemBusConnection();
    }
    catch (sdbus::Error &ex) {
        _logger.warning()
        << " Cannot get DBUS connection: " << ex.getMessage()
        << " No cleanup possible."
        << std::flush;
        return;
    }
    FirewallD1_IpSet firewallIpSet(connection);
    for (long id: incomingIds) {
        std::string ipSetName = _plugin.ipSetNameSrc(id);
        try {
            firewallIpSet.addEntry(ipSetName, vpnIp);
            answer(BreakDownRootAnswer::WARNING)
                << "  " << vpnIp << " removed from IP set " << ipSetName
                << flushAnswer;
        }
        catch (const sdbus::Error &ex) {
            answer(BreakDownRootAnswer::WARNING)
                << "  Cannot remove " << vpnIp << " from IP set " << ipSetName << ": "
                << ex.getMessage() << " (ignoring)"
                << flushAnswer;
        }
    }
    for (long id: outgoingIds) {
        try {
            firewallIpSet.addEntry(_plugin.ipSetNameDst(id), vpnIp);
        }
        catch (const sdbus::Error &ex) {
            answer(BreakDownRootAnswer::WARNING)
                << ex.getMessage() << " (ignoring)"
                << flushAnswer;
        }
    }
}

void BreakDownRootDaemon::addVpnIpToIpSets(const std::string &json)
{
    auto param = boost::json::parse(json);
    std::string vpnIp(param.at("clientIp").as_string().c_str());
    std::vector<long> incomingIds(boost::json::value_to<std::vector<long>>(param.at("incoming")));
    std::vector<long> outgoingIds(boost::json::value_to<std::vector<long>>(param.at("outgoing")));

    auto connection = sdbus::createSystemBusConnection();
    FirewallD1_IpSet firewallIpSet(connection);
    for (long id: incomingIds) {
        firewallIpSet.addEntry(_plugin.ipSetNameSrc(id), vpnIp);
    }
    for (long id: outgoingIds) {
        firewallIpSet.addEntry(_plugin.ipSetNameDst(id), vpnIp);
    }
}

void BreakDownRootDaemon::removeVpnIpFromIpSets(const std::string &json)
{
    auto param = boost::json::parse(json);
    std::string vpnIp(param.at("clientIp").as_string().c_str());
    std::vector<long> incomingIds(boost::json::value_to<std::vector<long>>(param.at("incomingIds")));
    std::vector<long> outgoingIds(boost::json::value_to<std::vector<long>>(param.at("outgoingIds")));

    auto connection = sdbus::createSystemBusConnection();
    FirewallD1_IpSet firewallIpSet(connection);
    for (long id: incomingIds) {
        firewallIpSet.removeEntry(_plugin.ipSetNameSrc(id), vpnIp);
    }
    for (long id: outgoingIds) {
        firewallIpSet.removeEntry(_plugin.ipSetNameDst(id), vpnIp);
    }
}
