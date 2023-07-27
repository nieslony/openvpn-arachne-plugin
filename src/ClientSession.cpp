#include "ClientSession.h"
#include "Http.h"
#include "FirewallD1.h"
#include "ArachnePlugin.h"

#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <sstream>
#include <set>

ClientSession::ClientSession(ArachnePlugin &plugin, plugin_vlog_t logFunc, int sessionId)
    : _plugin(plugin), _logger(logFunc, sessionId), _sessionId(sessionId)
{
    _logger.note() << "Creating Session " << _sessionId << std::flush;
}

ClientSession::~ClientSession()
{
    _logger.note() << "Cleanup session" << std::flush;
}

bool ClientSession::authUser(const Url &url, const std::string &username, const std::string &password)
{
    _logger.note() << "Authenticating user " << username << std::flush;

    http::Request request(http::GET, url);
    request.basicAuth(username, password);
    http::Response response;
    http::Http httpClient;
    _logger.note() << "Connecting to " << url.str() << std::flush;
    try {
        httpClient.doHttp(request, response);
    }
    catch (http::HttpException &ex)
    {
        _logger.error() << ex.what() << std::endl;
        return false;
    }
    _logger.note() << "Got " << response.status() << "(" << response.status_str() << ")" << std::flush;
    if (response.status() == 200) {
        _logger.note() << "Authenticating successfull" << std::flush;
        _username = username;
        _password = password;
        return true;
    }
    else {
        _logger.note() << "Authenticating failed" << std::flush;
        return false;
    }
}

bool ClientSession::setFirewallRules(const std::string &clientIp)
{
    return true;
    _logger.note() << "Setting firewall rules for user " << _username
        << ", connected from " << clientIp
        << std::flush;
    http::Request request(http::GET, _plugin.getFirewallUrlUser());
    request.basicAuth(_username, _password);
    http::Response response;
    http::Http httpClient;
    std::stringstream body;

    _logger.note() << "Connecting to " << _plugin.getFirewallUrlUser().str() << std::flush;
    httpClient.doHttp(request, response, &body);

    if (response.status() != 200) {
        _logger.error() << "Failed downloading firewall rules: " << body.str() << std::flush;
        return false;
    }

    boost::property_tree::ptree json;
    try {
        boost::property_tree::read_json(body, json);
    }
    catch (const std::exception &ex) {
        _logger.error() << "Cannot parse json. " << ex.what() << std::endl;
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    auto connection = sdbus::createSystemBusConnection();
    FirewallD1_Zone zone(connection);

    _logger.note() << "Parsing " << body.str() << std::endl;
    BOOST_FOREACH(boost::property_tree::ptree::value_type &v, json)
    {
        std::string rule = createRichRule(v, clientIp);
        _logger.note() << "Adding rich rule: "<< rule << std::flush;
        zone.addRichRule(_plugin.getFirewallZone(), rule, FirewallD1::DEFAULT_TIMEOUT);
        _richRules.push_back(rule);
    }

    return true;
}

bool ClientSession::removeFirewalRules()
{
    _logger.note() << "Removing " << _username << "'s rich rules" << std::flush;
    auto connection = sdbus::createSystemBusConnection();
    FirewallD1_Zone zone(connection);

    for (auto r : _richRules)
    {
        _logger.note() << "Removing " << _username << "'s rich rule " << r << std::flush;
        zone.removeRichRule(_plugin.getFirewallZone(), r);
    }

    return true;
}

bool ClientSession::updateEverybodyRules()
{
    _logger.note() << "Updating everybody rules" << std::flush;
    Url url(_plugin.getFirewallUrlEverybody());
    _logger.note() << "Getting rules from " << url.str() << std::flush;
    http::Request request(http::GET, url);
    request.basicAuth(_username, _password);
    http::Response response;
    http::Http httpClient;
    std::stringstream body;
    httpClient.doHttp(request, response, &body);

    boost::property_tree::ptree json;
    try {
        boost::property_tree::read_json(body, json);
    }
    catch (const std::exception &ex) {
        _logger.error() << "Cannot parse json. " << ex.what() << std::endl;
        return false;
    }

    _logger.note() << "Parsing " << body.str() << std::endl;
    std::set<std::string> newRules;
    auto connection = sdbus::createSystemBusConnection();
    FirewallD1_Policy policy(connection);
    std::string icmpRules;
    std::set<std::string> destIps;
    try {
        icmpRules = json.get<std::string>("icmpRules");
        _logger.note() << "ICMP rules: " << icmpRules << std::flush;

        BOOST_FOREACH(boost::property_tree::ptree::value_type &v, json.get_child("richRules"))
        {
            std::string rule = createRichRule(v);
            newRules.insert(rule);
            destIps.insert(v.second.get<std::string>("destinationAddress"));
        }
    }
    catch (boost::property_tree::ptree_bad_path &ex) {
        _logger.error() << "Invalid firewall rules: " << ex.what() << std::flush;
        return false;
    }

    if (icmpRules == "ALLOW_ALL") {
        newRules.insert("rule icmp-type name=\"echo-reply\" accept");
        newRules.insert("rule icmp-type name=\"echo-request\" accept");
    }
    else if (icmpRules == "DENY") {
    }
    else if (icmpRules == "ALLOW_ALL_GRANTED") {
        for (auto ip : destIps) {
            for (std::string type : { "echo-reply", "echo-request" }) {
                std::stringstream rule;
                rule
                    << "rule"
                    << " family=\"ipv4\""
                    << " destination address=\"" << ip << "\""
                    << " icmp-type name=\"" << type << "\""
                    << " accept";
                newRules.insert(rule.str());
            }
        }
    } else {
        _logger.error() << "Invalid value of icmpRules: " << icmpRules << std::flush;
        return false;
    }


    try {
        _logger.note() << "Getting current rich rules" << std::flush;
        std::map<std::string, sdbus::Variant> policySettings;
        policySettings = policy.getPolicySettings("arachne-incoming");
        std::vector<std::string> currentRules;
        if (policySettings.find(std::string("rich_rules")) != policySettings.end())
            currentRules = policySettings.at(std::string("rich_rules"));
        std::set<std::string> updRules(currentRules.begin(), currentRules.end());
        updRules.insert(newRules.begin(), newRules.end());
        for (const std::string &rule : updRules) {
            if (rule.find("destination address") == std::string::npos
                &&
                newRules.find(rule) == newRules.end()
            ) {
                _logger.note() << "Removing rich rule " << rule << std::flush;
                updRules.erase(rule);
            }
        }
        _logger.note() << "Everybody rich rules" << std::flush;
        for (auto r : updRules)
            _logger.note() << r << std::flush;
        std::vector<std::string> setRules(updRules.begin(), updRules.end());
        std::map<std::string, sdbus::Variant> settings;
        settings["rich_rules"] = setRules;
        policy.setPolicySettings("arachne-incoming", settings);
    }
    catch (const sdbus::Error &ex) {
        _logger.error() << "Cannot update rich rules: " << ex.what() << std::flush;
        return false;
    }

    _logger.note() << "Everybody rich rules updated" << std::flush;
    return true;
}

std::string ClientSession::createRichRule(
    boost::property_tree::ptree::value_type &node,
    const std::string &clientIp
)
{
    std::string destination = node.second.get<std::string>("destinationAddress");
    std::stringstream rule;

    rule << "rule family=\"ipv4\"";
    if (!clientIp.empty())
        rule << " source address=\"" << clientIp << "\"";
    rule << " destination address=\"" << destination << "\"";

    boost::optional<std::string> value;
    value = node.second.get_optional<std::string>("serviceName");
    if (value.has_value())
        rule << " service name=\"" << value.value() << "\"";

    value = node.second.get_optional<std::string>("port");
    if (value.has_value())
        rule << " port " << value.value();

    rule << " accept";

    return rule.str();
}
