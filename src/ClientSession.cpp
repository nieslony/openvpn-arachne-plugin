#include "ClientSession.h"
#include "Http.h"
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
    _logger.note() << "Updating " << _username << "'s firewall rules" << std::flush;
    boost::property_tree::ptree json;
    if (!readJson(_plugin.getFirewallUrlUser(), json))
        return false;

    try {
        BOOST_FOREACH(
            boost::property_tree::ptree::value_type &v, json
        ) {
            insertRichRules(v, _incomingForwardingRules, _incomingRules, clientIp);
        }
    }
    catch (boost::property_tree::ptree_bad_path &ex) {
        _logger.error() << "Invalid firewall rules: " << ex.what() << std::flush;
        return false;
    }
    _logger.note() << _username << "'s forwarding rules:" << std::flush;
    for (auto r : _incomingForwardingRules)
        _logger.note() << r << std::flush;
    _logger.note() << _username << "'s incoming rules:" << std::flush;
    for (auto r : _incomingRules)
        _logger.note() << r << std::flush;

    try {
        _logger.note() << "Getting current policy rich rules" << std::flush;
        std::map<std::string, sdbus::Variant> policySettings =
            _plugin.firewallPolicy().getPolicySettings("arachne-incoming");
        std::map<std::string, sdbus::Variant> newPolicySettings;
        if (policySettings.find(std::string("rich_rules")) != policySettings.end()) {
            const std::vector<std::string> &rulesV(
                policySettings.at(std::string("rich_rules"))
            );
            std::set<std::string> rulesS(rulesV.begin(), rulesV.end());
            rulesS.insert(_incomingForwardingRules.begin(), _incomingForwardingRules.end());
            newPolicySettings["rich_rules"] =
                std::vector<std::string>(rulesS.begin(), rulesS.end());
        }
        else
            newPolicySettings["rich_rules"] =
                std::vector<std::string>(_incomingForwardingRules.begin(),
                                         _incomingForwardingRules.end());
        _plugin.firewallPolicy().setPolicySettings("arachne-incoming", newPolicySettings);
    }
    catch (const sdbus::Error &ex) {
        _logger.error() << "Cannot update incoming policy rich rules: " << ex.what() << std::flush;
        return false;
    }

    try {
        _logger.note() << "Adding Incoming rules" << std::flush;
        for (const std::string &rule : _incomingRules) {
            _plugin.firewallZone().addRichRule("arachne", rule, FirewallD1::DEFAULT_TIMEOUT);
        }
    }
    catch (const sdbus::Error &ex) {
        _logger.error() << "Cannot update incoming rich rules: " << ex.what() << std::flush;
        return false;
    }

    _logger.note() << _username << "'s rich rules updated" << std::flush;

    return true;
}

bool ClientSession::removeFirewalRules()
{
    _logger.note() << "Removing " << _username << "'s rich rules" << std::flush;
    try {
        _logger.note() << "Getting current forwarding rich rules" << std::flush;
        std::map<std::string, sdbus::Variant> policySettings =
            _plugin.firewallPolicy().getPolicySettings("arachne-incoming");
        std::map<std::string, sdbus::Variant> newPolicySettings;
        if (policySettings.find(std::string("rich_rules")) != policySettings.end()) {
            const std::vector<std::string> &rulesV(
                policySettings.at(std::string("rich_rules"))
            );
            std::set<std::string> rulesS(rulesV.begin(), rulesV.end());
            for (auto it=_incomingForwardingRules.begin();
                 it != _incomingForwardingRules.end();
                 it++
            ) {
                _logger.note() << "Removing rule " << *it << std::flush;
                rulesS.erase(*it);
            }
            std::map<std::string, sdbus::Variant> newPolicySettings;
            newPolicySettings["rich_rules"] =
                std::vector<std::string>(rulesS.begin(), rulesS.end());
            _plugin.firewallPolicy().setPolicySettings("arachne-incoming", newPolicySettings);
        }
        else
            _logger.note() << "There are no forwarding rich rules" << std::flush;
    }
    catch (const sdbus::Error &ex) {
        _logger.error() << "Cannot update forwarding rich rules: " << ex.what() << std::flush;
        return false;
    }

    try {
        for (const std::string &rule : _incomingRules) {
            _plugin.firewallZone().removeRichRule("arachne", rule);
        }
    }
    catch (const sdbus::Error &ex) {
        _logger.error() << "Cannot update incoming rich rules: " << ex.what() << std::flush;
        return false;
    }

    return true;
}

bool ClientSession::updateEverybodyRules()
{
    _logger.note() << "Updating everybody rules" << std::flush;
    boost::property_tree::ptree json;
    if (!readJson(_plugin.getFirewallUrlEverybody(), json))
        return false;

    std::set<std::string> newForwardingRules;
    std::set<std::string> newLocalRules;
    try {
        std::string icmpRules = json.get<std::string>("icmpRules");
        _logger.note() << "ICMP rules: " << icmpRules << std::flush;
        if (icmpRules == "ALLOW_ALL") {
            newForwardingRules.insert("rule icmp-type name=\"echo-reply\" accept");
            newForwardingRules.insert("rule icmp-type name=\"echo-request\" accept");
            _icmpRules = ALLOW_ALL;
        }
        else if (icmpRules == "DENY") {
            _icmpRules = DENY;
        }
        else if (icmpRules == "ALLOW_ALL_GRANTED") {
            _icmpRules = ALLOW_ALL_GRANTED;
        }
        else {
            _logger.error() << "Invalid value of icmpRules: " << icmpRules << std::flush;
            return false;
        }

        BOOST_FOREACH(
            boost::property_tree::ptree::value_type &v,
            json.get_child("richRules")
        ) {
            insertRichRules(v, newForwardingRules, newLocalRules);
        }
    }
    catch (boost::property_tree::ptree_bad_path &ex) {
        _logger.error() << "Invalid firewall rules: " << ex.what() << std::flush;
        return false;
    }
    _logger.note() << "Everybody rules:" << std::flush;
    for (auto r : newForwardingRules)
        _logger.note() << r << std::flush;

    try {
        _logger.note() << "Getting current rich rules" << std::flush;
        std::map<std::string, sdbus::Variant> policySettings =
            _plugin.firewallPolicy().getPolicySettings("arachne-incoming");
        std::map<std::string, sdbus::Variant> newPolicySettings;
        if (policySettings.find(std::string("rich_rules")) != policySettings.end()) {
            const std::vector<std::string> &rulesV(policySettings.at(std::string("rich_rules")));
            std::set<std::string> rulesS(rulesV.begin(), rulesV.end());
            std::erase_if(rulesS, [newForwardingRules] (std::string r) {
                return
                    r.find("source address") == std::string::npos
                    &&
                    newForwardingRules.find(r) == newForwardingRules.end()
                    ;
            });
            rulesS.merge(newForwardingRules);
            newPolicySettings["rich_rules"] =
                std::vector<std::string>(rulesS.begin(), rulesS.end());
        }
        else
            newPolicySettings["rich_rules"] =
                std::vector<std::string>(newForwardingRules.begin(), newForwardingRules.end());
        _plugin.firewallPolicy().setPolicySettings("arachne-incoming", newPolicySettings);
    }
    catch (const sdbus::Error &ex) {
        _logger.error() << "Cannot update rich rules: " << ex.what() << std::flush;
        return false;
    }

    _logger.note() << "Everybody rich rules updated" << std::flush;
    return true;
}

void ClientSession::insertRichRules(
    const boost::property_tree::ptree::value_type &node,
    std::set<std::string> &forwardingRules,
    std::set<std::string> &localRules,
    const std::string &clientIp
)
{
    boost::optional<std::string> value;
    std::stringstream rule;
    bool isLocal = false;

    std::string destination;
    value = node.second.get_optional<std::string>("destinationAddress");
    if (value.has_value()) {
        if (!_plugin.getMyIps().contains(value.value()))
            destination = " destination address=\"" + value.value() + "\"";
    }

    rule << "rule family=\"ipv4\"";
    if (!clientIp.empty())
        rule << " source address=\"" << clientIp << "\"";
    rule << destination;

    value = node.second.get_optional<std::string>("serviceName");
    bool isEverything = true;
    if (value.has_value()) {
        rule << " service name=\"" << value.value() << "\"";
        isEverything = false;
    }

    value = node.second.get_optional<std::string>("port");
    if (value.has_value()) {
        rule << " port " << value.value();
        isEverything = false;
    }

    rule << " accept";

    if (destination.empty())
        localRules.insert(rule.str());
    else
        forwardingRules.insert(rule.str());

    if (_icmpRules == ALLOW_ALL_GRANTED && !isEverything) {
        std::stringstream reply;
        reply << "rule family=\"ipv4\"";
        if (!clientIp.empty())
            reply << " source address=\"" << clientIp << "\"";
        reply
            << destination
            << " icmp-type name=\"echo-reply\""
            << " accept";
        std::stringstream request;
        request << "rule family=\"ipv4\"";
        if (!clientIp.empty())
            request << " source address=\"" << clientIp << "\"";
        request
            << destination
            << " icmp-type name=\"echo-request\""
            << " accept";
        forwardingRules.insert(request.str());
        forwardingRules.insert(reply.str());
    }
}

bool ClientSession::readJson(const Url &url, boost::property_tree::ptree &json)
{
    _logger.note() << "Getting rules from " << url.str() << std::flush;
    http::Request request(http::GET, url);
    request.basicAuth(_username, _password);
    http::Response response;
    http::Http httpClient;
    std::stringstream body;

    try {
        httpClient.doHttp(request, response, &body);
    }
    catch (http::HttpException &ex) {
        _logger.error() << "Error connecting to " << url.str() << ": " << ex.what() << std::endl;
        return false;
    }

    try {
        boost::property_tree::read_json(body, json);
    }
    catch (const std::exception &ex) {
        _logger.error() << "Cannot parse json. " << ex.what() << std::endl;
        return false;
    }
    _logger.note() << "Got " << body.str() << std::endl;
    return true;
}
