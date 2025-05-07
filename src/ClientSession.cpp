#include "ArachnePlugin.h"
#include "ClientSession.h"
#include "Config.h"
#include "Http.h"

#include <boost/asio.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string_regex.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/asio.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/foreach.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/regex.hpp>

#include <set>
#include <sstream>
#include <string>

#include <net/route.h>
#include <sys/socket.h>

namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http = beast::http;       // from <boost/beast/http.hpp>
namespace net = boost::asio;        // from <boost/asio.hpp>
namespace ssl = net::ssl;
using tcp = net::ip::tcp;           // from <boost/asio/ip/tcp.hpp>

ClientSession::ClientSession(ArachnePlugin &plugin, plugin_vlog_t logFunc, int sessionId)
    : _plugin(plugin), _logger(logFunc, sessionId), _sessionId(sessionId)
{
    _logger.note() << "Creating Session " << _sessionId << std::flush;
}

ClientSession::~ClientSession()
{
    _logger.note() << "Cleanup session" << std::flush;
}

void ClientSession::readConfigFile(const std::string &filename)
{
    Config config;
    std::string myFilename = boost::replace_all_copy(filename, "%cn", _commonName);
    _logger.note() << "Reading client configuration " <<myFilename << std::flush;
    try {
        std::ifstream ifs;
        ifs.open (myFilename, std::ifstream::in);
        if (!ifs.is_open()) {
            throw std::runtime_error("Cannot open config file");
        }
        config.load(ifs);
        ifs.close();

        std::string siteVerification = config.get("site-verification", "");
        if (siteVerification == "DNS")
            _verifyIpDns = true;
        else
            _verifyIpDns = false;
        _logger.debug()
            << "Client verification type: " << siteVerification
            << std::flush;
        if (siteVerification == "WHITELIST") {
            std::string ipWhiteList = config.get("ip-wihtelist");
            boost::algorithm::split_regex(_ipWhitelist, ipWhiteList, boost::regex(", *"));
            _logger.debug()
                << " IP whitelist: " << ipWhiteList
                << std::flush;
        }

        int noRemoteNetworks = config.getInt("no-remote-networks", -1);
        for (int i = 0; i < noRemoteNetworks; i++) {
            std::string addressKey =
                "remote-network" + std::to_string(i) + "-address";
            std::string maskKey =
                "remote-network" + std::to_string(i) + "-mask";
            const RemoteNetwork remoteNetwork(
                config.get(addressKey),
                config.get(maskKey)
            );
            _remoteNetworks.push_back(remoteNetwork);
        }
    }
    catch (std::exception &ex) {
        std::stringstream str;
        str << "Error reading " << myFilename << ": " << ex.what();
        throw ConfigException(str.str());
    }
}

void ClientSession::verifyClientIp()
{
    if (_verifyIpDns)
    {
        boost::asio::ip::address_v4 ip =
            boost::asio::ip::address_v4::from_string(vpnIp());
        boost::asio::io_service io_service;
        boost::asio::ip::tcp::resolver resolver(io_service);
        boost::asio::ip::tcp::resolver::results_type endpoints =
            resolver.resolve(_commonName, "");
        for (auto &it : endpoints)
        {
            boost::asio::ip::tcp::endpoint endpoint = it;
            if (endpoint.address() == ip)
            {
                _logger.note()
                    << "IP verification succeeded. IP " << vpnIp()
                    << " matches DNS entry " <<_commonName
                    << std::flush;
                return;
            }
        }
        std::stringstream msg;
        msg
            << "IP verification failed. IP " << vpnIp()
            << " does not match DNS entry"
            << std::flush;
        throw PluginException(msg.str());
    }

    if (!_ipWhitelist.empty())
    {
        for (auto &it :_ipWhitelist)
        {
            if (it == vpnIp())
            {
                _logger.note()
                    << "IP verification succeeded. IP " << vpnIp()
                    << " matches whitelist"
                    << std::flush;
                return;
            }
        }
        std::stringstream msg;
        msg
            << "IP verification failed. IP " << vpnIp()
            << " does not match whitelist"
            << std::flush;
        throw PluginException(msg.str());
    }

    _logger.note() << "No client verification enabled" << std::flush;
    return;
}

std::string makeBasicAuth(const std::string &username, const std::string &password)
{
    using namespace boost::archive::iterators;
    std::string authStr = username + ":" + password;
    std::stringstream os;
    using IT =
        base64_from_binary<    // convert binary values to base64 characters
            transform_width<   // retrieve 6 bit integers from a sequence of 8 bit bytes
                std::string::const_iterator,
                6,
                8
            >
        >; // compose all the above operations in to a new iterator
    std::copy(
        IT(std::begin(authStr)),
        IT(std::end(authStr)),
        std::ostream_iterator<char>(os)
    );
    os << std::string("====").substr(0, (4 - os.str().length() % 4) % 4);
    return "Basic " + os.str();
}

std::string ClientSession::makeBearerAuth()
{
    return "Bearer " + _apiToken;
}

void ClientSession::loginUser(
    const Url &url,
    const std::string &username,
    const std::string &password
) {
    _username = username;
    std::string body;
    try
    {
        body = doHttp(url, makeBasicAuth(username, password));
    }
    catch (HttpException &ex)
    {
        throw PluginException("Authentication failed", ex.what());
    }

    boost::property_tree::ptree json;
    try {
        std::istringstream iss(body);
        boost::property_tree::read_json(iss, json);
        _apiToken = json.get<std::string>("apiAuthToken");
    }
    catch (const std::exception &ex) {
        throw PluginException("Cannot parse json", ex.what());
    }

    return;
}

void ClientSession::authUser(const Url &url)
{
    try {
        doHttp(url, makeBearerAuth());
    }
    catch (HttpException &ex) {
        throw PluginException("Authentication failed", ex.what());
    }
}

void ClientSession::addUserFirewallRules()
{
    if (_plugin.firewallUrlUser().empty()) {
        _logger.note() << "No url-firewall-user specified, skipping user firewall rules";
        return;
    }

    _logger.note() << "Updating " << _username << "'s firewall rules" << std::flush;
    boost::property_tree::ptree json;
    readJson(_plugin.firewallUrlUser(), json);

    try {
        BOOST_FOREACH(
            boost::property_tree::ptree::value_type &v, json
        ) {
            insertRichRules(v, _incomingForwardingRules, _incomingRules, vpnIp());
        }
    }
    catch (boost::property_tree::ptree_bad_path &ex) {
        throw PluginException(
            "Invalid firewall rules",
            ex.what()
        );
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
            _plugin.firewallPolicy().getPolicySettings(_plugin.incomingPolicyName());
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
        _plugin.firewallPolicy().setPolicySettings(_plugin.incomingPolicyName(), newPolicySettings);
    }
    catch (const sdbus::Error &ex) {
        throw PluginException(
            "Cannot update incoming policy rich rules",
            ex.what()
        );
    }

    try {
        _logger.note() << "Adding Incoming rules" << std::flush;
        for (const std::string &rule : _incomingRules) {
            _plugin.firewallZone().addRichRule(_plugin.firewallZoneName(), rule, FirewallD1::DEFAULT_TIMEOUT);
        }
    }
    catch (const sdbus::Error &ex) {
        throw PluginException(
            "Cannot update incoming rich rules",
            ex.what()
        );
    }

    _logger.note() << _username << "'s rich rules updated" << std::flush;
}

void ClientSession::removeUserFirewalRules()
{
    _logger.note() << "Removing " << _username << "'s rich rules" << std::flush;
    try {
        _logger.note() << "Getting current forwarding rich rules" << std::flush;
        std::map<std::string, sdbus::Variant> policySettings =
            _plugin.firewallPolicy().getPolicySettings(_plugin.incomingPolicyName());
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
            _plugin.firewallPolicy().setPolicySettings(_plugin.incomingPolicyName(), newPolicySettings);
        }
        else
            _logger.note() << "There are no forwarding rich rules" << std::flush;
    }
    catch (const sdbus::Error &ex) {
        throw PluginException("Cannot update forwarding rich rules: ", ex.what());
    }

    try {
        for (const std::string &rule : _incomingRules) {
            _plugin.firewallZone().removeRichRule(_plugin.firewallZoneName(), rule);
        }
    }
    catch (const sdbus::Error &ex) {
        throw PluginException("Cannot update incoming rich rules: ", ex.what());
    }
}

void ClientSession::updateEverybodyRules()
{
    if (_plugin.firewallUrlEverybody().empty()) {
        _logger.note() << "No url-firewall-everybody specified, skipping everybody firewall rules";
        return;
    }

    _logger.note() << "Updating everybody rules" << std::flush;
    boost::property_tree::ptree json;
    readJson(_plugin.firewallUrlEverybody(), json);

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
            throw PluginException("Invalid value of icmpRules: ", icmpRules);
        }

        BOOST_FOREACH(
            boost::property_tree::ptree::value_type &v,
            json.get_child("richRules")
        ) {
            insertRichRules(v, newForwardingRules, newLocalRules);
        }
    }
    catch (boost::property_tree::ptree_bad_path &ex) {
        throw PluginException("Invalid firewall rules", ex.what());
    }
    _logger.note() << "Everybody rules:" << std::flush;
    for (auto r : newForwardingRules)
        _logger.note() << r << std::flush;

    try {
        _logger.note() << "Getting current rich rules" << std::flush;
        std::map<std::string, sdbus::Variant> policySettings =
            _plugin.firewallPolicy().getPolicySettings(_plugin.incomingPolicyName());
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
        _plugin.firewallPolicy().setPolicySettings(_plugin.incomingPolicyName(), newPolicySettings);
    }
    catch (const sdbus::Error &ex) {
        throw PluginException("Cannot update rich rules", ex.what());
    }

    _logger.note() << "Everybody rich rules updated" << std::flush;
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

    std::string destination;
    value = node.second.get_optional<std::string>("destinationAddress");
    if (value.has_value()) {
        if (!_plugin.myIps().contains(value.value()))
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

void ClientSession::readJson(
    const Url &url,
    boost::property_tree::ptree &json
) {
    _logger.note() << "Getting rules from " << url.str() << std::flush;
    std::string body;

    try {
        body = doHttp(url, makeBearerAuth());
    }
    catch (HttpException &ex) {
        std::stringstream msg;
        msg << "Error connecting to " << url.str();
        throw PluginException(msg.str(), ex.what());
    }

    try {
        std::istringstream iss(body);
        boost::property_tree::read_json(iss, json);
    }
    catch (const std::exception &ex) {
        throw PluginException("Cannot parse json", ex.what());
    }
    _logger.debug() << "Got " << body << std::endl;
}

std::string ClientSession::doHttp(
    const Url &url,
    const std::string &authentication
) {
    net::io_context ioc;
    tcp::resolver resolver(ioc);
    auto const results = resolver.resolve(url.host(), std::to_string(url.port()));
    beast::flat_buffer buffer;

    http::request<http::string_body> req{http::verb::get, url.path(), 11};
    req.set(http::field::host, url.host());
    req.set(http::field::authorization, authentication);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    http::response<http::string_body> res;

    if (url.protocol() == "https") {
        ssl::context ctx(ssl::context::tlsv12_client);
        ctx.set_default_verify_paths();
        ctx.set_verify_mode(ssl::verify_peer);
        ctx.set_verify_callback(
            boost::asio::ssl::rfc2818_verification(url.host())
        );
        beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);
        if(! SSL_set_tlsext_host_name(stream.native_handle(), url.host().c_str()))
        {
            beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
            throw HttpException(ec.message());
        }
        beast::get_lowest_layer(stream).connect(results);
        stream.handshake(ssl::stream_base::client);

        http::write(stream, req);
        http::read(stream, buffer, res);
    }
    else
    {
        beast::tcp_stream stream(ioc);
        stream.connect(results);

        http::write(stream, req);
        http::read(stream, buffer, res);
    }

    if (res.result_int() >= 400) {
        std::stringstream msg;
        msg << "Cannot connect to " << url.str() << ": " << res.result() << "(" << res.result_int() << ")";
        throw HttpException(msg.str());
    }

    return res.body();
}

void ClientSession::addRoutesToRemoteNetworks()
{
    if (_remoteNetworks.empty()) {
        _logger.note()
            << "No remote networks configured. Dont't add any routes."
            << std::flush;
        return;
    }

    int fd = socket(PF_INET, SOCK_DGRAM,  IPPROTO_IP);
    for(const auto &it : _remoteNetworks) {
        _logger.note() <<
            "Add route to remote network "
            << it.address() << " " << it.mask()
            << std::flush;
        addRoute(fd, it.address(), it.mask());
    }
    close(fd);
}

void ClientSession::removeRoutesToRemoteNetworks()
{
    if (_remoteNetworks.empty()) {
        _logger.note()
            << "No remote networks configured. Dont't remove any routes."
            << std::flush;
        return;
    }

    int fd = socket(PF_INET, SOCK_DGRAM,  IPPROTO_IP);
    for(const auto &it : _remoteNetworks) {
        _logger.note() <<
            "Remove route to remote network "
            << it.address() << " " << it.mask()
            << std::flush;
        removeRoute(fd, it.address(), it.mask());
    }
    close(fd);
}

void ClientSession::addRoute(
    int fd,
    const std::string &address,
    const std::string &mask
) {
    struct sockaddr_in * addr;
    struct rtentry route;
    memset(&route, 0, sizeof(route));
    route.rt_flags = RTF_UP | RTF_GATEWAY;

    // gatway
    addr = (struct sockaddr_in*)&route.rt_gateway;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(vpnIp().c_str());

    // destination
    addr = (struct sockaddr_in*) &route.rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(address.c_str());;

    // mask
    addr = (struct sockaddr_in*)&route.rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(mask.c_str());

    if (ioctl( fd, SIOCADDRT, &route) < 0)
    {
        throw PluginException(
            "Cannot add route to "
            + address + " " + mask +
            ": " + strerror(errno)
        );
    }
}

void ClientSession::removeRoute(
    int fd,
    const std::string &address,
    const std::string &mask
) {
    struct sockaddr_in * addr;
    struct rtentry route;
    memset(&route, 0, sizeof(route));

    // destination
    addr = (struct sockaddr_in*) &route.rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(address.c_str());;

    // mask
    addr = (struct sockaddr_in*)&route.rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(mask.c_str());

    if (ioctl( fd, SIOCDELRT, &route) < 0)
    {
        throw PluginException(
            "Cannot remove route to "
            + address + " " + mask +
            ": " + strerror(errno)
        );
    }
}
