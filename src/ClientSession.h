#ifndef CLIENT_SESSION_H
#define CLIENT_SESSION_H

#include "ArachneLogger.h"
#include "Config.h"

#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot include openvpn-plugin.h"
#endif

#include <boost/property_tree/ptree.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>

#include <set>
#include <list>

class Url;
class ArachnePlugin;

enum IcmpRules {
    ALLOW_ALL,
    ALLOW_ALL_GRANTED,
    DENY
};

class RemoteNetwork {
public:
    RemoteNetwork(const std::string &address, const std::string &mask)
        : _address(address), _mask(mask)
    {}

    const std::string &address() const { return _address; };
    const std::string &mask() const { return _mask; };

private:
    const std::string _address;
    const std::string _mask;
};

class ClientSession
{
public:
    ClientSession(ArachnePlugin &plugin, plugin_vlog_t logFunc, int sessionid);
    ~ClientSession();

    void readConfigFile(const std::string &filename);

    void commonName(const std::string &commonName) { _commonName = commonName; }
    const std::string &commonName() const { return _commonName; }

    void vpnIp(const std::string &ip) { _vpnIp = ip; }
    const std::string &vpnIp() const { return _vpnIp; }

    void remoteIp(const std::string &ip) { _remoteIp = ip; }
    const std::string &remoteIp() const { return _remoteIp; }

    void loginUser(
        const Url &url,
        const std::string &username,
        const std::string &password
    );
    void authUser(const Url &url);
    void verifyClientIp();

    void addUserFirewallRules();
    void removeUserFirewalRules();
    void updateEverybodyRules();

    void addRoutesToRemoteNetworks();
    void removeRoutesToRemoteNetworks();

    ArachneLogger &logger() { return _logger; }

private:
    ArachnePlugin &_plugin;
    ArachneLogger _logger;
    int _sessionId;
    std::string _username;
    std::string _apiToken;
    std::set<std::string> _incomingForwardingRules;
    std::set<std::string> _incomingRules;
    IcmpRules _icmpRules;
    std::string _commonName;
    bool _verifyIpDns;
    std::vector<std::string> _ipWhitelist;
    std::string _vpnIp;
    std::string _remoteIp;
    std::list<RemoteNetwork> _remoteNetworks;

    std::string doHttp(
        const Url &url,
        const std::string &authentication
    );
    void insertRichRules(
        const boost::property_tree::ptree::value_type &node,
        std::set<std::string> &forwardingRules,
        std::set<std::string> &localRules,
        const std::string &clientIp = ""
    );
    void readJson(const Url &url, boost::property_tree::ptree &json);
    void addRoute(int fd, const std::string &address, const std::string &mask);
    void removeRoute(int fd, const std::string &address, const std::string &mask);
    std::string makeBearerAuth();
};

#endif
