#ifndef CLIENT_SESSION_H
#define CLIENT_SESSION_H

#include "ArachneLogger.h"

#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot include openvpn-plugin.h"
#endif

#include <boost/property_tree/ptree.hpp>

#include <set>

class Url;
class ArachnePlugin;

enum IcmpRules {
    ALLOW_ALL,
    ALLOW_ALL_GRANTED,
    DENY
};

class ClientSession
{
public:
    ClientSession(ArachnePlugin &plugin, plugin_vlog_t logFunc, int sessionid);
    ~ClientSession();

    bool authUser(const Url &url, const std::string &username, const std::string &password);
    bool setFirewallRules(const std::string &clientIp);
    bool removeFirewalRules();
    bool updateEverybodyRules();

    ArachneLogger &getLogger() { return _logger; }

private:
    ArachnePlugin &_plugin;
    ArachneLogger _logger;
    int _sessionId;
    std::string _username;
    std::string _password;
    std::set<std::string> _incomingForwardingRules;
    std::set<std::string> _incomingRules;
    IcmpRules _icmpRules;

    void insertRichRules(
        const boost::property_tree::ptree::value_type &node,
        std::set<std::string> &forwardingRules,
        std::set<std::string> &localRules,
        const std::string &clientIp = ""
    );
    bool readJson(const Url &url, boost::property_tree::ptree &json);
};

#endif
