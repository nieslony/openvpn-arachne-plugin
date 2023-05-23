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

#include <list>

class Url;
class ArachnePlugin;

class ClientSession
{
public:
    ClientSession(ArachnePlugin &plugin, plugin_vlog_t logFunc, int sessionid);
    ~ClientSession();

    bool authUser(const Url &url, const std::string &username, const std::string &password);
    bool setFirewallRules(const std::string &clientIp, const Url &url);
    bool removeFirewalRules();

    ArachneLogger &getLogger() { return _logger; }

private:
    ArachnePlugin &_plugin;
    ArachneLogger _logger;
    int _sessionId;
    std::string _username;
    std::string _password;
    std::list<std::string> _richRules;
};

#endif
