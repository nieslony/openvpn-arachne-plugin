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

class Url;

class ClientSession
{
public:
    ClientSession(plugin_vlog_t logFunc, int sessionid);
    ~ClientSession();

    bool authUser(const Url &url, const std::string &username, const std::string &password);
    ArachneLogger &getLogger() { return _logger; }

private:
    ArachneLogger _logger;
    int _sessionId;
};

#endif
