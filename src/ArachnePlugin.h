#ifndef ARACHNE_PLUGIN_H
#define ARACHNE_PLUGIN_H

#include <string>
#include <iostream>

#include <boost/asio/ssl.hpp>
#include <boost/asio.hpp>

#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot inclide openvpn-plugin.h"
#endif

#include "Url.h"
#include "Http.h"

class Logger;
class ClientSession;

class PluginException : public std::runtime_error {
public:
    PluginException(const std::string& what) : runtime_error(what) {}
};

class ArachnePlugin {
private:
    plugin_vlog_t _log_func = NULL;
    time_t _startupTime = -1;
    long _sessionCounter = 0;
    Logger *_logger = NULL;
    Http _http;

    Url _authUrl;
    std::string _caFile;
    bool _ignoreSsl;
    bool _handleIpForwarding;
    std::string _oldIpForwarding;
    bool _manageFirewall = false;
    std::string _firewallZone = "arachne-uservpn";

    void chop(std::string&);

    int http(const Url &url, const std::string& user, std::string password, ClientSession*);

    //std::string base64(const char* in) noexcept;

    //void log(openvpn_plugin_log_flags_t flags, const char *format, ...);
    const char* getenv(const char *key, const char *envp[]);
    void parseOptions(const char **argv);

    template<typename Socket>
    int handleRequest(Socket &socket, const std::string &userPwd, ClientSession* session);

    void enableIpForwarding();
    void resetIpForwarding();

public:
    ArachnePlugin(const openvpn_plugin_args_open_in*);
    ~ArachnePlugin();

    int userAuthPassword(const char *argv[], const char *envp[], ClientSession*);
    int pluginUp(const char *argv[], const char *envp[], ClientSession*);
    int pluginDown(const char *argv[], const char *envp[], ClientSession*);

    ClientSession *createClientSession();

    // void log(openvpn_plugin_log_flags_t flags, long sessionId, const char *format, ...);

    time_t startupTime() const { return _startupTime; }
    plugin_vlog_t log_func() const { return _log_func; }
};

#endif
