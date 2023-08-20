#ifndef ARACHNE_PLUGIN_H
#define ARACHNE_PLUGIN_H

#include <string>
#include <iostream>

#include <boost/asio/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>

#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot inclide openvpn-plugin.h"
#endif

#include "Url.h"
#include "Http.h"
#include "Firewall.h"

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
    Firewall _firewall;

    Url _authUrl;
    std::string _caFile;
    bool _ignoreSsl = false;
    bool _handleIpForwarding =  false;
    std::string _oldIpForwarding;
    bool _manageFirewall = false;
    std::string _firewallZone = "arachne-uservpn";

    const char* getenv(const char *key, const char *envp[]);
    void parseOptions(const char **argv);

    template<typename Socket>
    int handleRequest(Socket &socket, const std::string &userPwd, ClientSession* session);

    void enableIpForwarding();
    void resetIpForwarding();

    int setupFirewall(const std::string &clientIp, ClientSession *session) noexcept;
    int getFirewallWhats(boost::property_tree::ptree::value_type &node,
                         std::vector<std::string> &whats,
                          ClientSession *session) noexcept;
    int getFirewallWheres(boost::property_tree::ptree::value_type &node,
                          std::vector<std::string> &wheres,
                          ClientSession *session
                         ) noexcept;

public:
    ArachnePlugin(const openvpn_plugin_args_open_in*);
    ~ArachnePlugin();

    bool ignoreSsl() const { return _ignoreSsl; }

    int userAuthPassword(const char *argv[], const char *envp[], ClientSession*) noexcept;
    int pluginUp(const char *argv[], const char *envp[], ClientSession*) noexcept;
    int pluginDown(const char *argv[], const char *envp[], ClientSession*) noexcept;
    int clientConnect(const char *argv[], const char *envp[], ClientSession*) noexcept;
    int clientDisconnect(const char *argv[], const char *envp[], ClientSession*) noexcept;

    ClientSession *createClientSession();

    time_t startupTime() const { return _startupTime; }
    plugin_vlog_t log_func() const { return _log_func; }
};

#endif
