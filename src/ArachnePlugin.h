#ifndef ARACHNE_PLUGIN_H
#define ARACHNE_PLUGIN_H

#include <stdio.h>
#include <ostream>
#include <sstream>
#include <cstring>

#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot include openvpn-plugin.h"
#endif

#include "ArachneLogger.h"
#include "Url.h"
#include "Config.h"

class ClientSession;

class PluginException : public std::runtime_error {
public:
    PluginException(const std::string& what) : runtime_error(what) {}
};

class ArachnePlugin
{
public:
    ArachnePlugin(const openvpn_plugin_args_open_in*);
    ~ArachnePlugin();

    ClientSession *createClientSession();
    int userAuthPassword(const char *envp[], ClientSession*);

    void setRouting(ClientSession*);
    void restoreRouting(ClientSession*);
    void createFirewallZone(ClientSession*);

    int pluginUp(const char *argv[], const char *envp[], ClientSession*) noexcept;
    int pluginDown(const char *argv[], const char *envp[], ClientSession*) noexcept;
    int clientConnect(const char *argv[], const char *envp[], ClientSession*) noexcept;
    int clientDisconnect(const char *argv[], const char *envp[], ClientSession*) noexcept;

    const std::string &getFirewallZone() { return _firewallZone; }

private:
    ArachneLogger _logger;
    plugin_vlog_t _logFunc;
    int _lastSession;
    Config _config;

    Url _authUrl;
    Url _firewallUrl;
    std::string _savedIpForward;
    std::string _enableRouting;
    bool _enableFirewall;
    std::string _firewallZone;

    const char* getEnv(const char* key, const char *envp[]);
    void readConfigFile(const char*);

    std::string getRoutingStatus();
    void setRoutingStatus(const std::string&);
    void removeAllRichRules();
};

#endif
