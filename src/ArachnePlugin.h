#ifndef ARACHNE_PLUGIN_H
#define ARACHNE_PLUGIN_H

#include <cstring>
#include <ostream>
#include <sstream>
#include <stdio.h>
#include <set>

#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot include openvpn-plugin.h"
#endif

#include "ArachneLogger.h"
#include "Config.h"
#include "FirewallD1.h"
#include "Url.h"

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

    const std::string &getFirewallZoneName() { return _firewallZoneName; }
    const Url &getFirewallUrlUser() { return _firewallUrlUser; }
    const Url &getFirewallUrlEverybody() { return _firewallUrlEverybody; }

    FirewallD1_Zone &firewallZone() { return _firewallZone; }
    FirewallD1_Policy &firewallPolicy() { return _firewallPolicy; }

private:
    ArachneLogger _logger;
    plugin_vlog_t _logFunc;
    int _lastSession;
    Config _config;

    std::unique_ptr<sdbus::IConnection> _dbusConnection;
    FirewallD1_Zone _firewallZone;
    FirewallD1_Policy _firewallPolicy;

    Url _authUrl;
    Url _firewallUrlUser;
    Url _firewallUrlEverybody;
    std::set<std::string> _myIps;
    std::string _savedIpForward;
    std::string _enableRouting;
    bool _enableFirewall;
    std::string _firewallZoneName;

    const char* getEnv(const char* key, const char *envp[]);
    void readConfigFile(const char*);

    std::string getRoutingStatus();
    void setRoutingStatus(const std::string&);
    void removeAllRichRules();
};

#endif
