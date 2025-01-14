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
    PluginException(const std::string& what, const std::string &why)
        : runtime_error(what + ": " + why)
    {}
};

class ArachnePlugin
{
public:
    ArachnePlugin(const openvpn_plugin_args_open_in*);
    ~ArachnePlugin();

    ClientSession *createClientSession();

    void setRouting(ClientSession*);
    void restoreRouting(ClientSession*);
    void createFirewallZone(ClientSession*);

    int userAuthPassword(const char *envp[], ClientSession*);
    int pluginUp(const char *argv[], const char *envp[], ClientSession*) noexcept;
    int pluginDown(const char *argv[], const char *envp[], ClientSession*) noexcept;
    int clientConnect(const char *argv[], const char *envp[], ClientSession*) noexcept;
    int clientDisconnect(const char *argv[], const char *envp[], ClientSession*) noexcept;

    const std::string &firewallZoneName() { return _firewallZoneName; }
    const Url &firewallUrlUser() { return _firewallUrlUser; }
    const Url &firewallUrlEverybody() { return _firewallUrlEverybody; }
    const std::set<std::string> &myIps() { return _myIps; }

    FirewallD1_Zone &firewallZone() { return _firewallZone; }
    FirewallD1_Policy &firewallPolicy() { return _firewallPolicy; }

    const std::string &clientConfig() { return _clientConfig; }
    bool userPasswdAuthEnabled() const { return !_authUrl.empty(); }

    const std::string &interface() const { return _interface; }

private:
    ArachneLogger _logger;
    plugin_vlog_t _logFunc;
    int _lastSession;
    Config _config;

    std::unique_ptr<sdbus::IConnection> _dbusConnection;
    FirewallD1_Zone _firewallZone;
    FirewallD1_Policy _firewallPolicy;

    Url _loginUrl;
    Url _authUrl;
    Url _firewallUrlUser;
    Url _firewallUrlEverybody;
    std::set<std::string> _myIps;
    std::string _savedIpForward;
    std::string _enableRouting;
    bool _enableFirewall;
    std::string _firewallZoneName;
    std::string _clientConfig;
    std::string _interface;

    const char* getEnv(const char* key, const char *envp[]);
    std::ostream&  dumpEnv(std::ostream &os, const char *envp[]);
    void readConfigFile(const char*);

    std::string getRoutingStatus();
    void setRoutingStatus(const std::string&);
    void removeAllRichRules();

    void getLocalIpAddresses();
};

#endif
