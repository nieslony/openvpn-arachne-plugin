#ifndef ARACHNE_PLUGIN_H
#define ARACHNE_PLUGIN_H

#include <cstring>
#include <ostream>
#include <sched.h>
#include <sstream>
#include <stdio.h>
#include <set>
#include <list>
#include <boost/property_tree/ptree.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>

#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot include openvpn-plugin.h"
#endif

#include "ArachneLogger.h"
#include "Config.h"
#include "BreakDownRootDaemon.h"
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

    void userAuthPassword(const char *envp[], ClientSession*);
    void pluginUp(const char *argv[], const char *envp[], ClientSession*);
    void pluginDown(const char *argv[], const char *envp[], ClientSession*);
    void clientConnect(const char *argv[], const char *envp[], ClientSession*);
    void clientDisconnect(const char *argv[], const char *envp[], ClientSession*);

    const std::string &firewallZoneName() { return _firewallZoneName; }
    const Url &firewallUrlUser() { return _firewallUrlUser; }
    const std::set<std::string> &myIps() { return _myIps; }

    FirewallD1_Zone &firewallZone() { return _firewallZone; }
    FirewallD1_Policy &firewallPolicy() { return _firewallPolicy; }

    const std::string &clientConfig() { return _clientConfig; }
    bool userPasswdAuthEnabled() const { return !_authUrl.empty(); }

    const std::string &interface() const { return _interface; }

    const std::string &incomingPolicyName() const { return _incomingPolicyName; }
    const std::string &outgongPolicyName() const { return _outgoingPolicyName; }

    std::string ipSetNameSrc(long id) const;
    std::string ipSetNameDst(long id) const;

private:
    ArachneLogger _logger;
    BreakDownRootDaemon _breakDownRootDaemon;
    plugin_vlog_t _logFunc;
    int _lastSession;
    Config _config;

    std::unique_ptr<sdbus::IConnection> _dbusConnection;
    FirewallD1_Zone _firewallZone;
    FirewallD1_Policy _firewallPolicy;

    Url _loginUrl;
    Url _authUrl;
    Url _firewallUrlUser;
    std::set<std::string> _myIps;
    std::string _savedIpForward;
    std::string _enableRouting;
    bool _enableFirewall;
    std::string _firewallZoneName;
    std::string _firewallRulesPath;
    std::string _clientConfig;
    std::string _interface;

    std::string _incomingPolicyName;
    std::string _outgoingPolicyName;
    std::string _toHostPolicyName;
    std::string _fromHostPolicyName;

    pid_t _backgroundPid;
    boost::iostreams::stream<boost::iostreams::file_descriptor_sink> _backgroundCommandChannel;
    boost::iostreams::stream<boost::iostreams::file_descriptor_source> _backgroundReplyChannel;

    const char* getEnv(const char* key, const char *envp[]);
    std::ostream&  dumpEnv(std::ostream &os, const char *envp[]);
    void readConfigFile(const char*);

    std::string getRoutingStatus();
    void setRoutingStatus(const std::string&);
    void cleanupPolicies(ClientSession *session);
    void loadFirewallRules(ClientSession *session);
    void applyPermentRulesToRuntime(ClientSession *session);

    void createRichRules(
        const boost::property_tree::ptree &ptree,
        const std::string icmpRules,
        std::vector<std::string> &richRules,
        std::vector<std::string> &localRichRules,
        std::map<std::string, std::vector<std::string>> &ipSets,
        ClientSession *session
    );
    void getLocalIpAddresses(ClientSession *session);

    void parseConfigFile(const openvpn_plugin_args_open_in *in_args);
    void startBackgroundProcess();
};

#endif
