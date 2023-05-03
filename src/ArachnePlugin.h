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

private:
    ArachneLogger _logger;
    plugin_vlog_t _logFunc;
    int _lastSession;
    Url _authUrl;

    const char* getEnv(const char* key, const char *envp[]);
    void readConfigFile(const char*);
    Config _config;
};

#endif
