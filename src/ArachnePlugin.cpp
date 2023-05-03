#include "ArachnePlugin.h"
#include "ClientSession.h"

#include <fstream>

#define URL_AUTH     "/auth"

ArachnePlugin::ArachnePlugin(const openvpn_plugin_args_open_in *in_args)
    : _logger(in_args->callbacks->plugin_vlog), _lastSession(0)
{
    _logger.note() << "Initializing" << "..." << std::flush;
    _logFunc = in_args->callbacks->plugin_vlog;

    const char* configFile = in_args->argv[1];
    if (configFile == 0)
        throw PluginException("Please specify configuration file");

    readConfigFile(configFile);
    _authUrl = _config.get("auth-url");
}

ArachnePlugin::~ArachnePlugin()
{
    _logger.note() << "Clean up" << std::flush;
}

ClientSession *ArachnePlugin::createClientSession()
{
    return new ClientSession(_logFunc, ++_lastSession);
}

const char* ArachnePlugin::getEnv(const char* key, const char *envp[])
{
    if (envp) {
        int i;
        int keylen = strlen(key);
        for (i = 0; envp[i]; i++) {
            if (!strncmp(envp[i], key, keylen)) {
                const char *cp = envp[i] + keylen;
                if (*cp == '=') {
                    return cp + 1;
                }
            }
        }
    }

    return "";
}

int ArachnePlugin::userAuthPassword(const char *envp[], ClientSession* session)
{
    std::string username(getEnv("username", envp));
    std::string password(getEnv("password", envp));

    Url url(_authUrl);
    url.path(_authUrl.path() + URL_AUTH);
    if (session->authUser(url, username, password))
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    else
        return OPENVPN_PLUGIN_FUNC_ERROR;
}

void ArachnePlugin::readConfigFile(const char*filename)
{
    std::ifstream ifs;
    ifs.open (filename, std::ifstream::in);
    if (!ifs.is_open()) {
        throw std::runtime_error("Cannot open config file");
    }
    _config.load(ifs);
    ifs.close();
}
