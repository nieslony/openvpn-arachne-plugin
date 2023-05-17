#include "ArachnePlugin.h"
#include "ClientSession.h"

#include <fstream>

static const std::string URL_AUTH = "/auth";
static const std::string FN_IP_FORWATD = "/proc/sys/net/ipv4/ip_forward";

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
    std::string enableRouting = _config.get("enable-routing");
    if (enableRouting == "RESTORE_ON_EXIT") {
        _savedIpForward = getRoutingStatus();
        if (enableRouting == "1") {
            _logger.note() << "Enabling IP forwarding" << std::flush;
            setRoutingStatus("1");
        } else {
            _logger.note() << "IP forwarding already enabled" << std::flush;
        }
    } else if (enableRouting == "ENABLE") {
        _logger.note() << "Enabling IP forwarding" << std::flush;
        setRoutingStatus("1");
    } else if (enableRouting == "OFF") {
        _logger.note() << "Don't enable IP forwarding" << std::flush;
    } else {
        throw PluginException("Invalid value of enable-routing: " + enableRouting);
    }

    _enableFirewall = _config.getBool("enable-firewall");
    if (_enableFirewall) {
        _firewallZone = _config.get("firewall-zone");
        if (_firewallZone == "") {
            _firewallZone = "arachne";
            _logger.warning() << "firewall-zone not given, fall back to arachne" << std::flush;
        } else {
            _logger.note() << "Enabling firewall zone \"" + _firewallZone << "\"" << std::flush;
        }
    }
}

ArachnePlugin::~ArachnePlugin()
{
    _logger.note() << "Clean up" << std::flush;
    if (_savedIpForward != "1" && _savedIpForward != "") {
        _logger.note() << "Restoring IP forwading to " << _savedIpForward << std::flush;
        setRoutingStatus(_savedIpForward);
    }
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

std::string ArachnePlugin::getRoutingStatus()
{
    std::string s;
    std::ifstream ifs;
    ifs.open (FN_IP_FORWATD);
    if (!ifs.is_open()) {
        throw std::runtime_error("Error opening " + FN_IP_FORWATD);
    }
    ifs >> s;
    ifs.close();
    return s;
}

void ArachnePlugin::setRoutingStatus(const std::string&)
{
    std::ofstream ofs;
    ofs.open(FN_IP_FORWATD);
    if (!ofs.is_open()) {
        throw std::runtime_error("Cannot open " + FN_IP_FORWATD + " for reading");
    }
    ofs << _savedIpForward << std::endl;
    ofs.close();
}
