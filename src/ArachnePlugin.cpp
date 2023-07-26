#include "ArachnePlugin.h"
#include "ClientSession.h"
#include "FirewallD1.h"

#include <boost/algorithm/string/predicate.hpp>
#include <fstream>
#include <sstream>
#include <boost/algorithm/string.hpp>

static const std::string FN_IP_FORWATD = "/proc/sys/net/ipv4/ip_forward";

ArachnePlugin::ArachnePlugin(const openvpn_plugin_args_open_in *in_args)
    : _logger(in_args->callbacks->plugin_vlog), _lastSession(0), _autoAddIcmpRules(false)
{
    _logger.note() << "Initializing" << "..." << std::flush;
    _logFunc = in_args->callbacks->plugin_vlog;

    const char* configFile = in_args->argv[1];
    if (configFile == NULL)
        throw PluginException("Please specify configuration file");
    _logger.note() << "Reading configuration from " << configFile << std::flush;

    readConfigFile(configFile);
    _authUrl = _config.get("auth-url");
    _enableRouting = _config.get("enable-routing");
    _enableFirewall = _config.getBool("enable-firewall");
    if (_enableFirewall) {
        _firewallZone = _config.get("firewall-zone");
        _firewallUrlUser = _config.get("firewall-url") + "/user_rules";
        _firewallUrlEverybody = _config.get("firewall-url") + "/everybody_rules";
    }
}

ArachnePlugin::~ArachnePlugin()
{
}

ClientSession *ArachnePlugin::createClientSession()
{
    return new ClientSession(*this, _logFunc, ++_lastSession);
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

void ArachnePlugin::setRouting(ClientSession *session)
{
    if (_enableRouting == "RESTORE_ON_EXIT") {
        _savedIpForward = getRoutingStatus();
        if (_enableRouting == "1") {
            session->getLogger().note() << "Enabling IP forwarding" << std::flush;
            setRoutingStatus("1");
        } else {
            session->getLogger().note() << "IP forwarding already enabled" << std::flush;
        }
    } else if (_enableRouting == "ENABLE") {
        session->getLogger().note() << "Enabling IP forwarding" << std::flush;
        setRoutingStatus("1");
    } else if (_enableRouting == "OFF") {
        session->getLogger().note() << "Don't enable IP forwarding" << std::flush;
    } else {
        throw PluginException("Invalid value of enable-routing: " + _enableRouting);
    }
}

void ArachnePlugin::restoreRouting(ClientSession *session)
{
    if (_savedIpForward != "1" && _savedIpForward != "") {
        session->getLogger().note() << "Restoring IP forwading to " << _savedIpForward << std::flush;
        setRoutingStatus(_savedIpForward);
    } else {
        session->getLogger().note() << "Leaving routing untouched" << std::flush;
    }
}

void ArachnePlugin::createFirewallZone(ClientSession *session)
{
    if (_enableFirewall) {
        session->getLogger().note() << "Creating firewall zone '" << _firewallZone << "'" << std::flush;
        auto connection = sdbus::createSystemBusConnection();
        FirewallD1 firewall(connection);
        FirewallD1_Config firewallConfig(connection);

        std::map<std::string, sdbus::Variant> settings;
        settings["target"] = "DROP";
        settings["interfaces"] = std::vector<std::string> { "arachne" };

        try {
            firewallConfig.addZone2(_firewallZone, settings);
            firewall.reload();
        }
        catch (const sdbus::Error &ex)
        {
            if (ex.getName() == "org.fedoraproject.FirewallD1.Exception" &&
                boost::algorithm::starts_with(ex.getMessage(), "NAME_CONFLICT"))
            {
                session->getLogger().warning() << "Firewall zone '" << _firewallZone << "' already exists" << std::flush;
            } else {
                std::stringstream msg;
                msg << "Cannot create firewall zone " << _firewallZone
                    << ": [" << ex.getName() << "]: "
                    << ex.getMessage()
                    ;
                throw PluginException(msg.str());
            }
        }
    } else {
        _logger.note() << "Firewall is disabled" << std::flush;
    }
}

int ArachnePlugin::pluginUp(const char *argv[], const char *envp[], ClientSession*session) noexcept
{
    session->getLogger().note() << "Plugin up..." << std::flush;
    setRouting(session);
    createFirewallZone(session);
    removeAllRichRules();

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::pluginDown(const char *argv[], const char *envp[], ClientSession* session) noexcept
{
    session->getLogger() << "Plugin down..." << std::flush;
    removeAllRichRules();
    restoreRouting(session);

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::clientConnect(
    const char *argv[],
    const char *envp[],
    ClientSession*session
) noexcept
{
    std::string clientIp(getEnv("ifconfig_pool_remote_ip", envp));

    if (_enableFirewall)
    {
        if (session->setFirewallRules(clientIp) && session->updateEverybodyRules())
            return OPENVPN_PLUGIN_FUNC_SUCCESS;
        else
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::clientDisconnect(
    const char *argv[],
    const char *envp[],
    ClientSession* session
) noexcept
{
    if (_enableFirewall)
    {
        if (session->removeFirewalRules() && session->updateEverybodyRules())
            return OPENVPN_PLUGIN_FUNC_SUCCESS;
        else
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

void ArachnePlugin::removeAllRichRules()
{
    if (_enableFirewall) {
        _logger.note() << "Removing all rich rules" << std::flush;
        auto connection = sdbus::createSystemBusConnection();
        FirewallD1_Zone firewallZone(connection);
        for (auto r : firewallZone.getRichRules(_firewallZone))
        {
            _logger.note() << "Removing rich rule " << r << std::flush;
            firewallZone.removeRichRule(_firewallZone, r);
        }
    }
}
