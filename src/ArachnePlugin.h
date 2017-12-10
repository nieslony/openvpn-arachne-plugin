#ifndef ARACHNE_PLUGIN_H
#define ARACHNE_PLUGIN_H

#include <string>
#include <iostream>

#include <boost/asio/ssl.hpp>

#include <openvpn-plugin.h>

#include <Url.h>

class ClientSession;

class PluginException : public std::runtime_error {
public:
    PluginException(const std::string& what) : runtime_error(what) {}
};

class ArachnePlugin {
private:
    plugin_vlog_t log_func;

    const char* getenv(const char *key, const char *envp[]);

    Url url;
    time_t _startupTime;
    long _sessionCounter;
    std::string _caFile;
    bool _ignoreSsl = false;

    void chop(std::string&);

    int http(const Url &url, const std::string& userPwd, ClientSession*);
    std::string base64(const char* in) noexcept;
    void log(openvpn_plugin_log_flags_t flags, const char *format, ...);
    void parseOptions(const char **argv);

    bool verify_certificate(bool preverified,
                            boost::asio::ssl::verify_context& ctx);
public:
    ArachnePlugin(const openvpn_plugin_args_open_in*);

    int userAuthPassword(const char *argv[], const char *envp[], ClientSession*);

    ClientSession *createClientSession();

    void log(openvpn_plugin_log_flags_t flags, long sessionId, const char *format, ...);
};

#endif
