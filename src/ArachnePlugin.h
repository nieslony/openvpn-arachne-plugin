#ifndef ARACHNE_PLUGIN_H
#define ARACHNE_PLUGIN_H

#include <string>

#include <openvpn-plugin.h>

#include <Url.h>

class ArachnePlugin {
private:
    plugin_vlog_t log_func;

    const char* getenv(const char *key, const char *envp[]);

    Url url;

    void chop(std::string&);

    void log(openvpn_plugin_log_flags_t flags, const char *format, ...);
    int http(const Url &url, const std::string& userPwd);
    std::string base64(const char* in) noexcept;

public:
    ArachnePlugin(const openvpn_plugin_args_open_in*);

    int userAuthPassword(const char *argv[], const char *envp[]);
};

#endif
