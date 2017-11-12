#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cstdarg>

#include <openvpn-plugin.h>

#include "ArachnePlugin.h"

/*OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1(unsigned int *type_mask, const char *argv[], const char *envp[])
{
    printf("Loading arachne plugin\n");

    ArachnePlugin *context = new ArachnePlugin(argv);

    *type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_UP) |
        OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT) |
        OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_DISCONNECT) |
        OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_DOWN) |
        OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

    return (openvpn_plugin_handle_t) context;
}
*/

plugin_vlog_t log;

void my_log(openvpn_plugin_log_flags_t flags, const char *msg, ...)
{
    va_list argptr;
    va_start(argptr, msg);

    log(flags, "Arachne", msg, argptr);

    va_end(argptr);
}

OPENVPN_EXPORT int
openvpn_plugin_open_v3 (const int version,
    struct openvpn_plugin_args_open_in const *arguments,
    struct openvpn_plugin_args_open_return *retptr)
{
    ArachnePlugin *context = new ArachnePlugin(arguments);

    retptr->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
    retptr->handle = (openvpn_plugin_handle_t*) context;

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(const int version,
                       struct openvpn_plugin_args_func_in const *args,
                       struct openvpn_plugin_args_func_return *retptr)
{
    ArachnePlugin *plugin = reinterpret_cast<ArachnePlugin*>(args->handle);

    switch (args->type) {
        case OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
            return plugin->userAuthPassword(args->argv, args->envp);
        default:
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    ArachnePlugin *context = reinterpret_cast<ArachnePlugin*>(handle);

    delete context;
}

