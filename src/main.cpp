#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cstdarg>

#include <openvpn-plugin.h>

#include "ArachnePlugin.h"
#include "ClientSession.h"

OPENVPN_EXPORT int
openvpn_plugin_open_v3 (const int version,
    struct openvpn_plugin_args_open_in const *arguments,
    struct openvpn_plugin_args_open_return *retptr)
{
    try {
        ArachnePlugin *context = new ArachnePlugin(arguments);

        retptr->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
        retptr->handle = (openvpn_plugin_handle_t*) context;
    }
    catch (const std::exception &ex) {
        //std::cout << "Caught exception: " << ex.what() << std::endl;

        va_list a;
        va_end(a);
        arguments->callbacks->plugin_vlog(PLOG_ERR, "Arachne", ex.what(), a);

        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(const int version,
                       struct openvpn_plugin_args_func_in const *args,
                       struct openvpn_plugin_args_func_return *retptr)
{
    ArachnePlugin *plugin = reinterpret_cast<ArachnePlugin*>(args->handle);
    ClientSession *session = reinterpret_cast<ClientSession*>(args->per_client_context);

    switch (args->type) {
        case OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
            return plugin->userAuthPassword(args->argv, args->envp, session);
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

OPENVPN_EXPORT void*
openvpn_plugin_client_constructor_v1(openvpn_plugin_handle_t handle)
{
    ArachnePlugin *plugin = reinterpret_cast<ArachnePlugin*>(handle);
    ClientSession *session = plugin->createClientSession();

    return session;
}

OPENVPN_EXPORT void
openvpn_plugin_client_destructor_v1(openvpn_plugin_handle_t handle,
                                    void *per_client_context)
{
    ClientSession *session = reinterpret_cast<ClientSession*>(per_client_context);

    delete session;
}
