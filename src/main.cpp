#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot include openvpn-plugin.h"
#endif

#include "ArachnePlugin.h"
#include "ClientSession.h"

#include <iostream>

OPENVPN_EXPORT int
openvpn_plugin_open_v3 (
    const int version,
    struct openvpn_plugin_args_open_in const *arguments,
    struct openvpn_plugin_args_open_return *retptr
) {
    try {
        ArachnePlugin *context = new ArachnePlugin(arguments);

        retptr->type_mask =
            (context->userPasswdAuthEnabled() ? OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) : 0) |
            OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT_V2) |
            OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_DISCONNECT) |
            OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_UP) |
            OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_DOWN)
        ;

        retptr->handle = (openvpn_plugin_handle_t*) context;
    }
    catch (const std::exception &ex) {
        va_list a;
        va_end(a);
        arguments->callbacks->plugin_vlog(PLOG_ERR, "Arachne", ex.what(), a);

        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    catch (...) {
        va_list a;
        va_end(a);
        arguments->callbacks->plugin_vlog(
            PLOG_ERR,
            "Arachne", "Something went wrong...",
            a
        );

        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    ArachnePlugin *context = reinterpret_cast<ArachnePlugin*>(handle);

    delete context;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v3(
    const int version,
    struct openvpn_plugin_args_func_in const *args,
    struct openvpn_plugin_args_func_return *retptr
) {
    ArachnePlugin *plugin = reinterpret_cast<ArachnePlugin*>(args->handle);
    ClientSession *session = reinterpret_cast<ClientSession*>(args->per_client_context);

    try {
        switch (args->type) {
            case OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY:
                plugin->userAuthPassword(args->envp, session);
            case OPENVPN_PLUGIN_UP:
                plugin->pluginUp(args->argv, args->envp, session);
            case OPENVPN_PLUGIN_DOWN:
                plugin->pluginDown(args->argv, args->envp, session);
            case OPENVPN_PLUGIN_CLIENT_CONNECT_V2:
                plugin->clientConnect(args->argv, args->envp, session);
            case OPENVPN_PLUGIN_CLIENT_DISCONNECT:
                plugin->clientDisconnect(args->argv, args->envp, session);
        }

        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }
    catch (const std::exception &ex) {
        session->logger().error() << ex.what() << std::flush;
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

OPENVPN_EXPORT void*
openvpn_plugin_client_constructor_v1(
    openvpn_plugin_handle_t handle
) {
    ArachnePlugin *plugin = reinterpret_cast<ArachnePlugin*>(handle);
    ClientSession *session = plugin->createClientSession();

    return session;
}

OPENVPN_EXPORT void
openvpn_plugin_client_destructor_v1(
    openvpn_plugin_handle_t handle,
    void *per_client_context
) {
    ClientSession *session = reinterpret_cast<ClientSession*>(per_client_context);

    delete session;
}
