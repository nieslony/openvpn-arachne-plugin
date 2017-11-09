#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openvpn-plugin.h>

#include "ArachnePlugin.h"

struct plugin_context {
    const char *username;
    const char *password;
};

static const char *
get_env(const char *name, const char *envp[])
{
    if (envp)
    {
        int i;
        const int namelen = strlen(name);
        for (i = 0; envp[i]; ++i)
        {
            if (!strncmp(envp[i], name, namelen))
            {
                const char *cp = envp[i] + namelen;
                if (*cp == '=')
                {
                    return cp + 1;
                }
            }
        }
    }
    return NULL;
}

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1(unsigned int *type_mask, const char *argv[], const char *envp[])
{
    printf("Loading arachne plugin\n");
    
    ArachnePlugin *context = new ArachnePlugin(argv);

    *type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_UP) |
        OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_DOWN) |
        OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

    return (openvpn_plugin_handle_t) context;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v1(openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
    ArachnePlugin *plugin = reinterpret_cast<ArachnePlugin*>(handle);    
    
    switch (type) {
        case OPENVPN_PLUGIN_UP:
            return plugin->up(argv, envp);
            break;
        case OPENVPN_PLUGIN_DOWN:
            return plugin->down(argv, envp);
            break;
        default:
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct plugin_context *context = (struct plugin_context *) handle;
    free(context);
}

