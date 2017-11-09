#include "ArachnePlugin.h"

#include <openvpn-plugin.h>

#include <iostream>
using namespace std;

ArachnePlugin::ArachnePlugin(const char *argv[]) 
{
}

int ArachnePlugin::up(const char *argv[], const char *envp[])
{
    clog << "Arachne: up" << endl;
    
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::down(const char *argv[], const char *envp[])
{
    clog << "Arachne: down" << endl;

    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

int ArachnePlugin::userAuthPassword(const char *argv[], const char *envp[])
{
    clog << "Arachne: user auth password" << endl;
    
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}
