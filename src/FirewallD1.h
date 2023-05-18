#ifndef FIREWALLD1_H
#define FIREWALLD1_H

#include <sdbus-c++/sdbus-c++.h>
#include "FirewallD1_Proxy.h"
#include "FirewallD1_Config_Proxy.h"

class FirewallD1 : public sdbus::ProxyInterfaces<org::fedoraproject::FirewallD1_proxy>
{
public:
    FirewallD1(std::unique_ptr<sdbus::IConnection> &connection)
        : ProxyInterfaces(*connection, "org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1")
    {
        registerProxy();
    }

    ~FirewallD1()
    {
        unregisterProxy();
    }

protected:
    void onReloaded() {}
    void onPanicModeEnabled() {}
    void onPanicModeDisabled() {}
    void onLogDeniedChanged(const std::string&) {}
    void onAutomaticHelpersChanged(const std::string&) {}
    void onDefaultZoneChanged(const std::string&) {}
};


class FirewallD1_Config : public sdbus::ProxyInterfaces<org::fedoraproject::FirewallD1::config_proxy>
{
public:
    FirewallD1_Config(std::unique_ptr<sdbus::IConnection> &connection)
        : ProxyInterfaces(*connection, "org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1/config")
    {
        registerProxy();
    }

    ~FirewallD1_Config()
    {
        unregisterProxy();
    }

protected:
    void onIPSetAdded(const std::string&) {}
    void onIcmpTypeAdded(const std::string&) {}
    void onServiceAdded(const std::string&) {}
    void onZoneAdded(const std::string&) {}
    void onPolicyAdded(const std::string&) {}
    void onHelperAdded(const std::string&) {}
};

#endif
