#ifndef FIREWALLD1_H
#define FIREWALLD1_H

#include <sdbus-c++/sdbus-c++.h>
#include "FirewallD1_Proxy.h"
#include "FirewallD1_Config_Proxy.h"

class FirewallD1
    : public sdbus::ProxyInterfaces<org::fedoraproject::FirewallD1_proxy>
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

    static const int DEFAULT_TIMEOUT = 0;

protected:
    void onReloaded() {}
    void onPanicModeEnabled() {}
    void onPanicModeDisabled() {}
    void onLogDeniedChanged(const std::string&) {}
    void onAutomaticHelpersChanged(const std::string&) {}
    void onDefaultZoneChanged(const std::string&) {}
};


class FirewallD1_Config
    : public sdbus::ProxyInterfaces<org::fedoraproject::FirewallD1::config_proxy>
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

class FirewallD1_Zone
    : public sdbus::ProxyInterfaces<org::fedoraproject::FirewallD1::zone_proxy>
{
public:
    FirewallD1_Zone(std::unique_ptr<sdbus::IConnection> &connection)
        : ProxyInterfaces(*connection, "org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1")
    {
        registerProxy();
    }

    ~FirewallD1_Zone()
    {
        unregisterProxy();
    }

protected:
    void onZoneUpdated(const std::string&, const std::map<std::__cxx11::basic_string<char>, sdbus::Variant>&) {}
    void onInterfaceAdded(const std::string&, const std::string&) {}
    void onZoneChanged(const std::string&, const std::string&) {}
    void onZoneOfInterfaceChanged(const std::string&, const std::string&) {}
    void onInterfaceRemoved(const std::string&, const std::string&) {}
    void onSourceAdded(const std::string&, const std::string&) {}
    void onZoneOfSourceChanged(const std::string&, const std::string&) {}
    void onSourceRemoved(const std::string&, const std::string&) {}
    void onRichRuleAdded(const std::string&, const std::string&, const int32_t&) {}
    void onRichRuleRemoved(const std::string&, const std::string&) {}
    void onServiceAdded(const std::string&, const std::string&, const int32_t&) {}
    void onServiceRemoved(const std::string&, const std::string&) {}
    void onPortAdded(const std::string&, const std::string&, const std::string&, const int32_t&) {}
    void onPortRemoved(const std::string&, const std::string&, const std::string&) {}
    void onProtocolAdded(const std::string&, const std::string&, const int32_t&) {}
    void onProtocolRemoved(const std::string&, const std::string&) {}
    void onSourcePortAdded(const std::string&, const std::string&, const std::string&, const int32_t&) {}
    void onSourcePortRemoved(const std::string&, const std::string&, const std::string&) {}
    void onMasqueradeAdded(const std::string&, const int32_t&) {}
    void onMasqueradeRemoved(const std::string&) {}
    void onForwardPortAdded(const std::string&, const std::string&, const std::string&, const std::string&, const std::string&, const int32_t&) {}
    void onForwardPortRemoved(const std::string&, const std::string&, const std::string&, const std::string&, const std::string&) {}
    void onIcmpBlockAdded(const std::string&, const std::string&, const int32_t&) {}
    void onIcmpBlockRemoved(const std::string&, const std::string&) {}
    void onIcmpBlockInversionAdded(const std::string&) {}
    void onIcmpBlockInversionRemoved(const std::string&) {}
};

class FirewallD1_Policy
    : public sdbus::ProxyInterfaces<org::fedoraproject::FirewallD1::policy_proxy>
{
public:
    FirewallD1_Policy(std::unique_ptr<sdbus::IConnection> &connection)
        : ProxyInterfaces(*connection, "org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1")
    {
        registerProxy();
    }

    ~FirewallD1_Policy()
    {
        unregisterProxy();
    }

protected:
    void onPolicyUpdated(const std::string&, const std::map<std::__cxx11::basic_string<char>, sdbus::Variant>&) {}
};

#endif
