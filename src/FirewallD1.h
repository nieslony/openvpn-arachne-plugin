#ifndef FIREWALLD1_H
#define FIREWALLD1_H

#include <sdbus-c++/Types.h>
#include <sdbus-c++/sdbus-c++.h>

#ifdef SDBUS_CPP_1
#include "firewalld-proxy-sdbus-1/FirewallD1_Proxy.h"
#include "firewalld-proxy-sdbus-1/FirewallD1_Config_Proxy.h"
#include "firewalld-proxy-sdbus-1/FirewallD1_Config_IpSet_Proxy.h"
#include "firewalld-proxy-sdbus-1/FirewallD1_Config_Policy_Proxy.h"
#elif defined SDBUS_CPP_2
#include "firewalld-proxy-sdbus-2/FirewallD1_Proxy.h"
#include "firewalld-proxy-sdbus-2/FirewallD1_Config_Proxy.h"
#include "firewalld-proxy-sdbus-2/FirewallD1_Config_IpSet_Proxy.h"
#include "firewalld-proxy-sdbus-2/FirewallD1_Config_Policy_Proxy.h"
#endif

class FirewallD1
    : public sdbus::ProxyInterfaces<org::fedoraproject::FirewallD1_proxy>
{
public:
    FirewallD1(std::unique_ptr<sdbus::IConnection> &connection)
#if defined SDBUS_CPP_1
        : ProxyInterfaces(*connection, "org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1")
#elif defined SDBUS_CPP_2
        : ProxyInterfaces(*connection, sdbus::ServiceName("org.fedoraproject.FirewallD1"), sdbus::ObjectPath("/org/fedoraproject/FirewallD1"))
#endif
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
#if defined SDBUS_CPP_1
        : ProxyInterfaces(*connection, "org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1/config")
#elif defined SDBUS_CPP_2
        : ProxyInterfaces(*connection, sdbus::ServiceName("org.fedoraproject.FirewallD1"), sdbus::ObjectPath("/org/fedoraproject/FirewallD1/config"))
#endif
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

class FirewallD1_IpSet
    : public sdbus::ProxyInterfaces<org::fedoraproject::FirewallD1::ipset_proxy>
{
public:
    FirewallD1_IpSet(std::unique_ptr<sdbus::IConnection> &connection)
#if defined SDBUS_CPP_1
    : ProxyInterfaces(*connection, "org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1")
#elif defined SDBUS_CPP_2
    : ProxyInterfaces(*connection, sdbus::ServiceName("org.fedoraproject.FirewallD1"), sdbus::ObjectPath("/org/fedoraproject/FirewallD1"))
#endif
    {
        registerProxy();
    }

    ~FirewallD1_IpSet()
    {
        unregisterProxy();
    }

protected:
    virtual void onEntryAdded(const std::string& ipset, const std::string& entry) {}
    virtual void onEntryRemoved(const std::string& ipset, const std::string& entry)  {}
};

class FirewallD1_Zone
    : public sdbus::ProxyInterfaces<org::fedoraproject::FirewallD1::zone_proxy>
{
public:
    FirewallD1_Zone(std::unique_ptr<sdbus::IConnection> &connection)
#if defined SDBUS_CPP_1
        : ProxyInterfaces(*connection, "org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1")
#elif defined SDBUS_CPP_2
        : ProxyInterfaces(*connection, sdbus::ServiceName("org.fedoraproject.FirewallD1"), sdbus::ObjectPath("/org/fedoraproject/FirewallD1"))
#endif
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
#if defined SDBUS_CPP_1
        : ProxyInterfaces(*connection, "org.fedoraproject.FirewallD1", "/org/fedoraproject/FirewallD1")
#elif defined SDBUS_CPP_2
        : ProxyInterfaces(*connection, sdbus::ServiceName("org.fedoraproject.FirewallD1"), sdbus::ObjectPath("/org/fedoraproject/FirewallD1"))
#endif
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

class FirewallD1_Config_Policy
    : public sdbus::ProxyInterfaces<org::fedoraproject::FirewallD1::config::policy_proxy>
{
public:
    FirewallD1_Config_Policy(std::unique_ptr<sdbus::IConnection> &connection, const std::string &objPath)
#if defined SDBUS_CPP_1
    : ProxyInterfaces(*connection, "org.fedoraproject.FirewallD1", objPath)
#elif defined SDBUS_CPP_2
    : ProxyInterfaces(*connection, sdbus::ServiceName("org.fedoraproject.FirewallD1"), sdbus::ObjectPath(objPath))
#endif
    {
        registerProxy();
    }

protected:
    virtual void onUpdated(const std::string& name) {};
    virtual void onRemoved(const std::string& name) {};
    virtual void onRenamed(const std::string& name) {};
};

class FirewallD1_Config_IpSet
: public sdbus::ProxyInterfaces<org::fedoraproject::FirewallD1::config::ipset_proxy>
{
public:
    FirewallD1_Config_IpSet(std::unique_ptr<sdbus::IConnection> &connection, const std::string &objPath)
#if defined SDBUS_CPP_1
    : ProxyInterfaces(*connection, "org.fedoraproject.FirewallD1", objPath)
#elif defined SDBUS_CPP_2
    : ProxyInterfaces(*connection, sdbus::ServiceName("org.fedoraproject.FirewallD1"), sdbus::ObjectPath(objPath))
#endif
    {
        registerProxy();
    }

protected:
    virtual void onUpdated(const std::string& name) {}
    virtual void onRemoved(const std::string& name) {}
    virtual void onRenamed(const std::string& name) {}
};

#endif
