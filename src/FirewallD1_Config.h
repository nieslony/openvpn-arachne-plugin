#ifndef FIREWALLD1_CONFIG_H
#define FIREWALLD1_CONFIG_H

#include <dbus-c++/dbus.h>
#include "FirewallD1_Config_proxy.h"

class FirewallD1_Config : public org::fedoraproject::FirewallD1::config_proxy,
    public DBus::IntrospectableProxy,
    public DBus::PropertiesProxy,
    public DBus::ObjectProxy
{
public:
    FirewallD1_Config(DBus::Connection &connection, const char *path, const char *name);

    virtual void IPSetAdded(const std::string& ipset) {}
    virtual void IcmpTypeAdded(const std::string& icmptype) {}
    virtual void ServiceAdded(const std::string& service) {}
    virtual void ZoneAdded(const std::string& zone) {}
    virtual void HelperAdded(const std::string& helper) {}
};

#endif


