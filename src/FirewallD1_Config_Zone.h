#ifndef FIREWALLD1_CONFIG_ZONE_H
#define FIREWALLD1_CONFIG_ZONE_H

#include <dbus-c++/dbus.h>
#include "FirewallD1_Config_Zone_proxy.h"

class FirewallD1_Config_Zone : public org::fedoraproject::FirewallD1::config::zone_proxy,
    public DBus::IntrospectableProxy,
    public DBus::PropertiesProxy,
    public DBus::ObjectProxy
{
public:
    FirewallD1_Config_Zone(DBus::Connection &connection, const char *path, const char *name);
    FirewallD1_Config_Zone(DBus::Connection &connection, const ::DBus::Path &path, const char *name);

    virtual void Updated(const std::string& name) {}
    virtual void Removed(const std::string& name) {}
    virtual void Renamed(const std::string& name) {}
};

#endif
