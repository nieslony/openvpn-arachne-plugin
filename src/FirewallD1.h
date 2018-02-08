#ifndef FIREWALLD1_H
#define FIREWALLD1_H

#include <dbus-c++/dbus.h>
#include "FirewallD1_proxy.h"

class FirewallD1 : public org::fedoraproject::FirewallD1_proxy,
    public DBus::IntrospectableProxy,
    public DBus::PropertiesProxy,
    public DBus::ObjectProxy
{
public:
    FirewallD1(DBus::Connection &connection, const char *path, const char *name);

    virtual void Reloaded(){}
    virtual void PanicModeEnabled(){}
    virtual void PanicModeDisabled(){}
    virtual void LogDeniedChanged(const std::string& value){}
    virtual void AutomaticHelpersChanged(const std::string& value){}
    virtual void DefaultZoneChanged(const std::string& zone){}

};

#endif
