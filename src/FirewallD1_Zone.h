#ifndef FIREWALLD1_ZONE_H
#define FIREWALLD1_ZONE_H

#include <dbus-c++/dbus.h>
#include "FirewallD1_proxy.h"

class FirewallD1_Zone : public org::fedoraproject::FirewallD1::zone_proxy,
    public DBus::IntrospectableProxy,
    public DBus::PropertiesProxy,
    public DBus::ObjectProxy
{
public:
    FirewallD1_Zone(DBus::Connection &connection, const char *path, const char *name);
    FirewallD1_Zone(DBus::Connection &connection, const ::DBus::Path &path, const char *name);

    virtual void InterfaceAdded(const std::string& zone, const std::string& interface) {}
    virtual void ZoneChanged(const std::string& zone, const std::string& interface) {}
    virtual void ZoneOfInterfaceChanged(const std::string& zone, const std::string& interface) {}
    virtual void InterfaceRemoved(const std::string& zone, const std::string& interface) {}
    virtual void SourceAdded(const std::string& zone, const std::string& source) {}
    virtual void ZoneOfSourceChanged(const std::string& zone, const std::string& source) {}
    virtual void SourceRemoved(const std::string& zone, const std::string& source) {}
    virtual void RichRuleAdded(const std::string& zone, const std::string& rule, const int32_t& timeout) {}
    virtual void RichRuleRemoved(const std::string& zone, const std::string& rule) {}
    virtual void ServiceAdded(const std::string& zone, const std::string& service, const int32_t& timeout) {}
    virtual void ServiceRemoved(const std::string& zone, const std::string& service) {}
    virtual void PortAdded(const std::string& zone, const std::string& port, const std::string& protocol, const int32_t& timeout) {}
    virtual void PortRemoved(const std::string& zone, const std::string& port, const std::string& protocol) {}
    virtual void ProtocolAdded(const std::string& zone, const std::string& protocol, const int32_t& timeout) {}
    virtual void ProtocolRemoved(const std::string& zone, const std::string& protocol) {}
    virtual void SourcePortAdded(const std::string& zone, const std::string& port, const std::string& protocol, const int32_t& timeout) {}
    virtual void SourcePortRemoved(const std::string& zone, const std::string& port, const std::string& protocol) {}
    virtual void MasqueradeAdded(const std::string& zone, const int32_t& timeout) {}
    virtual void MasqueradeRemoved(const std::string& zone) {}
    virtual void ForwardPortAdded(const std::string& zone, const std::string& port, const std::string& protocol, const std::string&
toport, const std::string& toaddr, const int32_t& timeout) {}
    virtual void ForwardPortRemoved(const std::string& zone, const std::string& port, const std::string& protocol, const std::string
& toport, const std::string& toaddr) {}
    virtual void IcmpBlockAdded(const std::string& zone, const std::string& icmp, const int32_t& timeout) {}
    virtual void IcmpBlockRemoved(const std::string& zone, const std::string& icmp) {}
    virtual void IcmpBlockInversionAdded(const std::string& zone) {}
    virtual void IcmpBlockInversionRemoved(const std::string& zone) {}
};

#endif

