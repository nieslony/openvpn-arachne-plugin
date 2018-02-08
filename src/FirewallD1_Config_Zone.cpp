#include "FirewallD1_Config_Zone.h"

FirewallD1_Config_Zone::FirewallD1_Config_Zone(DBus::Connection &connection, const char *path, const char *name)
    : DBus::ObjectProxy(connection, path, name)
{}

FirewallD1_Config_Zone::FirewallD1_Config_Zone(DBus::Connection &connection, const ::DBus::Path &path, const char *name)
    : DBus::ObjectProxy(connection, path, name)
{}
