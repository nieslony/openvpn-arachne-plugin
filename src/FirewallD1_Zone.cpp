#include "FirewallD1_Zone.h"

FirewallD1_Zone::FirewallD1_Zone(DBus::Connection &connection, const char *path, const char *name)
    : DBus::ObjectProxy(connection, path, name)
{}

FirewallD1_Zone::FirewallD1_Zone(DBus::Connection &connection, const ::DBus::Path &path, const char *name)
    : DBus::ObjectProxy(connection, path, name)
{}
