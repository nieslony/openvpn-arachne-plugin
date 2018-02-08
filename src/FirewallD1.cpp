#include "FirewallD1.h"

#include <dbus-c++/dbus.h>

FirewallD1::FirewallD1(DBus::Connection &connection, const char *path, const char *name)
    : DBus::ObjectProxy(connection, path, name)
{
}

