#include "FirewallD1_Config.h"

FirewallD1_Config::FirewallD1_Config(DBus::Connection &connection, const char *path, const char *name)
    : DBus::ObjectProxy(connection, path, name)
{
}

