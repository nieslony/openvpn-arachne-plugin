#include "Firewall.h"

#include <sstream>

Firewall::Firewall()
{
    init();
}

Firewall::~Firewall()
{
    dbus_connection_close(conn);
}

void Firewall::init()
{
     DBusError err;
     dbus_error_init(&err);
     conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);

    if (dbus_error_is_set(&err)) {
        std::stringstream str;
        str << "DBUS Connection Error: " << err.message;
        dbus_error_free(&err);
        throw FirewallException(str.str());
    }
    if (NULL == conn) {
        throw FirewallException("Unable to get DBUS connection");
    }
}

