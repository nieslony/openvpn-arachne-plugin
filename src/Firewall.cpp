#include "Firewall.h"

#include <iostream>
#include <vector>

#include <dbus/dbus.h>

#include <boost/algorithm/string.hpp>

#define FIREWALL_INTERFACE_NAME "org.fedoraproject.FirewallD1"

FirewallRuntimeException::FirewallRuntimeException(DBusError *error)
    : FirewallException(error->message)
{
    std::vector<std::string> tokens;
    boost::split(tokens, error->message, boost::is_any_of(":"));
    std::string code(tokens.at(0));

    if (code == "ALREADY_ENABLED")
        _type = ALREADY_ENABLED;
    else if (code == "INVALID_COMMAND")
        _type = INVALID_COMMAND;
    else if (code == "INVALID_NAME")
        _type = INVALID_NAME;
    else if (code == "INVALID_RULE")
        _type = INVALID_RULE;
    else if (code == "INVALID_TYPE")
        _type = INVALID_TYPE;
    else if (code == "INVALID_ZONE")
        _type = INVALID_ZONE;
    else if (code == "NAME_CONFLICT")
        _type = NAME_CONFLICT;
    else if (code == "NOT_ENABLED")
        _type = NAME_CONFLICT;
    else if (code == "ZONE_ALREADY_EXISTS")
        _type = ZONE_ALREADY_EXISTS;
    else
        _type = Unknown;
}

Firewall::Firewall()
{

    DBusError error;

    dbus_error_init(&error);
    _connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

    checkError(&error);
}

Firewall::~Firewall()
{
}

void Firewall::checkError(DBusError *error)
{
    if (dbus_error_is_set(error)) {
       const std::string error_name(error->name);
       if (error_name == "org.fedoraproject.FirewallD1.Exception")
            throw FirewallRuntimeException(error);
        else
            throw FirewallException(error->message);
    }
}

void Firewall::reload()
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;

    dbus_error_init(&error);

    msgQuery = dbus_message_new_method_call(FIREWALL_INTERFACE_NAME,
        "/org/fedoraproject/FirewallD1",
        "org.fedoraproject.FirewallD1",
        "reload");
    if (msgQuery == NULL) {
        throw FirewallException("Cannot find function");
    }
    msgReply = dbus_connection_send_with_reply_and_block(_connection, msgQuery, 1000, &error);
    dbus_message_unref(msgQuery);
    checkError(&error);
    dbus_message_unref(msgReply);
}

void Firewall::addRichRule(const std::string &zone, const std::string &rule)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;

    const char* zoneStr = zone.c_str();
    const char* ruleStr = rule.c_str();
    const uint32_t timeOut = 0;

    dbus_error_init(&error);

    msgQuery = dbus_message_new_method_call(FIREWALL_INTERFACE_NAME,
        "/org/fedoraproject/FirewallD1",
        "org.fedoraproject.FirewallD1.zone",
        "addRichRule");
    if (msgQuery == NULL) {
        throw FirewallException("Cannot find function");
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_STRING, &zoneStr,
                             DBUS_TYPE_STRING, &ruleStr,
                             DBUS_TYPE_INT32, &timeOut,
                             DBUS_TYPE_INVALID);


    msgReply = dbus_connection_send_with_reply_and_block(_connection, msgQuery, 1000, &error);
    dbus_message_unref(msgQuery);
    checkError(&error);
    dbus_message_unref(msgReply);
}

void Firewall::removeRichRule(const std::string &zone, const std::string &rule)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;

    const char* zoneStr = zone.c_str();
    const char* ruleStr = rule.c_str();
    const uint32_t timeOut = 0;

    dbus_error_init(&error);

    msgQuery = dbus_message_new_method_call(FIREWALL_INTERFACE_NAME,
        "/org/fedoraproject/FirewallD1",
        "org.fedoraproject.FirewallD1.zone",
        "removeRichRule");
    if (msgQuery == NULL) {
        throw FirewallException("Cannot find function");
    }

    dbus_message_append_args(msgQuery,
                             DBUS_TYPE_STRING, &zoneStr,
                             DBUS_TYPE_STRING, &ruleStr,
                             DBUS_TYPE_INVALID);


    msgReply = dbus_connection_send_with_reply_and_block(_connection, msgQuery, 1000, &error);
    dbus_message_unref(msgQuery);
    checkError(&error);
    dbus_message_unref(msgReply);
}

void Firewall::addZone(const std::string &zoneName, const std::string &interfaceName)
{
    DBusMessage *msgQuery = NULL;
    DBusMessage *msgReply = NULL;
    DBusError error;

    const char* zoneNameStr = zoneName.c_str();
    const char* version = "";
    const char* name = zoneName.c_str();
    const char* description = "Arachne user VPN";
    int unused = 0;
    const char* target = "DROP";
    const char* services[] = { NULL };
    const void* ports = NULL;
    const char* icmpBlocks[] = { "" };
    int masquerade = 0;
    const void* forwardPorts = NULL;
    const char* interfaces[] = { interfaceName.c_str() };
    const char* sourceAddresses[] = { "" };
    const char* richRules[] = { "" };
    const char* protocols[] = { "" };
    const void* sourcePorts = NULL;

    dbus_error_init(&error);

    msgQuery = dbus_message_new_method_call(FIREWALL_INTERFACE_NAME,
        "/org/fedoraproject/FirewallD1/config",
        "org.fedoraproject.FirewallD1.config",
        "addZone");

    DBusMessageIter args, settings;
    dbus_message_iter_init_append(msgQuery, &args);
    dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &zoneNameStr);

    dbus_message_iter_open_container(&args, DBUS_TYPE_STRUCT, NULL, &settings);
    dbus_message_iter_append_basic(&settings, DBUS_TYPE_STRING, &version);
    dbus_message_iter_append_basic(&settings, DBUS_TYPE_STRING, &name);
    dbus_message_iter_append_basic(&settings, DBUS_TYPE_STRING, &description);
    dbus_message_iter_append_basic(&settings, DBUS_TYPE_BOOLEAN, &unused);
    dbus_message_iter_append_basic(&settings, DBUS_TYPE_STRING, &target);

    DBusMessageIter servicesArr;
    dbus_message_iter_open_container(&settings, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &servicesArr);
    dbus_message_iter_close_container(&settings, &servicesArr);

    DBusMessageIter portsArr;
    dbus_message_iter_open_container(&settings, DBUS_TYPE_ARRAY, "ss", &portsArr);
    dbus_message_iter_close_container(&settings, &portsArr);

    DBusMessageIter icmpBlocksArr;
    dbus_message_iter_open_container(&settings, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &icmpBlocksArr);
    dbus_message_iter_close_container(&settings, &icmpBlocksArr);

    dbus_message_iter_append_basic(&settings, DBUS_TYPE_BOOLEAN, &masquerade);

    DBusMessageIter forwardPortsArr;
    dbus_message_iter_open_container(&settings, DBUS_TYPE_ARRAY, "ssss", &forwardPortsArr);
    dbus_message_iter_close_container(&settings, &forwardPortsArr);

    DBusMessageIter interfacesArr;
    dbus_message_iter_open_container(&settings, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &interfacesArr);
    dbus_message_iter_append_basic(&interfacesArr, DBUS_TYPE_STRING, interfaces);
    dbus_message_iter_close_container(&settings, &interfacesArr);

    DBusMessageIter sourceAddressesArr;
    dbus_message_iter_open_container(&settings, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &sourceAddressesArr);
    dbus_message_iter_close_container(&settings, &sourceAddressesArr);

    DBusMessageIter richRulesArr;
    dbus_message_iter_open_container(&settings, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &richRulesArr);
    dbus_message_iter_close_container(&settings, &richRulesArr);

    DBusMessageIter protocolsArr;
    dbus_message_iter_open_container(&settings, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &protocolsArr);
    dbus_message_iter_close_container(&settings, &protocolsArr);

    DBusMessageIter sourcePortsArr;
    dbus_message_iter_open_container(&settings, DBUS_TYPE_ARRAY, "ss", &sourcePortsArr);
    dbus_message_iter_close_container(&settings, &sourcePortsArr);

    dbus_message_iter_append_basic(&settings, DBUS_TYPE_BOOLEAN, &unused);
    dbus_message_iter_close_container(&args, &settings);

    msgReply = dbus_connection_send_with_reply_and_block(_connection, msgQuery, 1000, &error);
    dbus_message_unref(msgQuery);
    checkError(&error);
    dbus_message_unref(msgReply);
}
