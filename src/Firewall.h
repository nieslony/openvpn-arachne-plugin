#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdexcept>

struct DBusConnection;
struct DBusError;

class FirewallException : public std::runtime_error {
public:

    FirewallException(const std::string& msg)
        : runtime_error(msg)
    {}
};

class FirewallRuntimeException : public FirewallException {
public:
    enum Type {
        ALREADY_ENABLED,
        INVALID_COMMAND,
        INVALID_NAME,
        INVALID_RULE,
        INVALID_TYPE,
        INVALID_ZONE,
        NAME_CONFLICT,
        NOT_ENABLED,
        ZONE_ALREADY_EXISTS,
        Unknown = -1
    };

    FirewallRuntimeException(DBusError *error);

    Type type() { return _type; }

private:
    Type _type;
};

class Firewall {
public:
    Firewall();
    ~Firewall();

    void addRichRule(const std::string &zone, const std::string &rule);
    void removeRichRule(const std::string &zone, const std::string &rule);
    void addZone(const std::string &zoneName, const std::string &interfaceName);
    void reload();

private:
    DBusConnection *_connection = NULL;
    void checkError(DBusError *error);
};

#endif
