#ifndef FIREWALL_H
#define FIREWALL_H

#include <string>
#include <stdexcept>

#include <dbus/dbus.h>

class FirewallException : public std::runtime_error {
public:
    FirewallException(const std::string &msg)
        : std::runtime_error(msg) {}
};

class Firewall {
public:
    Firewall();
    ~Firewall();

    void init();

    void createZone(const std::string &zoneName, const std::string &interface);
    void addRichRule(const std::string &zoneName, const std::string &richRule);
    void removeRichRule(const std::string &zoneName, const std::string &richRule);

private:
    DBusConnection* conn;
};

#endif
