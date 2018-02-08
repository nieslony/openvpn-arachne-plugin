#ifndef FIRAWALL_H
#define FIREWALL_H

#include <dbus-c++-1/dbus-c++/dbus.h>

class FirewallD1;
class FirewallD1_Config;

class Firewall {
public:
    Firewall();
    ~Firewall();

    void init();

    void createZone(const std::string &zoneName, const std::string &interface);

    static const std::string FIREWALLD1_EXCEPTION;
    static const std::string FIREWALLD1_EX_INVALID_ZONE;
    static const std::string FIREWALLD1_EX_NAME_CONFLICT;

    static std::string exceptionType(const DBus::Error &ex,
                              std::string &type, std::string &param);

private:
    FirewallD1 *firewalld1 = NULL;
    FirewallD1_Config *fwConfig = NULL;
};

#endif
