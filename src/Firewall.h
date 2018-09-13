#ifndef FIREWALL_H
#define FIREWALL_H

#include <dbus-c++-1/dbus-c++/dbus.h>

class FirewallD1;
class FirewallD1_Config;
class FirewallD1_Zone;

class Firewall {
public:
    Firewall();
    ~Firewall();

    void init();

    void createZone(const std::string &zoneName, const std::string &interface);
    void addRichRule(const std::string &zoneName, const std::string &richRule);
    void removeRichRule(const std::string &zoneName, const std::string &richRule);

    static const std::string FIREWALLD1_EXCEPTION;
    static const std::string FIREWALLD1_EX_INVALID_ZONE;
    static const std::string FIREWALLD1_EX_NAME_CONFLICT;

    static std::string exceptionType(const DBus::Error &ex,
                              std::string &type, std::string &param);

private:
    FirewallD1 *firewalld1 = NULL;
    FirewallD1_Config *fwConfig = NULL;
    FirewallD1_Zone *fwZone = NULL;
};

#endif
