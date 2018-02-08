#include "Firewall.h"
#include "FirewallD1.h"
#include "FirewallD1_Config.h"
#include "FirewallD1_Config_Zone.h"
#include "FirewallD1_Zone.h"

#include <dbus-c++-1/dbus-c++/dbus.h>
#include <dbus-c++-1/dbus-c++/dispatcher.h>
#include <dbus-c++-1/dbus-c++/object.h>
#include <dbus-c++-1/dbus-c++/connection.h>

DBus::BusDispatcher dispatcher;

const std::string Firewall::FIREWALLD1_EXCEPTION("org.fedoraproject.FirewallD1.Exception");
const std::string Firewall::FIREWALLD1_EX_INVALID_ZONE("INVALID_ZONE");
const std::string Firewall::FIREWALLD1_EX_NAME_CONFLICT("NAME_CONFLICT");

Firewall::Firewall()
{
}

Firewall::~Firewall()
{
    delete fwConfig;
    delete firewalld1;
}

std::string Firewall::exceptionType(const DBus::Error &ex,
    std::string &type,
    std::string &param
) {
    if (ex.name() == FIREWALLD1_EXCEPTION) {
        const std::string what(ex.what());
        size_t pos = what.find(":");
        if (pos != what.npos) {
            type = what.substr(0, pos);
            pos++;
            while (pos != what.npos && what[pos] == ' ')
                pos++;
            param = what.substr(pos);
        }
        else {
            type = "Unparsable error";
            param = what;
        }
    }

    return "";
}

typedef ::DBus::Struct<
            std::string,
            std::string,
            std::string,
            bool,
            std::string,
            std::vector< std::string >,
            std::vector<
                ::DBus::Struct< std::string, std::string >
            >,
            std::vector< std::string >,
            bool,
            std::vector<
                ::DBus::Struct< std::string, std::string, std::string, std::string >
            >,
            std::vector< std::string >,
            std::vector< std::string >,
            std::vector< std::string >,
            std::vector< std::string >,
            std::vector<
                ::DBus::Struct<std::string, std::string>
            >,
            bool
        > ZoneSettings;

void debugZoneSettings(ZoneSettings &zoneSettings)
{
    int pos = 1;
    std::cerr << pos++ << ": " << zoneSettings._1 << std::endl;
    std::cerr << pos++ << ": " << zoneSettings._2 << std::endl;
    std::cerr << pos++ << ": " << zoneSettings._3 << std::endl;
    std::cerr << pos++ << ": " << zoneSettings._4 << std::endl;
    std::cerr << pos++ << ": " << zoneSettings._5 << std::endl;

    std::cerr << pos++ << ": ";
    for (auto &i: zoneSettings._6)
        std::cerr << i << " | ";
    std::cerr << std::endl;

    std::cerr << pos++ << ": ";
    for (auto &i: zoneSettings._7)
        std::cerr << "(" << i._1  << "," << i._2 << ") ";
    std::cerr << std::endl;

    std::cerr << pos++ << ": ";
    for (auto &i: zoneSettings._8)
        std::cerr << i << " ";
    std::cerr << std::endl;

    std::cerr << pos++ << ": " << zoneSettings._9 << std::endl;

    std::cerr << pos++ << ": ";
    for (auto &i: zoneSettings._10)
        std::cerr << "(" << i._1 << "," << ") ";
    std::cerr << std::endl;

    std::cerr << pos++ << ": ";
    for (auto &i: zoneSettings._11)
        std::cerr << i << " ";
    std::cerr << std::endl;

    std::cerr << pos++ << ": ";
    for (auto &i: zoneSettings._12)
        std::cerr << i << " ";
    std::cerr << std::endl;

    std::cerr << pos++ << ": ";
    for (auto &i: zoneSettings._13)
        std::cerr << i << " ";
    std::cerr << std::endl;

    std::cerr << pos++ << ": ";
    for (auto &i: zoneSettings._14)
        std::cerr << i << " ";
    std::cerr << std::endl;

    std::cerr << pos++ << ": ";
    for (auto &i: zoneSettings._15)
        std::cerr << "(" << i._1 << "," << ") ";
    std::cerr << std::endl;

    std::cerr << pos++ << ": " << zoneSettings._16 << std::endl;
}

void Firewall::createZone(const std::string &zoneName, const std::string &interface)
{
    ZoneSettings zoneSettings;
    // version
    zoneSettings._2 = zoneName;
    zoneSettings._3 = "Arachne user VPN"; // description
    zoneSettings._4 = false;
    zoneSettings._5 = "ACCEPT"; // target
    // services
    // ports
    // icmp-blocks
    zoneSettings._9 = false; // masquerade
    // forward-ports
    //
    zoneSettings._11 = std::vector<std::string>(1, {"tun0"});
    // rich rules
    // protocols
    // source-ports
    zoneSettings._16 = 24;
    //debugZoneSettings(zoneSettings);
    fwConfig->addZone(zoneName, zoneSettings);
    firewalld1->reload();
}

void Firewall::init()
{
    DBus::default_dispatcher = &dispatcher;
    DBus::Connection conn = DBus::Connection::SystemBus();

    firewalld1 = new FirewallD1(conn,
                          "/org/fedoraproject/FirewallD1",
                          "org.fedoraproject.FirewallD1"
                           );

    fwConfig = new FirewallD1_Config(conn,
                          "/org/fedoraproject/FirewallD1/config",
                          "org.fedoraproject.FirewallD1"
                           );
    // firewalld1.authorizeAll();
}
