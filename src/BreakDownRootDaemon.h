#ifndef DAEMON_H
#define DAEMON_H

#include "ArachneLogger.h"

#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/describe/enum.hpp>

#include <ostream>
#include <map>

#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot include openvpn-plugin.h"
#endif

class ClientSession;
class ArachnePlugin;
class ArachneLogger;

namespace boost { namespace json { class value; }}

BOOST_DEFINE_FIXED_ENUM_CLASS(
    BreakDownRootCommand,
    uint8_t,
    PING,
    CLEANUP_POLICIES,
    APPLY_PERMANENT_RULES_TO_RUNTIME,
    SET_ROUTING_STATUS,
    UPDATE_FIREWALL_RULES,
    FORCE_IPSET_CLEANUP,
    EXIT
)

BOOST_DEFINE_FIXED_ENUM_CLASS(
    BreakDownRootAnswer,
    uint8_t,
    SUCCESS,
    DEBUG,
    NOTE,
    WARNING,
    ERROR,
    EXCEPTION
)

class BreakDownRootDaemon {
public:

    BreakDownRootDaemon(plugin_vlog_t logFunc, const ArachnePlugin&);
    void commandLoop(int readFd, int writeFd);
    static void execCommand(std::ostream &commandStream, std::istream &replyStream,
                            ArachneLogger&,
                            BreakDownRootCommand, const std::string& param = "");

private:
    static const char DELIM;

    const ArachnePlugin &_plugin;
    ArachneLogger _logger;
    boost::iostreams::stream<boost::iostreams::file_descriptor_source> _reader;
    boost::iostreams::stream<boost::iostreams::file_descriptor_sink> _writer;

    void sendAnswer(BreakDownRootAnswer);
    std::ostream &answer(BreakDownRootAnswer);
    void sendAnswer(BreakDownRootAnswer, const std::string &msg);
    static std::ostream &flushAnswer(std::ostream &str) { return str << DELIM << std::flush; }

    void createRichRules(
        const boost::json::value &json,
        const std::string icmpRules,
        std::vector<std::string> &richRules,
        std::vector<std::string> &localRichRules,
        std::map<std::string, std::vector<std::string>> &ipSets
    );

    void cleanupPolicies();
    void applyPermentRulesToRuntime();
    void setRoutingStatus(const std::string &forward);
    void updateFirewallRules(const std::string &rules);
    void forceIpSetCleanup(const std::string &vpnIp_ipSetIds);
};

#endif
