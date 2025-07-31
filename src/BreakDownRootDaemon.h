#ifndef DAEMON_H
#define DAEMON_H

#include "ArachneLogger.h"

#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <ostream>

#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot include openvpn-plugin.h"
#endif

class ClientSession;

class BreakDownRootDaemon {
public:
    enum Command : uint8_t {
        PING,
        CLEANUP_POLICIES
    };

    BreakDownRootDaemon(plugin_vlog_t logFunc);
    void commandLoop(int readFd, int writeFd);
    static void execCommand(std::ostream &commandStream, std::istream &replyStream,
                            ClientSession *,
                            Command, const std::string& param = "");

private:
    enum Answer : uint8_t {
        SUCCESS,
        DEBUG,
        NOTE,
        WARNING,
        ERROR,
        EXCEPTION
    };

    static const char DELIM;

    ArachneLogger _logger;
    boost::iostreams::stream<boost::iostreams::file_descriptor_source> _reader;
    boost::iostreams::stream<boost::iostreams::file_descriptor_sink> _writer;

    void sendAnswer(Answer);
    void sendAnswer(Answer, const std::string &msg);
};

#endif
