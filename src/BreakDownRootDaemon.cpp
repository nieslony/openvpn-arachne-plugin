#include "BreakDownRootDaemon.h"
#include "ArachnePlugin.h"
#include "ClientSession.h"

#include <cstdint>
#include <ostream>

#include <cstdio>

const char BreakDownRootDaemon::DELIM = '\x09';

BreakDownRootDaemon::BreakDownRootDaemon(plugin_vlog_t logFunc) :
    _logger(logFunc, "BreakDownRootCommands")
{}

void BreakDownRootDaemon::commandLoop(int fdRead, int fdWrite)
{
    _logger.note() << "Starting event loop" << std::flush;

    _reader.open(
        boost::iostreams::file_descriptor_source(fdRead, boost::iostreams::never_close_handle)
    );
    _writer.open(
        boost::iostreams::file_descriptor_sink(fdWrite, boost::iostreams::never_close_handle)
    );

    while (_reader) {
        uint8_t command;
        std::string param;

        _reader >> command;
        std::getline(_reader, param, DELIM);

        _logger.debug() << "Got command: " << std::to_string(command) << "(" << param << ")" << std::flush;
        switch (static_cast<Command>(command)) {
            case PING:
                _logger.debug() << "Ping" << std::flush;
                sendAnswer(DEBUG, "Pong: " + param);
                sendAnswer(SUCCESS);
                break;
            case CLEANUP_POLICIES:
                _logger.debug() << "Cleanup Policies" << std::flush;
                break;
            default:
                _logger.warning() << "Invalid command: " << command << std::flush;
                sendAnswer(WARNING, "Invalid command");
                sendAnswer(SUCCESS);
        }
    }
    _logger.warning() << "Event loop unexped left" << std::flush;
}

void BreakDownRootDaemon::execCommand(std::ostream &commandStream, std::istream &replyStream,
                                      ClientSession *session,
                                      Command command, const std::string &param)
{
    session->logger().debug() << "Sending " << command << std::flush;
    commandStream << static_cast<uint8_t>(command)
    //commandStream << "PING" << DELIM
        << param << DELIM
        << std::flush;
    while (true) {
        uint8_t reply;
        std::string replyStr;

        replyStream >> reply;
        session->logger().debug() << "Got reply: " << std::to_string(reply) << std::flush;
        switch (static_cast<Answer>(reply)) {
            case SUCCESS:
                session->logger().debug() << "Success" << std::flush;
                return;
            case DEBUG:
                std::getline(replyStream, replyStr, DELIM);
                session->logger().debug() << replyStr << std::flush;
                break;
            case NOTE:
                std::getline(replyStream, replyStr, DELIM);
                session->logger().note() << replyStr << std::flush;
                break;
            case WARNING:
                std::getline(replyStream, replyStr, DELIM);
                session->logger().warning() << replyStr << std::flush;
                break;
            case ERROR:
                std::getline(replyStream, replyStr, DELIM);
                session->logger().error() << replyStr << std::flush;
                break;
            case EXCEPTION:
                std::getline(replyStream, replyStr, DELIM);
                throw PluginException(replyStr);
            default:
                throw PluginException("Invalid command");
        }
    }
    throw PluginException("Command stream died");
}

void BreakDownRootDaemon::sendAnswer(Answer answer)
{
    _writer
        << static_cast<uint8_t>(answer) << answer
        << std::flush;
}
void BreakDownRootDaemon::sendAnswer(Answer answer, const std::string &msg)
{
    _writer
        << static_cast<uint8_t>(answer) << answer
        << msg << DELIM
        << std::flush;
}
