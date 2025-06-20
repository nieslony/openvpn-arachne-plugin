#include "ArachneLogger.h"

#include <openvpn-plugin.h>
#include <sstream>

ArachneLogBuf::ArachneLogBuf(plugin_vlog_t log_func, int sessionId) :
    _logFunc(log_func),
    _sessionId(sessionId),
    _level(PLOG_NOTE)
{
}

int ArachneLogBuf::sync()
{
    log(_line.str().c_str());
    _line.str("");

    return 0;
}

std::streambuf::int_type ArachneLogBuf::overflow(std::streambuf::int_type ch)
{
    char c = char(ch);
    if (c != '\r' && c != '\n')
        _line << char(ch);

    return traits_type::to_int_type(ch);
}

void ArachneLogBuf::log(const char* msg, ...)
{
    va_list argptr;
    va_start(argptr, msg);

    std::stringstream s;
    s << "Arachne";
    if (_sessionId != -1)
        s << "_" << _sessionId << " ";
    switch (_level) {
        case PLOG_ERR:
            s << "ERROR";
            break;
        case PLOG_WARN:
            s << " WARN";
            break;
        case PLOG_NOTE:
            s << " NOTE";
            break;
        case PLOG_DEBUG:
            s << "DEBUG";
            break;
        default:
            break;
    }

    _logFunc(_level, s.str().c_str(), msg, argptr);

    va_end(argptr);
}

ArachneLogger::ArachneLogger(plugin_vlog_t logFunc, int sessionId) :
    std::ostream(&_buf),
    _buf(logFunc, sessionId)
{
}
