#include "Logger.h"
#include "ArachnePlugin.h"
#include "ClientSession.h"

#include <stdio.h>
#include <stdexcept>

LoggerBuf::LoggerBuf(const ArachnePlugin *plugin, const ClientSession *session)
{
    _plugin = plugin;
    _session = session;
    _line = std::stringstream();
    _level = PLOG_NOTE;
}

std::streambuf::int_type LoggerBuf::overflow(std::streambuf::int_type ch)
{
    char c = char(ch);
    if (c != '\r' && c != '\n')
        _line << char(ch);

    return traits_type::to_int_type(ch);
}

void do_sync(const ArachnePlugin *plugin, const ClientSession *session,
             openvpn_plugin_log_flags_t flags,
             const char *prefix, const char* msg, ...)
{
    va_list argptr;
    va_start(argptr, msg);

    plugin_vlog_t log_func = plugin->log_func();
    if (log_func == NULL)
        std::cerr << "Cannot log" <<  std::endl;
    else
        plugin->log_func()(flags, prefix, msg, argptr);
    va_end(argptr);
}

int LoggerBuf::sync()
{
    std::stringstream s;
    s << "Arachne_" << std::hex << _plugin->startupTime();

    if (_session != NULL)
        s << "-" << _session->id();

    std::string prefix = s.str();
    std::string msg = _line.str();
    chop(msg);

    do_sync(_plugin, _session, _level, prefix.c_str(), msg.c_str());

    _line = std::stringstream();

    return 0;
}

void LoggerBuf::chop(std::string &s)
{
    size_t pos;

    while ( (pos = s.find("\r")) != std::string::npos)
        s.erase(pos, 1);

    while ( (pos = s.find("\n")) != std::string::npos)
        s.erase(pos, 1);
}

