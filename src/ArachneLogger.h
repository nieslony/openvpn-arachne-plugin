#ifndef ARACHNE_LOGGER_H
#define ARACHNE_LOGGER_H

#include <streambuf>
#include <ostream>
#include <sstream>

#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot include openvpn-plugin.h"
#endif

class ArachneLogBuf : public std::streambuf
{
public:
    ArachneLogBuf(plugin_vlog_t logFunc, const std::string &sessionId);

    std::streambuf::int_type overflow( std::streambuf::int_type ch = EOF);
    void setLevel(openvpn_plugin_log_flags_t level) { _level = level; }

protected:
    virtual int sync();

private:
    plugin_vlog_t _logFunc;
    std::string _sessionId;
    openvpn_plugin_log_flags_t _level;
    std::stringstream _line;

    void log(const char* msg, ...);
};

class ArachneLogger : public std::ostream
{
private:
    ArachneLogBuf _buf;

public:
    ArachneLogger(plugin_vlog_t logFunc, const std::string &sessionId = "");

    ArachneLogger &debug() { _buf.setLevel(PLOG_DEBUG); return *this; }
    ArachneLogger &note() { _buf.setLevel(PLOG_NOTE); return *this; }
    ArachneLogger &warning() { _buf.setLevel(PLOG_WARN); return *this; }
    ArachneLogger &error() { _buf.setLevel(PLOG_ERR); return *this; }
};

#endif
