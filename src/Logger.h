#ifndef LOGGER_H
#define LOGGER_H

#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot inclide openvpn-plugin.h"
#endif

#include <ostream>
#include <istream>
#include <streambuf>
#include <ios>
#include <sstream>
#include <cinttypes>
#include <iostream>
#include <streambuf>
#include <string>
#include <type_traits>

class ArachnePlugin;
class ClientSession;

class LoggerBuf : public std::streambuf {
public:
    LoggerBuf(const ArachnePlugin*, const ClientSession*);

    std::streambuf::int_type overflow( std::streambuf::int_type ch = EOF);

    //void linePrefix(const std::string& lp) { _linePrefix = lp; }
    void flags(openvpn_plugin_log_flags_t f) { _flags = f; }

protected:
    virtual int sync();

private:
    const ArachnePlugin *_plugin;
    const ClientSession *_session;

    std::stringstream _line;
    // std::string _linePrefix;
    openvpn_plugin_log_flags_t _flags;
};

class Logger : public std::ostream {
public:
    Logger(const ArachnePlugin *plugin, const ClientSession *session = NULL)
        : std::ostream(&_loggerBuf), std::ios(0), _loggerBuf(plugin, session)
    {}

    // void linePrefix(const std::string& lp) { _loggerBuf.linePrefix(lp); }

    static Logger &err(Logger&);
    static Logger &warn(Logger&);
    static Logger &note(Logger&);

private:
    LoggerBuf _loggerBuf;
};

#endif
