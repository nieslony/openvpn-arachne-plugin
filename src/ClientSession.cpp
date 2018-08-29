#include "ClientSession.h"

#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot inclide openvpn-plugin.h"
#endif

#include <sstream>

ClientSession::ClientSession(const ArachnePlugin &plugin, long id)
    : _plugin(plugin), _logger(&plugin, this)
{
    _sessionId = id;
}

ClientSession::~ClientSession()
{
    logger() << Logger::note << "Deleting session";
}

long ClientSession::id() const
{
    return _sessionId;
}
