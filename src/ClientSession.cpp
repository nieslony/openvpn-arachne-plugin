#include "ClientSession.h"

#if defined HAVE_OPENVPN_PLUGIN_H
#include <openvpn-plugin.h>
#elif defined HAVE_OPENVPN_OPENVPN_PLUGIN_H
#include <openvpn/openvpn-plugin.h>
#else
#error "Cannot inclide openvpn-plugin.h"
#endif

ClientSession::ClientSession(ArachnePlugin &plugin)
    : _plugin(plugin)
{
}

ClientSession::~ClientSession()
{
    _plugin.log(PLOG_NOTE, _sessionId, "Deleting session");
}

long ClientSession::id() const
{
    return _sessionId;
}
