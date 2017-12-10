#include "ClientSession.h"

#include <openvpn-plugin.h>

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
