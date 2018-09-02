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
    : _plugin(plugin), _logger(&plugin, this), _http(_logger)
{
    _sessionId = id;
}

ClientSession::~ClientSession()
{
    _logger.levelNote();
    _logger << "Deleting session" << std::endl;
}

long ClientSession::id() const
{
    return _sessionId;
}

bool ClientSession::authUser(const Url &authUrl, const std::string &username, const std::string &password)
{
    try {
        http::Request request(authUrl);
        request.basicAuth(username, password);

        http::Response response;
        _http.get(request, response);
        return response.status() == 200;
    }
    catch (const std::runtime_error &ex) {
        _logger.levelErr();
        _logger << ex.what() << std::endl;

        return false;
    }
}