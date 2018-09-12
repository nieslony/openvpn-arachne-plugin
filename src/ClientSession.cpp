#include "ClientSession.h"

#include <boost/property_tree/json_parser.hpp>

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
    _http.ignoreSsl(plugin.ignoreSsl());
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

        _username = username;
        _password = password;

        return response.status() == 200;
    }
    catch (const std::runtime_error &ex) {
        _logger.levelErr();
        _logger << ex.what() << std::endl;

        return false;
    }
}

void ClientSession::getFirewallConfig(const Url &url, boost::property_tree::ptree &json)
{
    _logger.levelNote();
    _logger << "Getting firewall configuration" << std::endl;

    http::Request request(url);
    request.basicAuth(_username, _password);

    http::Response response;
    std::stringstream content;
    _http.get(request, response, content);

    boost::property_tree::read_json(content, json);
}
