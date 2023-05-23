#include "ClientSession.h"
#include "Http.h"

#include <sstream>

ClientSession::ClientSession(plugin_vlog_t logFunc, int sessionId)
    : _logger(logFunc, sessionId), _sessionId(sessionId)
{
    _logger.note() << "Creating Session " << _sessionId << std::flush;
}

ClientSession::~ClientSession()
{
    _logger.note() << "Cleanup session" << std::flush;
}

bool ClientSession::authUser(const Url &url, const std::string &username, const std::string &password)
{
    _logger.note() << "Authenticating user " << username << std::flush;

    http::Request request(http::GET, url);
    request.basicAuth(username, password);
    http::Response response;
    http::Http httpClient;
    _logger.note() << "Connecting to " << url.str() << std::flush;
    httpClient.doHttp(request, response);
    _logger.note() << "Got " << response.status() << "(" << response.status_str() << ")" << std::flush;
    if (response.status() == 200) {
        _logger.note() << "Authenticating successfull" << std::flush;
        _username = username;
        _password = password;
        return true;
    }
    else {
        _logger.note() << "Authenticating failed" << std::flush;
        return false;
    }
}

bool ClientSession::setFirewallRules(const Url &url)
{
    _logger.note() << "Setting firewall rules for user " << _username << std::flush;
    http::Request request(http::GET, url);
    request.basicAuth(_username, _password);
    http::Response response;
    http::Http httpClient;
    std::stringstream body;

    _logger.note() << "Connecting to " << url.str() << std::flush;
    httpClient.doHttp(request, response, &body);

    if (response.status() != 200) {
        _logger.error() << "Failed downloading firewall rules: " << body.str() << std::flush;
        return false;
    }
    _logger.note() << body.str() << std::flush;

    return true;
}

bool ClientSession::removeFirewalRules()
{
    _logger.note() << "Removing firewall rules" << std::flush;

    return true;
}
