#ifndef CLIERNT_SESSION_H
#define CLIENT_SESSION_H

#include <string>

#include "ArachnePlugin.h"
#include "Logger.h"
#include "Http.h"

class ClientSession {
friend ClientSession *ArachnePlugin::createClientSession(void);

private:
    long _sessionId;
    const ArachnePlugin &_plugin;

    ClientSession(const ArachnePlugin&, long id);

public:
    Logger _logger;
    http::Http _http;

    ~ClientSession();

    long id() const;
    Logger &logger() { return _logger; }
    bool authUser(const Url &authUrl, const std::string &username, const std::string &password);

};

#endif
