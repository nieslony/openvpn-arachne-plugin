#ifndef CLIERNT_SESSION_H
#define CLIENT_SESSION_H

#include <string>

#include "ArachnePlugin.h"
#include "Logger.h"

class ClientSession {
friend ClientSession *ArachnePlugin::createClientSession(void);

private:
    long _sessionId;
    const ArachnePlugin &_plugin;

    ClientSession(const ArachnePlugin&, long id);

public:
    Logger _logger;
    long id() const;
    Logger &logger() { return _logger; }

    ~ClientSession();
};

#endif
