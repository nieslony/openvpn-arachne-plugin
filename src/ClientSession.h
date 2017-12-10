#ifndef CLIERNT_SESSION_H
#define CLIENT_SESSION_H

#include <string>

#include "ArachnePlugin.h"

class ClientSession {
friend ClientSession *ArachnePlugin::createClientSession(void);

private:
    long _sessionId;
    ArachnePlugin &_plugin;

    ClientSession(ArachnePlugin&);

public:
    long id() const;

    ~ClientSession();
};

#endif
