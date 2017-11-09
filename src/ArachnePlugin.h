#ifndef ARACHNE_PLUGIN_H
#define ARACHNE_PLUGIN_H

class ArachnePlugin {
public:
    ArachnePlugin(const char *argv[]);
    
    int up(const char *argv[], const char *envp[]);
    int down(const char *argv[], const char *envp[]);
    int userAuthPassword(const char *argv[], const char *envp[]);
};

#endif
