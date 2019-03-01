#ifndef URL_H
#define URL_H

#include <string>

class Url {
private:
    std::string _protocol;
    std::string _host;
    std::string _path;
    unsigned _port;

    bool _autoPort;

    void init(const std::string&);

public:
    Url() {}
    Url(const std::string& url);
    Url &operator=(const std::string&);

    std::string str() const;

    const std::string &protocol() const { return _protocol; };
    const std::string &host() const { return _host; };
    const std::string &path() const { return _path; };
    bool autoPort() const { return _autoPort; }
    unsigned port() const { return _port; };

    void path(const std::string &path) { _path = path; }
    void port(unsigned p) { _port = p; }

};

#endif
