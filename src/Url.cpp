#include "Url.h"

#include <sstream>

Url::Url(const std::string& url)
{
    init(url);
}

void Url::init(const std::string& url)
{
    size_t begin_host = url.find("://") + 3;
    _protocol = url.substr(0, begin_host-3);

    size_t begin_path = url.find("/", begin_host);
    _host = url.substr(begin_host, begin_path-begin_host);

    size_t begin_port = _host.find(":");
    unsigned port = 80;
    if (begin_port != std::string::npos) {
        std::string port_str = _host.substr(begin_port+1);
        _port = std::stoi(port_str);
        _host = _host.substr(0, begin_port);
    }

    _path = url.substr(begin_path);
}

Url &Url::operator=(const std::string& url)
{
    init(url);
    return *this;
}

std::string Url::str() const
{
    std::ostringstream os;

    os << _protocol << "://" << _host;
    if (_port != 0)
        os << ":" << _port;
    os << _path;

    return os.str();
}