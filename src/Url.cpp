#include "Url.h"
#include "ArachnePlugin.h"

#include <sstream>
#include <regex>

Url::Url(const std::string& url)
{
    init(url);
}

void Url::init(const std::string& url)
{
    std::smatch m;

    std::string proto;
    std::string host;
    std::string port;
    std::string path;

    bool found = regex_search(url, m, std::regex("^(http[s]?)://([a-zA-Z0-9.\\-]*)(:([0-9]+))?(/(.*))?$"));

    if (!found) {
        std::ostringstream buf;
        buf << "Error parsing url: " << url;
        throw PluginException(buf.str());
    }

    _protocol = m[1].str();
    _host = m[2].str();
    port = m[4].str();
    _path = m[5].str();

    if (port == "") {
        if (_protocol == "http")
            _port = 80;
        else
            _port = 443;
        _autoPort = true;
    }
    else {
        _port = std::stoi(port);
        _autoPort = false;
    }

    if (_port < 1 || _port > 65534) {
        std::ostringstream buf;
        buf << "Error parsing url " << url << ": invalid port number: " << port;
        throw PluginException(buf.str());
    }
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
