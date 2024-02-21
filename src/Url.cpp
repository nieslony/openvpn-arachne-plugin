#include "Url.h"
#include "ArachnePlugin.h"

#include <sstream>
#include <boost/regex.hpp>

Url::Url(const std::string& url)
{
    init(url);
}

void Url::init(const std::string& url)
{
    if (url.empty()) {
        _empty = true;
        return;
    }

    boost::smatch m;

    std::string proto;
    std::string host;
    std::string port;
    std::string path;

    bool found = boost::regex_search(url, m, boost::regex("^(http[s]?)://([a-zA-Z0-9.\\-]*)(:([0-9]+))?(/(.*))?$"));

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

    _empty = false;
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
    os << query();

    return os.str();
}

void Url::addQuery(const std::string &key, const std::string &value)
{
    _query[key] = value;
}

std::string Url::query() const
{
    if (_query.empty())
        return "";

    std::stringstream os;
    os << "?";
    for (auto const& [key, value] : _query)
    {
        os << key << "=" << value << "&";
    }
    std::string queryStr = os.str();
    return queryStr.substr(0, queryStr.length()-1);
}
