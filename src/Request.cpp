#include "Http.h"
#include "Url.h"

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>
#include <map>
#include <ostream>
#include <sstream>

namespace http {

std::string base64(const std::string &in)
{
    using namespace boost::archive::iterators;
    std::stringstream os;
    using IT =
        base64_from_binary<    // convert binary values to base64 characters
            transform_width<   // retrieve 6 bit integers from a sequence of 8 bit bytes
                std::string::const_iterator,
                6,
                8
            >
        >; // compose all the above operations in to a new iterator
    std::copy(
        IT(std::begin(in)),
        IT(std::end(in)),
        std::ostream_iterator<char>(os)
    );
    os << std::string("====").substr(0, (4 - os.str().length() % 4) % 4);
    return os.str();
}

Request::Request(const Url &url)
    : _url(url)
{
}

void Request::header(const std::string &key, const std::string &value)
{
    _headers[key] = value;
}

void Request::basicAuth(const std::string &username, const std::string &password)
{
    std::string userPwd = username + ":" + password;
    std::string userPwdBase64 = base64(userPwd);

    _headers["Authorization"] = "Basic " + userPwdBase64;
}

std::ostream &operator<<(std::ostream& os, const Request& r)
{
    os << "GET " << r.url().path() << " HTTP/1.0\r\n";
    os << "Host: " << r.url().host() << "\r\n";
    os << "Accept: */*\r\n";
    os << "Connection: close\r\n";

    for (auto it = r._headers.begin(); it != r._headers.end(); ++it)
        os << (*it).first << ": " << (*it).second << "\r\n";
    os << "\r\n";

    os << "\r\n";

    return os;
}

}

