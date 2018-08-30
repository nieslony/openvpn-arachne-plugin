#include "Http.h"
#include "Url.h"
#include "ClientSession.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>

#include <sstream>
#include <iostream>

HttpException::HttpException(const std::string& msg)
    : std::runtime_error(msg)
{
}

std::string Http::base64(const std::string &in) noexcept
{
    std::ostringstream  os;
    const char B64CHARS[65] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "+/";

    int extra_chars = 0;
    for (std::string::const_iterator it = in.begin(); it != in.end(); ++it) {
        char oct0, oct1, oct2;

        oct0 = *it;

        if (*(it+1) != 0) {
            it++;
            oct1 = *it & 0xff;
        }
        else {
            oct1 = 0;
            extra_chars++;
        }

        if (*(it+1) != 0) {
            it++;
            oct2 = *it & 0xff;
        }
        else {
            oct2 = 0;
            extra_chars++;
        }

        uint32_t d0 = ( (oct0 & 0xfc) >> 2 )& 63;
        uint32_t d1 = ( ((oct0 << 4) & 0x30) | ((oct1 >> 4) & 0x0f) ) & 63;
        uint32_t d2 = ( ((oct1 << 2) & 0x3c) | ((oct2 >> 6) & 0x03) ) & 63;
        uint32_t d3 = ( (oct2 & 0x3f) );

        os << B64CHARS[d0 & 63] << B64CHARS[d1 & 63];
        switch (extra_chars) {
            case 0:
                os << B64CHARS[d2  & 63] << B64CHARS[d3 & 63];
                break;
            case 1:
                os << B64CHARS[d2 & 63] << "=";
                break;
            case 2:
                os << "==";
                break;
        }
    }

    return os.str();
}

int Http::get(const Url &url, const std::string &user, const std::string &password)
{
    boost::asio::io_service io_service;

    boost::asio::ip::tcp::resolver resolver(io_service);
    auto it = resolver.resolve({url.host(), std::to_string(url.port()) });
    if (url.protocol() == "https") {
        boost::asio::ssl::context ctx(boost::asio::ssl::context::method::sslv23_client);
        if (_caFile.length() > 0)
            ctx.load_verify_file(_caFile);

        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket(io_service, ctx);

        if (!_ignoreSsl) {
            socket.set_verify_mode(boost::asio::ssl::verify_peer);
            socket.set_verify_callback(boost::asio::ssl::rfc2818_verification(url.host()));
        }

        connect(socket.lowest_layer(), it);
        socket.handshake(boost::asio::ssl::stream_base::handshake_type::client);

        return handleRequest(socket, url, user, password);
    }
    else if (url.protocol() == "http") {
        boost::asio::ip::tcp::socket socket(io_service);
        boost::asio::connect(socket, it);

        return handleRequest(socket, url, user, password);
    }
    else {
        std::stringstream msg;
        msg << "Invalid protocol: " << url.protocol();

        throw HttpException(msg.str());
    }

    return -1;
}

template<typename Socket>
int Http::handleRequest(Socket &socket,
                        const Url& url,
                        const std::string &user, const std::string &password)
{
    _logger.levelDebug();
    _logger << "GET " << url.str() << std::endl;
    std::string userPwd = user + ":" + password;
    std::string userPwdBase64 = base64(userPwd.c_str());

    boost::asio::streambuf request;
    std::ostream request_stream(&request);
    request_stream << "GET " << url.path() << " HTTP/1.0\r\n";
    request_stream << "Host: " << url.host() << "\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Authorization: Basic " << userPwdBase64 << "\r\n";
    request_stream << "Connection: close\r\n\r\n";

    boost::asio::write(socket, request);

    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\r\n");

    std::istream response_stream(&response);
    std::string http_version;
    response_stream >> http_version;
    unsigned int status_code;
    response_stream >> status_code;
    std::string status_message;
    std::getline(response_stream, status_message);
    chop(status_message);

    if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
        throw HttpException("Invalid HTTP response");
    }
    _logger.levelNote();
    _logger << "Got status " << status_code << std::endl;
    boost::asio::read_until(socket, response, "\r\n\r\n");

    std::string header;
    std::map<std::string, std::string> headers;
    while (std::getline(response_stream, header) && header != "\r") {
        chop(header);
        size_t sep = header.find(":");
        std::string name = header.substr(0, sep);
        std::string value = header .substr(sep+2);
        headers[name] = value;

        _logger.levelDebug();
        _logger << "Name: " << name << " | Value: " << value << std::endl;
    }

    if (status_code == 302) {
        Url location = headers["Location"];
        if (location.autoPort())
            location.port(url.port());
        _logger.levelNote();
        _logger << "Redirecting to " << headers["Location"] << std::endl;
        return get(location, user, password);
    }

    return status_code;

    return -1;
}

void Http::chop(std::string &s)
{
    size_t pos;

    while ( (pos = s.find("\r")) != std::string::npos)
        s.erase(pos, 1);

    while ( (pos = s.find("\n")) != std::string::npos)
        s.erase(pos, 1);
}
