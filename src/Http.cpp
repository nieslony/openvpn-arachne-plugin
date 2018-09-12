#include "Http.h"
#include "Url.h"
#include "ClientSession.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/array.hpp>

#include <sstream>
#include <iostream>
#include <iterator>

namespace http {

HttpException::HttpException(const std::string& msg)
    : std::runtime_error(msg)
{
}

void Http::get(const Request &request, Response &response, std::ostream *os)
{
    Url url = request.url();

    _logger.levelNote();
    _logger << "GET " << request.url().str() << std::endl;
    boost::asio::io_service io_service;

    boost::asio::ip::tcp::resolver resolver(io_service);
    auto it = resolver.resolve(url.host(), std::to_string(url.port()));
    if (url.protocol() == "https") {
        boost::asio::ssl::context ctx(boost::asio::ssl::context::method::sslv23_client);
        if (_caFile.length() > 0)
            ctx.load_verify_file(_caFile);

        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket(io_service, ctx);

        if (!_ignoreSsl) {
        _logger.levelNote();
            _logger << "SSL verify: verify peer" << std::endl;
            socket.set_verify_mode(boost::asio::ssl::verify_peer);
            socket.set_verify_callback(boost::asio::ssl::rfc2818_verification(url.host()));
        }
        else {
            _logger.levelNote();
            _logger << "Ignoring SSL errors" << std::endl;
            socket.set_verify_mode(boost::asio::ssl::verify_none );
        }

        connect(socket.lowest_layer(), it);
        socket.handshake(boost::asio::ssl::stream_base::handshake_type::client);

        handleRequest(socket, request, response, os);
    }
    else if (url.protocol() == "http") {
        boost::asio::ip::tcp::socket socket(io_service);
        boost::asio::connect(socket, it);

        handleRequest(socket, request, response, os);
    }
    else {
        std::stringstream msg;
        msg << "Invalid protocol: " << url.protocol();

        throw HttpException(msg.str());
    }
}

template<typename Socket>
int Http::handleRequest(Socket &socket, const Request &request, Response &response, std::ostream *os)
{
    Url url = request.url();

    _logger.levelDebug();
    _logger << "GET " << url.str() << std::endl;

    boost::asio::streambuf requestBuf;
    std::ostream request_stream(&requestBuf);
    request_stream << request;

    boost::asio::write(socket, requestBuf);

    boost::asio::streambuf responseBuf;
    boost::asio::read_until(socket, responseBuf, "\r\n\r\n");

    std::istream response_stream(&responseBuf);
    response_stream >> response;

    if (os != NULL) {
        boost::system::error_code error;
        while (boost::asio::read(socket, responseBuf,
            boost::asio::transfer_at_least(1), error))
        *os << &responseBuf;
        if (error != boost::asio::error::eof)
            throw boost::system::system_error(error);
    }

    _logger.levelNote();
    _logger << "Got status " << response.status() << "(" << response.status_str() << ")" << std::endl;
    if (response.status() == 302) {
        Url location;
        try {
            location = response.header("Location");
        }
        catch (const std::out_of_range &ex) {
            _logger.levelErr();
            _logger << "Redirecting without location. Where do you want me to go?" << std::endl;

            return -1;
        }
        if (location.autoPort())
            location.port(url.port());
        _logger.levelNote();
        const std::string name("Location");
        _logger << "Redirecting to " << response.header(name) << std::endl;
        Request request2(location);
        request2.header("Authorization", request.header("Authorization"));
        get(request2, response);
    }

    return response.status();
}

void Http::chop(std::string &s)
{
    size_t pos;

    while ( (pos = s.find("\r")) != std::string::npos)
        s.erase(pos, 1);

    while ( (pos = s.find("\n")) != std::string::npos)
        s.erase(pos, 1);
}

} // namespace http
