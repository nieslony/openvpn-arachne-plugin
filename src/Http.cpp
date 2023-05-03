#include "Http.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/iostreams/stream.hpp>

#include <iostream>

namespace http {

void Http::doHttpInt(const Request &request, Response &response, std::iostream &https, std::ostream *os)
{
    https << request << std::flush;
    https >> response;

    if (os != NULL)
        *os << https.rdbuf();
}

void Http::doHttp(const Request &request, Response &response, std::ostream *os)
{
    std::string portStr;

    if (request.url().autoPort())
        portStr = request.url().protocol();
    else
        portStr = std::to_string(request.url().port());

    if (request.url().protocol() == "http") {
        boost::asio::ip::tcp::iostream tcps(request.url().host(), portStr);

        doHttpInt(request, response, tcps, os);
    } else {
        boost::asio::io_service ios;

        boost::asio::ip::tcp::resolver resolver(ios);
        boost::asio::ip::tcp::resolver::query query(request.url().host(), portStr);
        boost::asio::ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
        ctx.set_default_verify_paths();
        ssl_socket socket(ios, ctx);

        boost::asio::connect(socket.lowest_layer(), endpoint_iterator);

        socket.set_verify_mode(boost::asio::ssl::verify_peer);
        socket.set_verify_callback(boost::asio::ssl::rfc2818_verification(request.url().host()));
        socket.handshake(ssl_socket::client);

        boost::iostreams::stream<SslWrapper> ssls(socket);

        doHttpInt(request, response, ssls, os);
    }
}


}
