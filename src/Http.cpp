#include "Http.h"
#include <boost/system/detail/error_code.hpp>

#define BOOST_BIND_NO_PLACEHOLDERS

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/iostreams/stream.hpp>

#include <iostream>

namespace http {

typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;

class SslWrapper : public boost::iostreams::device<boost::iostreams::bidirectional>
{
    ssl_socket& sock;
public:
    typedef char char_type;

    SslWrapper(ssl_socket& sock) : sock(sock) {}

    std::streamsize read(char_type* s, std::streamsize n) {
        auto rc = boost::asio::read(sock, boost::asio::buffer(s,n));
        return rc;
    }
    std::streamsize write(const char_type* s, std::streamsize n) {
        return boost::asio::write(sock, boost::asio::buffer(s,n));
    }
};

void Http::doHttpInt(const Request &request, Response &response, std::iostream &https, std::ostream *os)
{
    https << request << std::flush;
    https >> response;

    if (os != NULL)
        *os << https.rdbuf();

    if (response.status() != 200)
        throw HttpException(response.status_str());
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
        if (!tcps)
        {
            boost::system::error_code error(tcps.error());
            std::stringstream msg;
            msg
                << "Cannot connect to " << request.url().host() << ":" << portStr
                << " \"" << error.message() << "\"";
            throw HttpException(msg.str());
        }

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
        socket.set_verify_callback(
            boost::asio::ssl::rfc2818_verification(request.url().host())
        );
        socket.handshake(ssl_socket::client);

        boost::iostreams::stream<SslWrapper> ssls(socket);
        if (!ssls)
        {
            std::stringstream msg;
            msg
                << "Cannot connect to " << request.url().host() << ":" << portStr;
            throw HttpException(msg.str());
        }

        doHttpInt(request, response, ssls, os);
    }
}

} // namespace http
