#include "Http.h"
#include "Url.h"
#include "ClientSession.h"

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/iostreams/stream.hpp>

#include <sstream>
#include <iostream>
#include <iterator>

namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
namespace bios = boost::iostreams;

using boost::asio::ip::tcp;
using boost::system::system_error;
using boost::system::error_code;

namespace http {

typedef ssl::stream<tcp::socket> ssl_socket;
class SslWrapper : public bios::device<bios::bidirectional>
{
    ssl_socket& sock;
public:
    typedef char char_type;

    SslWrapper(ssl_socket& sock) : sock(sock) {}

    std::streamsize read(char_type* s, std::streamsize n) {
        error_code ec;
        auto rc = asio::read(sock, asio::buffer(s,n), ec);
        return rc;
    }
    std::streamsize write(const char_type* s, std::streamsize n) {
        return asio::write(sock, asio::buffer(s,n));
    }
};

HttpException::HttpException(const std::string& msg)
    : std::runtime_error(msg)
{
}

void Http::doHttpInt(const Request &request, Response &response, std::iostream &https, std::ostream *os)
{
    _logger.levelNote();
    _logger << request.methodStr() << " " << request.url().str() << std::endl;
    _logger << request.secureCopy() << std::endl;

    https << request << std::flush;
    https >> response;

    _logger.levelNote();
    _logger << "HTTP status: " << response.status() << " " << response.status_str() << std::endl;

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
        _logger.levelNote();
        _logger << "HTTP" << std::endl;
        tcp::iostream tcps(request.url().host(), portStr);
        //tcps.expires_from_now(boost::posix_time::seconds(60));

        doHttpInt(request, response, tcps, os);
    } else {
        _logger.levelNote();
        _logger << "HTTPS" << std::endl;

        asio::io_service ios;

        tcp::resolver resolver(ios);
        tcp::resolver::query query(request.url().host(), portStr);
        tcp::resolver::iterator endpoint_iterator =
            resolver.resolve(query);

        ssl::context ctx(ssl::context::sslv23);
        ctx.set_default_verify_paths();
        ssl_socket socket(ios, ctx);

        asio::connect(socket.lowest_layer(), endpoint_iterator);

        socket.set_verify_mode(ssl::verify_peer);
        socket.set_verify_callback(ssl::rfc2818_verification(request.url().host()));
        socket.handshake(ssl_socket::client);

        bios::stream<SslWrapper> ssls(socket);

        doHttpInt(request, response, ssls, os);
    }
}

}
