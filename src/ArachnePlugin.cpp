#include "ArachnePlugin.h"

#include <cstring>
#include <cstdarg>
#include <iostream>
#include <fstream>

#include <boost/asio.hpp>

using namespace std;
using boost::asio::ip::tcp;

ArachnePlugin::ArachnePlugin(const openvpn_plugin_args_open_in *in_args)
{
    log_func = in_args->callbacks->plugin_vlog;

    log(PLOG_NOTE, "Initializing plugin...");
    url = in_args->argv[1];
}

const char* ArachnePlugin::getenv(const char* key, const char *envp[])
{
    if (envp) {
        int i;
        int keylen = strlen(key);
        for (i = 0; envp[i]; i++) {
            if (!strncmp(envp[i], key, keylen)) {
                const char *cp = envp[i] + keylen;
                if (*cp == '=') {
                    return cp + 1;
                }
            }
        }
    }

    return "";
}

void ArachnePlugin::log(openvpn_plugin_log_flags_t flags, const char *msg, ...)
{
    va_list argptr;
    va_start(argptr, msg);

    log_func(flags, "Arachne", msg, argptr);

    va_end(argptr);
}

int ArachnePlugin::userAuthPassword(const char *argv[], const char *envp[])
{
    bool authSuccessfull = true;
    const char *username = getenv("username", envp);

    log(PLOG_NOTE, "Trying to authticate user %s...", username);

    authSuccessfull = http(url) == 200;

    if (authSuccessfull) {
        log(PLOG_NOTE, "User %s authenticated successfull", username);
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }
    else {
        log(PLOG_NOTE, "Authtication for user %s failed", username);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

int ArachnePlugin::http(const Url &url)
{
    log(PLOG_NOTE, "Opening %s...", url.str().c_str());

    try {
        boost::asio::io_service io_service;

        tcp::resolver resolver(io_service);
        tcp::resolver::query query(url.host(), std::to_string(url.port()));
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

        tcp::socket socket(io_service);
        boost::asio::connect(socket, endpoint_iterator);
        if (!socket.is_open()) {
            log(PLOG_ERR, "Cannot open socket");
            return -1;
        }

        log(PLOG_NOTE, "Creating request...");
        boost::asio::streambuf request;
        std::ostream request_stream(&request);
        request_stream << "GET " << url.path() << " HTTP/1.0\r\n";
        request_stream << "Host: " << url.host() << "\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "Connection: close\r\n\r\n";

        log(PLOG_NOTE, "Sending request...");
        boost::asio::write(socket, request);

        log(PLOG_NOTE, "Waiting for response");
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
            log(PLOG_ERR, "Invalid HTTP response");
            return 500;
        }

        boost::asio::read_until(socket, response, "\r\n\r\n");

        std::string header;
        map<string, string> headers;
        while (std::getline(response_stream, header) && header != "\r") {
            chop(header);
            size_t sep = header.find(":");
            std::string name = header.substr(0, sep);
            std::string value = header .substr(sep+2);
            headers[name] = value;
        }

        log(PLOG_NOTE, "HTTP status: %d (%s )", status_code, status_message.c_str());

        if (status_code == 302) {
            Url location = headers["Location"];
            location.setPort(url.port());
            log(PLOG_NOTE, "Forwarding to %s", location.str().c_str());
            return http(location);
        }

        return status_code;
    }
    catch (std::exception& e)
    {
        log(PLOG_ERR, "Exception: %s", e.what());
    }

    return -1;
}

std::string toBase64(std::string& in) {
    const char BASE64CHARS[64] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "+/";

    ostringstream os;
    for ( std::string::iterator it=str.begin(); it!=str.end(); it++) {
        os << BASE64CHARS[*it & 63];

        char rest = *it >> 6 ;
        it++;
        if (it == str.end()) {
            os << "==";
            break;
        }
        rest |= (*it & 63);
        os << BASE64CHARS[rest];

        it++;
        if (it == str.end()) {
            os << =;
            break;
        }

        rest = *
    }
}

void ArachnePlugin::chop(std::string &s)
{
    size_t pos;

    while ( (pos = s.find("\r")) != string::npos)
        s.erase(pos, 1);

    while ( (pos = s.find("\n")) != string::npos)
        s.erase(pos, 1);
}
