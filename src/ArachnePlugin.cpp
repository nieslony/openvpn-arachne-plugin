#include "ArachnePlugin.h"
#include "ClientSession.h"
#include "IniFile.h"

#include <cstring>
#include <cstdarg>
#include <ctime>
#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_set>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>

static const std::string FN_IP_FORWARD("/proc/sys/net/ipv4/ip_forward");

ArachnePlugin::ArachnePlugin(const openvpn_plugin_args_open_in *in_args)
    : _ignoreSsl(false), _handleIpForwarding(false)
{
    log_func = in_args->callbacks->plugin_vlog;
    time(&_startupTime);

    log(PLOG_NOTE, "Initializing plugin...");

    parseOptions(in_args->argv);

    enableIpForwarding();

    _sessionCounter = 0;
}

ArachnePlugin::~ArachnePlugin()
{
    log(PLOG_NOTE, "Unloading Arachne plugin...");

    resetIpForwarding();
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

void ArachnePlugin::log(openvpn_plugin_log_flags_t flags, long sessionId, const char *msg, ...)
{
    va_list argptr;
    va_start(argptr, msg);

    std::stringstream id;
    id << "Arachne_" << std::hex << _startupTime << "-" << sessionId;

    log_func(flags, id.str().c_str(), msg, argptr);

    va_end(argptr);
}


void ArachnePlugin::log(openvpn_plugin_log_flags_t flags, const char *msg, ...)
{
    va_list argptr;
    va_start(argptr, msg);

    log(flags, 0, msg, argptr);
}

int ArachnePlugin::userAuthPassword(const char *argv[], const char *envp[],
    ClientSession* session)
{
    bool authSuccessfull = true;
    std::string username(getenv("username", envp));
    std::string password(getenv("password", envp));
    std::string userPwd = username + ":" + password;
    std::string userPwdBase64 = base64(userPwd.c_str());

    log(PLOG_NOTE, session->id(), "Trying to authenticate user %s...", username.c_str());

    authSuccessfull = http(url, userPwdBase64, session) == 200;

    if (authSuccessfull) {
        log(PLOG_NOTE, session->id(), "User %s authenticated successfully", username.c_str());
        return OPENVPN_PLUGIN_FUNC_SUCCESS;
    }
    else {
        log(PLOG_NOTE, session->id(), "Authtication for user %s failed", username.c_str());
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

int ArachnePlugin::http(const Url &url, const std::string &userPwd, ClientSession* session)
{
    log(PLOG_NOTE, session->id(), "Opening %s...", url.str().c_str());

    boost::asio::io_service io_service;

    boost::asio::ip::tcp::resolver resolver(io_service);
    auto it = resolver.resolve({url.host(), std::to_string(url.port()) });
    if (url.protocol() == "https") {
        log(PLOG_NOTE, session->id(), "Creating SSL socket");
        try {
            boost::asio::ssl::context ctx(io_service, boost::asio::ssl::context::method::sslv23_client);
            if (_caFile.length() > 0)
                ctx.load_verify_file(_caFile);

            boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket(io_service, ctx);

            if (!_ignoreSsl) {
                socket.set_verify_mode(boost::asio::ssl::verify_peer);
                socket.set_verify_callback(boost::asio::ssl::rfc2818_verification(url.host()));
            }

            connect(socket.lowest_layer(), it);
            socket.handshake(boost::asio::ssl::stream_base::handshake_type::client);

            return handleRequest(socket, userPwd, session);
        }
        catch (const std::exception &ex) {
            log(PLOG_ERR, session->id(), "Cannot open socket: %s", ex.what());

            return -1;
        }
    }
    else if (url.protocol() == "http") {
        log(PLOG_NOTE, session->id(), "Creating TCP socket");
        try {
            boost::asio::ip::tcp::socket socket(io_service);
            boost::asio::connect(socket, it);

            return handleRequest(socket, userPwd, session);
        }
        catch (std::exception &ex) {
            log(PLOG_ERR, session->id(), "Cannot open socket: %s", ex.what());

            return -1;
        }

    }
    else {
        log(PLOG_ERR, session->id(), "Invalid protocol: %s", url.protocol().c_str());
    }

    return -1;
}

void ArachnePlugin::chop(std::string &s)
{
    size_t pos;

    while ( (pos = s.find("\r")) != std::string::npos)
        s.erase(pos, 1);

    while ( (pos = s.find("\n")) != std::string::npos)
        s.erase(pos, 1);
}

std::string ArachnePlugin::base64(const char* in) noexcept
{
    std::ostringstream  os;
    const char B64CHARS[65] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "+/";

    int extra_chars = 0;
    try {
        for (const char* it = in; *it != 0; it++) {
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
    }
    catch (std::exception &ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
    }

    return os.str();
}

ClientSession *ArachnePlugin::createClientSession()
{
    ClientSession *session = new ClientSession(*this);
    session->_sessionId = ++_sessionCounter;

    return session;
}

void ArachnePlugin::parseOptions(const char **argv)
{
    IniFile iniFile;

    for (const char **arg = argv+1; *arg != 0; arg++) {
        std::string args(*arg);

        std::size_t found = args.find("=");
        if (found == std::string::npos) {
            std::stringstream msg;
            msg << "Key value pair expected: " << args;
            throw (PluginException(msg.str()));
        }
        std::string key = args.substr(0, found);
        std::string value = args.substr(found+1);

        if (key == "url") {
            url = value;
        }
        else if (key == "cafile") {
            _caFile = value;
        }
        else if (key == "ignoressl") {
            if (value == "1" or value == "true" or value == "yes") {
                _ignoreSsl = true;
            }
            else if (value == "0" or value == "false" or value == "no") {
                _ignoreSsl = false;
            }
            else {
                std::stringstream msg;
                msg << "Boolean value expected for parameter " << key << ": " << value;
                throw (PluginException(msg.str()));
            }
        }
        else if (key == "config") {
            std::unordered_set<std::string> keys;
            keys.insert("url");
            keys.insert("cafile");
            keys.insert("ignoressl");
            keys.insert("handleipforwarding");

            std::ostringstream buf;
            buf << "Reading config file " << value;
            log(PLOG_NOTE, buf.str().c_str());

            std::ifstream ifs;
            ifs.open (value, std::ifstream::in);
            if (!ifs.is_open()) {
                throw std::runtime_error("Cannot open config file");
            }
            iniFile.load(ifs, keys);
            ifs.close();
        }
        else {
            std::stringstream msg;
            msg << "Invalid key: " << key;
            throw (PluginException(msg.str()));
        }
    }

    std::string s;
    if (iniFile.get("url", s))
        url = s;
    iniFile.get("cafile", _caFile);
    iniFile.get("ignoressl", _ignoreSsl);
    iniFile.get("handleipforwarding", _handleIpForwarding);
}

template<typename Socket>
int ArachnePlugin::handleRequest(Socket &socket, const std::string &userPwd, ClientSession* session)
{
    try {
        //auto socket = openSslConnection(url);

        log(PLOG_NOTE, session->id(), "Creating request...");
        boost::asio::streambuf request;
        std::ostream request_stream(&request);
        request_stream << "GET " << url.path() << " HTTP/1.0\r\n";
        request_stream << "Host: " << url.host() << "\r\n";
        request_stream << "Accept: */*\r\n";
        request_stream << "Authorization: Basic " << userPwd << "\r\n";
        request_stream << "Connection: close\r\n\r\n";

        log(PLOG_NOTE, session->id(), "Sending request...");
        boost::asio::write(socket, request);

        log(PLOG_NOTE, session->id(), "Waiting for response");
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
            log(PLOG_ERR, session->id(), "Invalid HTTP response");
            return 500;
        }

        boost::asio::read_until(socket, response, "\r\n\r\n");

        std::string header;
        std::map<std::string, std::string> headers;
        while (std::getline(response_stream, header) && header != "\r") {
            chop(header);
            size_t sep = header.find(":");
            std::string name = header.substr(0, sep);
            std::string value = header .substr(sep+2);
            headers[name] = value;
        }

        log(PLOG_NOTE, session->id(), "HTTP status: %d (%s )", status_code, status_message.c_str());

        if (status_code == 302) {
            Url location = headers["Location"];
            //location.setPort(url.port());
            log(PLOG_NOTE, session->id(), "Forwarding to %s", location.str().c_str());
            return http(location, userPwd, session);
        }

        return status_code;
    }
    catch (const std::exception& e)
    {
        const std::type_info& r1 = typeid(e);
        log(PLOG_ERR, session->id(), r1.name());
        log(PLOG_ERR, session->id(), "Exception: %s", e.what());
    }

    return -1;
}

void ArachnePlugin::enableIpForwarding()
{
    if (_handleIpForwarding) {
        log(PLOG_NOTE, "Enabling IP forwarding");

        std::ifstream ifs;
        ifs.open(FN_IP_FORWARD);
        if (!ifs.is_open()) {
            std::ostringstream buf;
            buf << "Cannot open " << FN_IP_FORWARD << " for reading";
            throw PluginException(buf.str());
        }
        try {
            getline(ifs, _oldIpForwarding);
            ifs.close();
        }
        catch (std::exception &ex) {
            std::ostringstream buf;
            buf << "Error reading status of IP forwarding from " << FN_IP_FORWARD;
            throw PluginException(buf.str());
        }

        std::ofstream ofs;
        ofs.open(FN_IP_FORWARD);
        if (!ofs.is_open()) {
            std::ostringstream buf;
            buf << "Cannot open " << FN_IP_FORWARD << "=> cannot activate IP forwarding";
            throw PluginException(buf.str());
        }
        ofs << "1" << std::endl;
        ofs.close();
    }
    else {
        log(PLOG_NOTE, "Leaving IP forwarding untouched");
    }
}

void ArachnePlugin::resetIpForwarding()
{
    if (_handleIpForwarding) {
        std::ostringstream buf;
        buf << "Resetting IP forwarding: " << _oldIpForwarding;

        log(PLOG_NOTE, buf.str().c_str());
        std::ofstream ofs;
        ofs.open(FN_IP_FORWARD);
        if (!ofs.is_open()) {
            std::ostringstream buf;
            buf << "Error reading status of IP forwarding from " << FN_IP_FORWARD;
            throw PluginException(buf.str());
        }
        try {
            ofs << _oldIpForwarding << std::endl;
            ofs.close();
        }
        catch (std::exception &s) {
            std::ostringstream buf;
            buf << "Error resetting IP forwarding, cannot write to " << FN_IP_FORWARD;
            throw PluginException(buf.str());
        }
    }
    else {
        log(PLOG_NOTE, "Leaving IP forwarding untouched");
    }
}
