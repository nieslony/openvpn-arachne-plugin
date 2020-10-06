#ifndef HTTP_H
#define HTTP_H

#include <string>
#include <map>
#include <stdexcept>

#include "Url.h"

class ClientSession;
class Url;
class Logger;

namespace http {

typedef
    std::map<std::string, std::string>
    header_map;

enum HttpMethod {
    GET
};

class Request {
friend std::ostream &operator<<(std::ostream& os, const Request &r);

private:
    Url _url;
    header_map _headers;
    HttpMethod _method;

    Request() {}

public:
    Request(HttpMethod method, const Url &url);
    const Request secureCopy() const;

    const Url &url() const { return _url; }

    void header(const std::string &key, const std::string &value);
    const std::string &header(const std::string name) const {
        return const_cast<header_map*>(&_headers)->at(name);
    }

    void basicAuth(const std::string &username, const std::string &password);

    std::string methodStr() const;
};

std::ostream &operator<<(std::ostream&, const Request&);

class Response {
friend std::istream &operator>>(std::istream& os, Response &r);
private:
    std::string _protocol;
    int _status;
    std::string _status_str;
    header_map _headers;

    void header(const std::string name, const std::string value) {
        _headers.at(name) = std::string(value);
    }

public:
    int status() const { return _status; }
    std::string status_str() const { return _status_str; }

    const std::string header(const std::string &name) const {
        return const_cast<header_map*>(&_headers)->at(name);
    }

    std::istream &content() const;
};

std::istream &operator>>(std::istream& os, Response &r);

class HttpException : public std::runtime_error {
public:
    HttpException(const std::string &msg);
};

class Http {
public:
    Http(Logger &logger) : _logger(logger) {}
    ~Http() {}

    void doHttp(const Request &request, Response &response, std::ostream *os = NULL);

    void caFile(const std::string &fn) { _caFile = fn; }
    void ignoreSsl(bool is) { _ignoreSsl = is; }

private:
    Logger &_logger;
    std::string _caFile;
    bool _ignoreSsl = false;

    void doHttpInt(const Request &request, Response &response, std::iostream &https, std::ostream *os = NULL);
};

}

#endif
