#ifndef HTTP_H
#define HTTP_H

#include <string>
#include <map>

class ClientSession;
class Url;
class Logger;

class Request {
public:
    Request(std::string &url);
    void header(const std::string &key, const std::string &value);
    void basicAuth(const std::string &username, const std::string &password);
};

class Response {
private:
    int _status;
    std::map<const std::string, const std::string> headers;

public:
    int status() const;
    std::string header(const std::string &name) const;
    std::ostream &content() const;

    void caFile(const std::string &fn);
    void ignoreSsl(bool);
};

class HttpException : public std::runtime_error {
public:
    HttpException(const std::string &msg);
};

class Http {
public:
    Http(Logger &logger) : _logger(logger) {}
    ~Http() {}

    int get(const Url &url,
            const std::string &user, const std::string &password);

private:
    Logger &_logger;
    std::string _caFile;
    bool _ignoreSsl = false;

    std::string base64(const std::string &in) noexcept;

    template<typename Socket>
    int handleRequest(Socket &socket,
                      const Url& url,
                      const std::string &user, const std::string &password);

    static void chop(std::string &s);

};

#endif
