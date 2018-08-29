#ifndef HTTP_H
#define HTTP_H

#include <string>
#include <map>

class ClientSession;
class Url;

class Response {
private:
    int _status;
    std::map<std::string, std::string> headers;

public:
    int status() const;
    std::string header() const;
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
    Http() {}
    ~Http() {}

    int get(const Url &url,
            const std::string &user, const std::string &password,
            ClientSession* session);

private:
    std::string _caFile;
    bool _ignoreSsl = false;

    std::string base64(const std::string &in) noexcept;

    template<typename Socket>
    int handleRequest(Socket &socket,
                      const Url& url,
                      const std::string &user, const std::string &password,
                      ClientSession* session);

    static void chop(std::string &s);

};

#endif
