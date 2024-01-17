#ifndef HTTP_H
#define HTTP_H

#include <string>
#include <stdexcept>

class HttpException : public std::runtime_error {
public:
    HttpException(const std::string &msg)
        : std::runtime_error(msg)
    {}
};

#endif
