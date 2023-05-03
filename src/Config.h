#ifndef CONFIG_H
#define CONFIG_H

#include <map>
#include <istream>

class ConfigException : public std::runtime_error {
private:
    std::string createMsg(const std::string &line, uint lineNr, const std::string &msg);

public:
    ConfigException(const std::string &msg)
        : std::runtime_error(msg) {}
    ConfigException(const std::string &line, uint lineNr, const std::string &msg);
};

class Config
{
public:
    Config(){}

    void load(std::istream&);
    const std::string &get(const std::string&);

private:
    std::map<std::string, std::string> _entries;
};

#endif
