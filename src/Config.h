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

    const std::string &get(const std::string &key);
    const std::string &get(const std::string &key, const std::string &default_value);

    bool getBool(const std::string &key);
    bool getBool(const std::string &key, bool default_value);

    int getInt(const std::string &key);
    int getInt(const std::string &key, int default_value);

private:
    std::map<std::string, std::string> _entries;
};

#endif
