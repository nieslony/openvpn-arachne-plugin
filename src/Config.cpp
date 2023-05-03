#include "Config.h"

#include <boost/algorithm/string.hpp>

#include <sstream>
#include <string>

ConfigException::ConfigException(const std::string &line, uint lineNr, const std::string &msg)
    : runtime_error(createMsg(line, lineNr, msg))
{
}

std::string ConfigException::createMsg(const std::string &line, uint lineNr, const std::string &msg)
{
    std::stringstream str;
    str << "Error parsing line " << lineNr << " \"" << line << "\": " << msg;

    return str.str();
}

const std::string &Config::get(const std::string& key)
{
    try {
        return _entries.at(key);
    }
    catch (std::out_of_range &ex) {
        throw ConfigException("Key not found in configuration: " + key);
    }
}

void Config::load(std::istream &in)
{
    std::string line;
    uint lineNr = 1;

    while (std::getline(in, line)) {
        boost::algorithm::trim(line);
        if (line.empty() || line.front() == '#')
            continue;

        size_t pos = line.find("=");
        if (pos == std::string::npos)
            throw ConfigException(line, lineNr, "Invalid syntax. 'key = value' expected");

        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos+1);

        boost::algorithm::trim(key);
        boost::algorithm::trim(value);

        if (key.empty())
            throw ConfigException(line, lineNr, "No key given");
        else
            _entries[key] = value;

        lineNr++;
    }
}
