#ifndef INI_FILE_H
#define INI_FILE_H

#include <istream>
#include <map>
#include <unordered_set>
#include <string>
#include <stdexcept>

class IniFileException : public std::runtime_error {
public:
    IniFileException(const std::string &msg);
};

class IniFile {
private:
    std::map<std::string, std::string> params;

    void chop(std::string &s);

public:
    IniFile() {}
    IniFile(std::istream &in, const std::unordered_set<std::string> &keys);

    void load(std::istream &in, const std::unordered_set<std::string> &keys);

    bool get(const std::string &key, bool&);
    bool get(const std::string &key, std::string&);
};

#endif
