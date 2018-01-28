#include "IniFile.h"

#include <sstream>

#include <iostream>

using namespace std;

IniFile::IniFile(istream &in, const unordered_set<string> &keys)
{
    load(in, keys);
}

void IniFile::load(istream &in, const unordered_set<string> &keys) {
    string line;

    while (std::getline(in, line)) {
        chop(line);

        if (line.front() == '#')
            continue;
        if (line.empty())
            continue;

        size_t pos = line.find("=");

        if (pos == line.npos) {
            ostringstream buf;
            buf << "'='-separated key-value-pair expected: " << line;
            throw IniFileException(buf.str());
        }

        string key = line.substr(0, pos);
        string value = line.substr(pos+1);

        chop(key);
        chop(value);

        if (keys.find(key) == keys.end()) {
            ostringstream buf;
            buf << "Invalid key: " << key;
            throw IniFileException(buf.str());
        }

        params[key] = value;
    }
}

void IniFile::chop(string &s)
{
    size_t pos;

    while ( (pos = s.find("\r")) != std::string::npos)
        s.erase(pos, 1);

    while ( (pos = s.find("\n")) != std::string::npos)
        s.erase(pos, 1);
}

bool IniFile::get(const string &key, string &value)
{
    auto it = params.find(key);
    if (it != params.end()) {
        value = it->second;
        return true;
    }

    return false;
}

bool IniFile::get(const string &key, bool& value)
{
    string s_value;

    if (!get(key, s_value)) {
        return false;
    }

    if (s_value == "false" || s_value == "no" || s_value == "0") {
        value = false;

        return true;
    }
    if (s_value == "true" || s_value == "yes" || s_value == "1") {
        value = true;

        return true;
    }

    ostringstream buf;
    buf << "Bolean value expected for key " << key << ": " << value;
    throw IniFileException(buf.str());
}
