#include "IniFile.h"

#include <cwctype>
#include <iterator>
#include <sstream>

IniFileException::IniFileException(const std::string &line, uint lineNr, const std::string &msg)
    : runtime_error(createMsg(line, lineNr, msg))
{
}

std::string IniFileException::createMsg(const std::string &line, uint lineNr, const std::string &msg)
{
    std::stringstream str;
    str << "Error parsing line " << lineNr << " \"" << line << "\": " << msg;

    return str.str();
}

void StringValueConverter::setValue(const std::string& value)
{
    if (value.front() == '"' && value.back() == '"')
        *_value = value.substr(1, value.length() -2);
    else
        *_value = value;
}

void BoolValueConverter::setValue(const std::string& value)
{
    if (value == "true" || value == "yes" || value == "on" || value == "1")
        *_value = true;
    else if (value == "false" || value == "no" || value == "off" || value == "0")
        *_value = false;
    else
        throw IniFileException("Invalid bool value: " + value);
}

void IniFile::insert(const std::string &key, std::string &var)
{
    _entries[key] = std::unique_ptr<ValueConverter>(new StringValueConverter(&var));
}

void IniFile::insert(const std::string &key, bool &var)
{
    _entries[key] = std::unique_ptr<ValueConverter>(new BoolValueConverter(&var));
}

void IniFile::load(std::istream &in)
{
    std::string line;
    uint lineNr = 1;

    while (std::getline(in, line)) {
        chop(line);
        if (line.empty() || line.front() == '#')
            continue;

        size_t pos = line.find("=");
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos+1);

        chop(key);
        chop(value);

        if (_entries.find(key) == _entries.end())
            throw IniFileException(line, lineNr, "Key " + key + " is invalid");
        else
            try {
                _entries[key]->setValue(value);
            }
            catch (const IniFileException &ex) {
                throw IniFileException(line, lineNr, ex.what());
            }

        lineNr++;
    }
}

void IniFile::chop(std::string &s)
{
    size_t from;
    size_t to;

    for (from = 0; from < s.length(); from++)
        if (!iswspace(s[from]))
            break;
    for (to = s.length()-1; to >= 0; to--)
        if (!iswspace(s[to]))
            break;

    s = s.substr(from, to-from+1);
}

