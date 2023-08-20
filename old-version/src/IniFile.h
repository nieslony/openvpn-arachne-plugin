#ifndef INI_FILE_H
#define INI_FILE_H

#include <string>
#include <map>
#include <vector>
#include <memory>

class IniFileException : public std::runtime_error {
private:
    std::string createMsg(const std::string &line, uint lineNr, const std::string &msg);

public:
    IniFileException(const std::string &msg)
        : std::runtime_error(msg) {}
    IniFileException(const std::string &line, uint lineNr, const std::string &msg);
};

class ValueConverter {
public:
    virtual void setValue(const std::string&) = 0;
};

class StringValueConverter : public ValueConverter {
private:
    std::string *_value;

public:
    StringValueConverter(std::string *value) {
        _value = value;
    }

    virtual void setValue(const std::string&);
};

class BoolValueConverter : public ValueConverter {
private:
    bool *_value;

public:
    BoolValueConverter(bool *value) {
        _value = value;
    }

    virtual void setValue(const std::string&);
};

class IniFile {
private:
    std::map<const std::string, std::unique_ptr<ValueConverter>> _entries;

    void chop(std::string &s);

public:
    void insert(const std::string &key, std::string &value);
    void insert(const std::string &key, bool &value);

    void load(std::istream &in);
};

#endif
