#include "Http.h"

#include <iostream>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>

namespace http {

void chop(std::string &s)
{
    size_t pos;
    while ( (pos = s.find("\r")) != std::string::npos)
        s.erase(pos, 1);

    while ( (pos = s.find("\n")) != std::string::npos)
        s.erase(pos, 1);
}

std::string getChoppedLine(std::istream &is)
{
    std::string line;
    std::getline(is, line);
    chop(line);
    return line;
}

std::istream &operator>>(std::istream& is, Response &r)
{
    std::string line = getChoppedLine(is);

    std::vector<std::string> head;
    boost::algorithm::split(head, line, boost::algorithm::is_any_of(" "));
    r._protocol = head.at(0);
    r._status = std::stoi(head.at(1));
    r._status_str = head.at(2);

    for (line = getChoppedLine(is); !line.empty(); line = getChoppedLine(is)) {
        size_t pos = line.find(": ");
        std::string name = line.substr(0, pos);
        std::string value = line.substr(pos + 2);

        r._headers[name] = value;
    }

    return is;
}

}
