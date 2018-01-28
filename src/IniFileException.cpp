#include "IniFile.h"

using namespace std;

IniFileException::IniFileException(const string& msg)
    : runtime_error(msg)
{
}
