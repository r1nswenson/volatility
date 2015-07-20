#pragma once

#include <map>
#include <vector>
#include <string>
#include <algorithm>

using namespace std;

#define KILO (1024)
#define MEGA (KILO * KILO)

typedef map<string, string> MODULE_MAP_TYPE;

class ModulesLoadedClass {
  public:
    ModulesLoadedClass() : KernelNameFound(false) {}

    bool Initialize();

    bool ExportTo(const string &outputFilePath) const;
    bool ExportTo(const wstring &outputFilePath) const;

  private:
    bool GetSystemRoot();

    bool FileIsKernelName(const string &fileName) const;
    void AddModuleToMap(string &fileName, string &filePath);

    string SystemRoot;

    MODULE_MAP_TYPE ModuleLoadedMap;

    bool KernelNameFound;

    static const string         ArrayOfKernelNames[];
    static const vector<string> ListOfKernelNames;
};

namespace StringUtils {
  template <typename strtype> void ToLower(strtype &source) {
    transform(source.begin(), source.end(), source.begin(), ::tolower);
  }

  template <int arraySize> string ToBinaryString(const char (&charArray)[arraySize]) {
    return string(charArray, (arraySize - 1) * sizeof(char));
  }

  template <typename strtype> void ReplaceStringInPlace(strtype &subject, const strtype &search, const strtype &replace) {
    size_t pos = 0;
    while ((pos = subject.find(search, pos)) != std::string::npos) {
      subject.replace(pos, search.length(), replace);
      pos += replace.length();
    }
  }
}