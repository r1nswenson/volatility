#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <assert.h>
#include <iostream>
#include <fstream>

#include "modulesloaded.h"

//==============================================================================
class SystemApiClass {
  public:
    static PVOID GetRoutineAddress(__in CONST WCHAR *systemDll, __in PSTR systemRoutineName) {
      return ::GetProcAddress(::GetModuleHandleW(systemDll), systemRoutineName);
    }

    static PVOID GetNtDllRoutineAddress(__in PSTR systemRoutineName) {
      return GetRoutineAddress(L"ntdll.dll", systemRoutineName);
    }
};

//==============================================================================
class NtDllClass {
  public:
    static NtDllClass* GetInstance();

    typedef NTSTATUS WINAPI NtQuerySystemInformation_t (ULONG SysInfoClass, PVOID SysInfo, ULONG SysInfoLen, PULONG retLen);
    NtQuerySystemInformation_t *_NtQuerySystemInformation;

  private:
    NtDllClass() : _NtQuerySystemInformation(0) {}

    bool Load() {
      _NtQuerySystemInformation = (NtQuerySystemInformation_t *)SystemApiClass::GetNtDllRoutineAddress("NtQuerySystemInformation");
      return IsValid();
    }

    bool IsValid() const {
      return _NtQuerySystemInformation != 0;
    }
};

NtDllClass * NtDllClass::GetInstance() {
  static NtDllClass ntDll;
  if (ntDll.IsValid())
    return &ntDll;
  else {
    if (ntDll.Load())
      return &ntDll;
    else
      return 0;
  }
}

//==============================================================================
using namespace StringUtils;

const string         ModulesLoadedClass::ArrayOfKernelNames[] = {ToBinaryString("ntoskrnl.exe"), ToBinaryString("ntkrnlmp.exe"), ToBinaryString("ntkrnlpa.exe"), ToBinaryString("ntkrpamp.exe")};
const vector<string> ModulesLoadedClass::ListOfKernelNames(ModulesLoadedClass::ArrayOfKernelNames, ModulesLoadedClass::ArrayOfKernelNames + ARRAYSIZE(ModulesLoadedClass::ArrayOfKernelNames));

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
  HANDLE Section;
  PVOID  MappedBase;
  PVOID  ImageBase;
  ULONG  ImageSize;
  ULONG  Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
  ULONG                          NumberOfModules;
  RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

bool ModulesLoadedClass::GetSystemRoot() {
  char systemRoot[MAX_PATH] = {0};
  if (!::GetEnvironmentVariableA("SystemRoot", systemRoot, sizeof(systemRoot))) {
    printf("GetEnvironmentVariableA failed %d\n", ::GetLastError());
    SystemRoot = "\\SystemRoot";
    return false;
  }
  SystemRoot = systemRoot;
  return true;
}

bool ModulesLoadedClass::FileIsKernelName(const string &fileName) const {
  for (vector<string>::const_iterator itr = ListOfKernelNames.begin(); itr != ListOfKernelNames.end(); itr++)
    if (fileName == *itr)
      return true;
  return false;
}

void ModulesLoadedClass::AddModuleToMap(string &fileName, string &filePath) {
  StringUtils::ReplaceStringInPlace<string>(fileName, "\\", "\\\\");
  ToLower(fileName);

  if (!KernelNameFound) {
    if (FileIsKernelName(fileName)) {
      KernelNameFound = true;
      fileName        = "ntoskrnl.exe";
    }
  }

  StringUtils::ReplaceStringInPlace<string>(filePath, "\\SystemRoot", SystemRoot);
  StringUtils::ReplaceStringInPlace<string>(filePath, "\\", "\\\\");
  ToLower(filePath);

  if (ModuleLoadedMap.find(fileName) == ModuleLoadedMap.end())
    ModuleLoadedMap.insert(make_pair(fileName, filePath));
}

bool ModulesLoadedClass::Initialize() {
  assert(!KernelNameFound);

  NtDllClass *ntDll = NtDllClass::GetInstance();
  if (!ntDll)
    return false;

  GetSystemRoot();

  auto_ptr<RTL_PROCESS_MODULES> moduleInfo((RTL_PROCESS_MODULES *)new char[MEGA]);
  if (!moduleInfo.get()) {
    printf("Out of memory\n");
    return false;
  }

  enum {SystemmoduleInformation = 11};
  NTSTATUS status = ntDll->_NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemmoduleInformation, moduleInfo.get(), MEGA, NULL);
  if (!NT_SUCCESS(status)) {
    printf("\nError: Unable to query module list (%#x)\n", status);
    return false;
  }

  for (ULONG i = 0; i < moduleInfo->NumberOfModules; i++) {
    string fileName = (char *)moduleInfo->Modules[i].FullPathName + moduleInfo->Modules[i].OffsetToFileName;
    string filePath = (char *)moduleInfo->Modules[i].FullPathName;
    AddModuleToMap(fileName, filePath);
  }

  return true;
}

bool ModulesLoadedClass::ExportTo(const string &outputFilePath) const {
  assert(ModuleLoadedMap.size());

  ofstream outputFile;
  outputFile.open(outputFilePath, ios::out | ios::trunc | ios::binary);
  if (!outputFile.is_open()) {
    printf("failed to open modules_loaded.json %d\n", ::GetLastError());
    return false;
  }

  outputFile << "{\n";
  for (MODULE_MAP_TYPE::const_iterator itr = ModuleLoadedMap.begin(); itr != ModuleLoadedMap.end(); itr++)
    outputFile << "  \"" << itr->first << "\" : \"" << itr->second << "\",\n";

  outputFile << "  \"done\" : \"done\"\n}";
  return true;
}

bool ModulesLoadedClass::ExportTo(const wstring &outputFilePath) const {
  string outputFile(outputFilePath.begin(), outputFilePath.end());
  return ExportTo(outputFile);
}

//==============================================================================
