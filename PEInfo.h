#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <shlobj_core.h>
#include <stdexcept>
#include <vector>
#include <string>
#include <sstream>
#include <cstdio>

#pragma warning(disable:26495)
struct EXPORT_TABLE_ENTRY {
	std::string Name;
	std::string Forwarder;
	DWORD Ordinal;
	DWORD OrdinalBased;
	union {
		DWORD ExportRVA;
		DWORD ForwarderRVA;
	};
	DWORD ExportRaw;
	BOOL IsForwarderRVA;
};

struct EXPORT_DATA {
	IMAGE_EXPORT_DIRECTORY Directory;
	std::vector<EXPORT_TABLE_ENTRY> ExportTable;
	std::string Name;
	DWORD SectionSize;
};

struct IMPORT_FUNCTION_ENTRY {
	std::string Name;
	WORD Hint;
	DWORD Ordinal;
	BOOL IsImportByOrdinal = 0;
};

struct IMPORT_TABLE_ENTRY {
	union {
		DWORD   Characteristics;
		DWORD   OriginalFirstThunk;
	};
	DWORD   Timestamp;
	DWORD   ForwarderChain;
	DWORD   NameRVA;
	DWORD   FirstThunk;
	std::string Name;
	std::vector<IMPORT_FUNCTION_ENTRY> Functions;
};

struct IMPORT_DATA {
	std::vector<IMPORT_TABLE_ENTRY> ImportTable;
	DWORD SectionSize;
};

struct BASERELOC_TABLE_ENTRY {
	BYTE Type;
	DWORD RVA;
};

struct BASERELOC_DATA {
	std::vector<BASERELOC_TABLE_ENTRY> BaserelocTable;
	DWORD SectionSize;
};

struct SEH_TABLE_ENTRY {
	DWORD BeginRVA;
	DWORD EndRVA;
	DWORD UnwindRVA;
};

struct SEH_DATA {
	std::vector<SEH_TABLE_ENTRY> SehTable;
	DWORD SectionSize;
};
#pragma warning(default:26495)

class PEInfo {
public:
	IMAGE_DOS_HEADER DosHeader;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptHeader;
	EXPORT_DATA ExportData;
	IMPORT_DATA ImportData;
	BASERELOC_DATA RelocData;
	SEH_DATA SehData;
	// TODO:
	// TLS
	std::vector<IMAGE_SECTION_HEADER> SectionHeaders;

	PEInfo(LPCTSTR szFilePath);
	PEInfo(LPBYTE lpFileBuffer);
	PEInfo() = default;
	~PEInfo();

	IMAGE_SECTION_HEADER *GetSection(LPCSTR szSectionName);
	EXPORT_TABLE_ENTRY *GetExport(std::string Name);
	VOID Parse(LPBYTE lpFileBuffer);
	VOID Close();

	BOOL State();

private:
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hFileMapping = INVALID_HANDLE_VALUE;
	LPBYTE lpFile = NULL;
	BOOL state = FALSE;

	BOOL Parse64(LPBYTE lpFile);
	BOOL Parse32(LPBYTE lpFile);
};