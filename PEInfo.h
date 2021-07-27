#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdexcept>
#include <vector>
#include <string>
#include <sstream>
#include <cstdio>

class PEInfo {
#pragma warning(disable:26495)
struct EXPORT_TABLE_ENTRY {
	std::string name;
	std::string forwarder;
	DWORD ordinal;
	DWORD ordinalBased;
	union {
		DWORD exportRVA;
		DWORD forwarderRVA;
	};
	DWORD exportRaw;
	BOOL isForwarderRVA;
};

struct EXPORT_DATA {
	IMAGE_EXPORT_DIRECTORY directory;
	std::vector<EXPORT_TABLE_ENTRY> exportTable;
	std::string name;
	DWORD sectionSize{};
};

struct IMPORT_FUNCTION_ENTRY {
	std::string name;
	WORD hint;
	DWORD ordinal;
	BOOL isImportByOrdinal = 0;
};

struct IMPORT_TABLE_ENTRY {
	union {
		DWORD   characteristics;
		DWORD   originalFirstThunk;
	};
	DWORD   timestamp;
	DWORD   forwarderChain;
	DWORD   nameRVA;
	DWORD   firstThunk;
	std::string name;
	std::vector<IMPORT_FUNCTION_ENTRY> functions;
};

struct IMPORT_DATA {
	std::vector<IMPORT_TABLE_ENTRY> importTable;
	DWORD sectionSize;
};

struct BASERELOC_TABLE_ENTRY {
	BYTE type;
	DWORD offset;
};

struct BASERELOC_DATA {
	std::vector<BASERELOC_TABLE_ENTRY> baserelocTable;
	DWORD sectionSize;
};

struct SEH_TABLE_ENTRY {
	DWORD beginRVA;
	DWORD endRVA;
	DWORD unwindRVA;
};

struct SEH_DATA {
	std::vector<SEH_TABLE_ENTRY> sehTable;
	DWORD sectionSize;
};
#pragma warning(default:26495)

public:
	IMAGE_DOS_HEADER imageDosHeader;
	IMAGE_FILE_HEADER imageFileHeader;
	IMAGE_OPTIONAL_HEADER64 imageOptHeader;
	EXPORT_DATA imageExportData;
	IMPORT_DATA imageImportData;
	BASERELOC_DATA imageRelocData;
	SEH_DATA imageSehData;
	// TODO:
	// TLS
	std::vector<IMAGE_SECTION_HEADER> imageSectionHeaders;

	PEInfo(LPCTSTR szFilePath);
	~PEInfo();

	VOID Close();

	BOOL getState();

private:
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hFileMapping = INVALID_HANDLE_VALUE;
	LPBYTE lpFile = NULL;
	BOOL state = FALSE;

	BOOL Parse64();
	BOOL Parse32();
};