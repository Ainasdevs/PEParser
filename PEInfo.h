#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdexcept>
#include <vector>
#include <string>

struct EXPORT_TABLE_ENTRY {
	std::string Name;
	std::string Forwarder;
	DWORD Ordinal;
	DWORD OrdinalBiased;
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
	DWORD   TimeDateStamp;
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

class PEInfo {
public:
	IMAGE_DOS_HEADER m_imageDosHeader;
	IMAGE_FILE_HEADER m_imageFileHeader;
	IMAGE_OPTIONAL_HEADER64 m_imageOptHeader;
	EXPORT_DATA m_imageExportData;
	IMPORT_DATA m_imageImportData;
	// TODO:
	// BASE RELOCATIONS
	// SEH
	// TLS
	std::vector<IMAGE_SECTION_HEADER> m_imageSectionHeaders;

	PEInfo(LPCTSTR szFilePath);
	~PEInfo();
	BOOL State();

private:
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hFileMapping = INVALID_HANDLE_VALUE;
	LPBYTE lpFile = NULL;
	BOOL state = FALSE;

	BOOL Parse64();
	BOOL Parse32();
};

