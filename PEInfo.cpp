#include "PEInfo.h"

PEInfo::PEInfo(LPCTSTR szFilePath) {
	hFile = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE) throw std::runtime_error("File could not be opened");

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if(hFileMapping == NULL) throw std::runtime_error("Could not create a file mapping");

	lpFile = (LPBYTE) MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if(lpFile == NULL) throw std::runtime_error("Could not map file view");

	m_imageDosHeader = *(PIMAGE_DOS_HEADER) lpFile;
	m_imageFileHeader = *(PIMAGE_FILE_HEADER) (lpFile + m_imageDosHeader.e_lfanew + sizeof(DWORD));

	DWORD ntSignature = *(PDWORD) (lpFile + m_imageDosHeader.e_lfanew);

	if(m_imageDosHeader.e_magic != IMAGE_DOS_SIGNATURE || ntSignature != IMAGE_NT_SIGNATURE)
		throw std::runtime_error("File is not a valid PE file");

	switch(m_imageFileHeader.Machine) {
		case IMAGE_FILE_MACHINE_AMD64:
			state = Parse64();
			break;
		case IMAGE_FILE_MACHINE_I386:
			state = Parse32();
			break;
		default:
			throw std::runtime_error("File processor type is not supported by the parser");
			break;
	}
}

PEInfo::~PEInfo() {
	if(lpFile) {
		UnmapViewOfFile(lpFile);
		lpFile = NULL;
	}
	if(hFileMapping) {
		CloseHandle(hFileMapping);
		hFileMapping = INVALID_HANDLE_VALUE;
	}
	if(hFile) {
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}
	state = FALSE;
}

BOOL PEInfo::State() {
	return state;
}

BOOL PEInfo::Parse64() {
	m_imageOptHeader = *(PIMAGE_OPTIONAL_HEADER64) (lpFile + m_imageDosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

	PIMAGE_SECTION_HEADER rdataSection = NULL;
	PIMAGE_SECTION_HEADER textSection = NULL;

	PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER) (lpFile + m_imageDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64));
	for(WORD i = 0; i < m_imageFileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER temp;
		memcpy(&temp, &sectionHeaders[i], sizeof(IMAGE_SECTION_HEADER));

		if(!lstrcmpA((LPCSTR) temp.Name, ".rdata")) {
			rdataSection = &sectionHeaders[i];
		} else if(!lstrcmpA((LPCSTR) temp.Name, ".text")) {
			textSection = &sectionHeaders[i];
		}

		m_imageSectionHeaders.push_back(temp);
	}

	INT rdataOffsetOnFile = rdataSection != NULL ? rdataSection->PointerToRawData - rdataSection->VirtualAddress : 0;
	INT codeOffsetOnFile = textSection != NULL ? textSection->PointerToRawData - textSection->VirtualAddress : 0;

	m_imageExportData.SectionSize = m_imageOptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if(m_imageExportData.SectionSize) {
		DWORD directoryRVA = m_imageOptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		m_imageExportData.Directory = *(PIMAGE_EXPORT_DIRECTORY) (lpFile + directoryRVA + rdataOffsetOnFile);
		m_imageExportData.Name.assign((CHAR *) lpFile + m_imageExportData.Directory.Name + rdataOffsetOnFile);

		LPDWORD addressTable = (LPDWORD) (lpFile + m_imageExportData.Directory.AddressOfFunctions + rdataOffsetOnFile);
		LPDWORD namePointerTable = (LPDWORD) (lpFile + m_imageExportData.Directory.AddressOfNames + rdataOffsetOnFile);
		LPWORD ordinalTable = (LPWORD) (lpFile + m_imageExportData.Directory.AddressOfNameOrdinals + rdataOffsetOnFile);

		for(DWORD i = 0; i < m_imageExportData.Directory.NumberOfFunctions; ++i) {
			EXPORT_TABLE_ENTRY temp;
			temp.Ordinal = i;
			temp.OrdinalBiased = i + m_imageExportData.Directory.Base;
			temp.ExportRVA = addressTable[i];
			temp.IsForwarderRVA = (addressTable[i] >= directoryRVA && addressTable[i] <= directoryRVA + m_imageExportData.SectionSize);

			if(temp.IsForwarderRVA) {
				temp.ExportRaw = addressTable[i] + rdataOffsetOnFile;
				temp.Forwarder.assign((LPCSTR) (lpFile + addressTable[i] + rdataOffsetOnFile));
			} else {
				temp.ExportRaw = addressTable[i] + codeOffsetOnFile;
			}

			for(DWORD j = 0; j < m_imageExportData.Directory.NumberOfNames; ++j) {
				if(ordinalTable[j] == i) {
					temp.Name.assign((LPCSTR) (lpFile + namePointerTable[j] + rdataOffsetOnFile));
				}
			}

			m_imageExportData.ExportTable.push_back(temp);
		}
	}

	m_imageImportData.SectionSize = m_imageOptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if(m_imageImportData.SectionSize) {
		DWORD directoryRVA = m_imageOptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		PIMAGE_IMPORT_DESCRIPTOR importEntry = (PIMAGE_IMPORT_DESCRIPTOR) (lpFile + directoryRVA + rdataOffsetOnFile);

		while(importEntry->Characteristics) {
			IMPORT_TABLE_ENTRY temp;
			memcpy(&temp, importEntry, sizeof(IMAGE_IMPORT_DESCRIPTOR));
			temp.Name.assign((LPCSTR) (lpFile + temp.NameRVA + rdataOffsetOnFile));

			PULONGLONG functionEntry = (PULONGLONG) (lpFile + importEntry->OriginalFirstThunk + rdataOffsetOnFile);

			while(*functionEntry) {
				IMPORT_FUNCTION_ENTRY tempFunc;

				if(*functionEntry & IMAGE_ORDINAL_FLAG64) {
					tempFunc.IsImportByOrdinal = TRUE;
					tempFunc.Ordinal = IMAGE_ORDINAL64(*functionEntry);
				} else {
					tempFunc.IsImportByOrdinal = FALSE;
					LPBYTE nameTable = (LPBYTE) (lpFile + (*functionEntry & 0xffffffff) + rdataOffsetOnFile);
					tempFunc.Hint = *((LPWORD) nameTable);
					tempFunc.Name.assign((LPCSTR) (nameTable + sizeof(WORD)));
				}

				temp.Functions.push_back(tempFunc);
				++functionEntry;
			}

			m_imageImportData.ImportTable.push_back(temp);
			++importEntry;
		}
	}


	return TRUE;
}

BOOL PEInfo::Parse32() {
	PIMAGE_OPTIONAL_HEADER32 pImageOptHeader = (PIMAGE_OPTIONAL_HEADER32) (lpFile + m_imageDosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	memcpy(&m_imageOptHeader, pImageOptHeader, (LPBYTE) &pImageOptHeader->BaseOfData - (LPBYTE) pImageOptHeader);
	m_imageOptHeader.ImageBase = pImageOptHeader->ImageBase;
	memcpy(&m_imageOptHeader.SectionAlignment, &pImageOptHeader->SectionAlignment, (LPBYTE) &pImageOptHeader->SizeOfStackReserve - (LPBYTE) &pImageOptHeader->SectionAlignment);
	m_imageOptHeader.SizeOfStackReserve = pImageOptHeader->SizeOfStackReserve;
	m_imageOptHeader.SizeOfStackCommit = pImageOptHeader->SizeOfStackCommit;
	m_imageOptHeader.SizeOfHeapReserve = pImageOptHeader->SizeOfHeapReserve;
	m_imageOptHeader.SizeOfHeapCommit = pImageOptHeader->SizeOfHeapCommit;
	memcpy(&m_imageOptHeader.LoaderFlags, &pImageOptHeader->LoaderFlags, (LPBYTE) &pImageOptHeader->DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (LPBYTE) &pImageOptHeader->LoaderFlags);



	return TRUE;
}