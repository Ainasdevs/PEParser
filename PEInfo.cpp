#include "PEInfo.h"

PEInfo::PEInfo(LPCTSTR szFilePath) {
	hFile = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE) throw std::runtime_error("File could not be opened");

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if(hFileMapping == NULL) throw std::runtime_error("Could not create a file mapping");

	lpFile = (LPBYTE) MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if(lpFile == NULL) throw std::runtime_error("Could not map file view");

	PEInfo::PEInfo(lpFile);
	Close();
}

PEInfo::PEInfo(LPBYTE lpFileBuffer) {
	Parse(lpFileBuffer);
}

PEInfo::~PEInfo() {
	Close();
	state = FALSE;
}

VOID PEInfo::Close() {
	if(lpFile) {
		UnmapViewOfFile(lpFile);
		lpFile = NULL;
	}
	if(hFileMapping && hFileMapping != INVALID_HANDLE_VALUE) {
		CloseHandle(hFileMapping);
		hFileMapping = INVALID_HANDLE_VALUE;
	}
	if(hFile && hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}
}

BOOL PEInfo::State() {
	return state;
}

VOID PEInfo::Parse(LPBYTE lpFileBuffer) {
	DosHeader = *(PIMAGE_DOS_HEADER) lpFileBuffer;
	FileHeader = *(PIMAGE_FILE_HEADER) (lpFileBuffer + DosHeader.e_lfanew + sizeof(DWORD));

	DWORD ntSignature = *(PDWORD) (lpFileBuffer + DosHeader.e_lfanew);

	if(DosHeader.e_magic != IMAGE_DOS_SIGNATURE || ntSignature != IMAGE_NT_SIGNATURE)
		throw std::runtime_error("File is not a valid PE file");

	switch(FileHeader.Machine) {
		case IMAGE_FILE_MACHINE_AMD64:
			state = Parse64(lpFileBuffer);
			break;
		case IMAGE_FILE_MACHINE_I386:
			state = Parse32(lpFileBuffer);
			break;
		default:
			throw std::runtime_error("File processor type is not supported by the parser");
			break;
	}
}

BOOL PEInfo::Parse64(LPBYTE lpFile) {
	OptHeader = *(PIMAGE_OPTIONAL_HEADER64) (lpFile + DosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

	PIMAGE_SECTION_HEADER rdataSection = NULL;
	PIMAGE_SECTION_HEADER textSection = NULL;
	PIMAGE_SECTION_HEADER relocSection = NULL;
	PIMAGE_SECTION_HEADER pdataSection = NULL;

	PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER) (lpFile + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64));
	for(WORD i = 0; i < FileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER temp;
		memcpy(&temp, &sectionHeaders[i], sizeof(IMAGE_SECTION_HEADER));

		if(!lstrcmpA((LPCSTR) temp.Name, ".rdata")) {
			rdataSection = &sectionHeaders[i];
		} else if(!lstrcmpA((LPCSTR) temp.Name, ".text")) {
			textSection = &sectionHeaders[i];
		} else if(!lstrcmpA((LPCSTR) temp.Name, ".reloc")) {
			relocSection = &sectionHeaders[i];
		} else if(!lstrcmpA((LPCSTR) temp.Name, ".pdata")) {
			pdataSection = &sectionHeaders[i];
		}

		SectionHeaders.push_back(temp);
	}

	INT rdataOffsetOnFile = rdataSection != NULL ? rdataSection->PointerToRawData - rdataSection->VirtualAddress : 0;
	INT codeOffsetOnFile = textSection != NULL ? textSection->PointerToRawData - textSection->VirtualAddress : 0;
	INT relocOffsetOnFile = relocSection != NULL ? relocSection->PointerToRawData - relocSection->VirtualAddress : 0;
	INT pdataOffsetOnFile = pdataSection != NULL ? pdataSection->PointerToRawData - pdataSection->VirtualAddress : 0;

	ExportData.sectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT && ExportData.sectionSize) {
		DWORD directoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		ExportData.directory = *(PIMAGE_EXPORT_DIRECTORY) (lpFile + directoryRVA + rdataOffsetOnFile);
		ExportData.name.assign((CHAR *) lpFile + ExportData.directory.Name + rdataOffsetOnFile);

		LPDWORD addressTable = (LPDWORD) (lpFile + ExportData.directory.AddressOfFunctions + rdataOffsetOnFile);
		LPDWORD namePointerTable = (LPDWORD) (lpFile + ExportData.directory.AddressOfNames + rdataOffsetOnFile);
		LPWORD ordinalTable = (LPWORD) (lpFile + ExportData.directory.AddressOfNameOrdinals + rdataOffsetOnFile);

		for(DWORD i = 0; i < ExportData.directory.NumberOfFunctions; ++i) {
			EXPORT_TABLE_ENTRY temp;
			temp.ordinal = i;
			temp.ordinalBased = i + ExportData.directory.Base;
			temp.exportRVA = addressTable[i];
			temp.isForwarderRVA = (addressTable[i] >= directoryRVA && addressTable[i] <= directoryRVA + ExportData.sectionSize);

			if(temp.isForwarderRVA) {
				temp.exportRaw = addressTable[i] + rdataOffsetOnFile;
				temp.forwarder.assign((LPCSTR) (lpFile + addressTable[i] + rdataOffsetOnFile));
			} else {
				temp.exportRaw = addressTable[i] + codeOffsetOnFile;
			}

			for(DWORD j = 0; j < ExportData.directory.NumberOfNames; ++j) {
				if(ordinalTable[j] == i) {
					temp.name.assign((LPCSTR) (lpFile + namePointerTable[j] + rdataOffsetOnFile));
				}
			}

			ExportData.exportTable.push_back(temp);
		}
	}

	ImportData.sectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT && ImportData.sectionSize) {
		DWORD directoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		PIMAGE_IMPORT_DESCRIPTOR importEntry = (PIMAGE_IMPORT_DESCRIPTOR) (lpFile + directoryRVA + rdataOffsetOnFile);

		while(importEntry->Characteristics) {
			IMPORT_TABLE_ENTRY temp;
			memcpy(&temp, importEntry, sizeof(IMAGE_IMPORT_DESCRIPTOR));
			temp.name.assign((LPCSTR) (lpFile + temp.nameRVA + rdataOffsetOnFile));

			PULONGLONG functionEntry = (PULONGLONG) (lpFile + importEntry->OriginalFirstThunk + rdataOffsetOnFile);

			while(*functionEntry) {
				IMPORT_FUNCTION_ENTRY tempFunc;

				if(*functionEntry & IMAGE_ORDINAL_FLAG64) {
					tempFunc.isImportByOrdinal = TRUE;
					tempFunc.ordinal = IMAGE_ORDINAL64(*functionEntry);
				} else {
					tempFunc.isImportByOrdinal = FALSE;
					LPBYTE nameTable = (LPBYTE) (lpFile + (*functionEntry & 0xffffffff) + rdataOffsetOnFile);
					tempFunc.hint = *((LPWORD) nameTable);
					tempFunc.name.assign((LPCSTR) (nameTable + sizeof(WORD)));
				}

				temp.functions.push_back(tempFunc);
				++functionEntry;
			}

			ImportData.importTable.push_back(temp);
			++importEntry;
		}
	}

	RelocData.sectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC && RelocData.sectionSize) {
		DWORD directoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION) (lpFile + directoryRVA + relocOffsetOnFile);

		DWORD blockSize;
		for(DWORD sz = RelocData.sectionSize; sz > 0; sz -= blockSize) {
			blockSize = reloc->SizeOfBlock;
			PWORD relocations = (PWORD) (reloc + 1); // right after relocation block header

			for(DWORD i = 0; i < (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++i) {
				BASERELOC_TABLE_ENTRY temp;
				temp.type = relocations[i] >> 12;

				if(temp.type == IMAGE_REL_BASED_ABSOLUTE) continue;

				temp.offset = reloc->VirtualAddress + (relocations[i] & 0x0FFF);
				RelocData.baserelocTable.push_back(temp);
			}
			reloc = (PIMAGE_BASE_RELOCATION) ((LPBYTE) reloc + blockSize);
		}
	}

	SehData.sectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION && SehData.sectionSize) {
		DWORD directoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;

		PDWORD entry = (PDWORD)(lpFile + directoryRVA + pdataOffsetOnFile);
		for(int i = 0; i < SehData.sectionSize / (3 * sizeof(DWORD)); ++i) {
			SEH_TABLE_ENTRY temp;
			temp.beginRVA = *(entry++);
			temp.endRVA = *(entry++);
			temp.unwindRVA = *(entry++);
			SehData.sehTable.push_back(temp);
		}
	}

	return TRUE;
}

BOOL PEInfo::Parse32(LPBYTE lpFile) {
	PIMAGE_OPTIONAL_HEADER32 pImageOptHeader = (PIMAGE_OPTIONAL_HEADER32) (lpFile + DosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	memcpy(&OptHeader, pImageOptHeader, (LPBYTE) &pImageOptHeader->BaseOfData - (LPBYTE) pImageOptHeader);
	OptHeader.ImageBase = pImageOptHeader->ImageBase;
	memcpy(&OptHeader.SectionAlignment, &pImageOptHeader->SectionAlignment, (LPBYTE) &pImageOptHeader->SizeOfStackReserve - (LPBYTE) &pImageOptHeader->SectionAlignment);
	OptHeader.SizeOfStackReserve = pImageOptHeader->SizeOfStackReserve;
	OptHeader.SizeOfStackCommit = pImageOptHeader->SizeOfStackCommit;
	OptHeader.SizeOfHeapReserve = pImageOptHeader->SizeOfHeapReserve;
	OptHeader.SizeOfHeapCommit = pImageOptHeader->SizeOfHeapCommit;
	memcpy(&OptHeader.LoaderFlags, &pImageOptHeader->LoaderFlags, (LPBYTE) &pImageOptHeader->DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (LPBYTE) &pImageOptHeader->LoaderFlags);

	PIMAGE_SECTION_HEADER rdataSection = NULL;
	PIMAGE_SECTION_HEADER textSection = NULL;
	PIMAGE_SECTION_HEADER relocSection = NULL;
	PIMAGE_SECTION_HEADER pdataSection = NULL;

	PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER) (lpFile + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	for(WORD i = 0; i < FileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER temp;
		memcpy(&temp, &sectionHeaders[i], sizeof(IMAGE_SECTION_HEADER));

		if(!lstrcmpA((LPCSTR) temp.Name, ".rdata")) {
			rdataSection = &sectionHeaders[i];
		} else if(!lstrcmpA((LPCSTR) temp.Name, ".text")) {
			textSection = &sectionHeaders[i];
		} else if(!lstrcmpA((LPCSTR) temp.Name, ".reloc")) {
			relocSection = &sectionHeaders[i];
		} else if(!lstrcmpA((LPCSTR) temp.Name, ".pdata")) {
			pdataSection = &sectionHeaders[i];
		}

		SectionHeaders.push_back(temp);
	}

	INT rdataOffsetOnFile = rdataSection != NULL ? rdataSection->PointerToRawData - rdataSection->VirtualAddress : 0;
	INT codeOffsetOnFile = textSection != NULL ? textSection->PointerToRawData - textSection->VirtualAddress : 0;
	INT relocOffsetOnFile = relocSection != NULL ? relocSection->PointerToRawData - relocSection->VirtualAddress : 0;
	INT pdataOffsetOnFile = pdataSection != NULL ? pdataSection->PointerToRawData - pdataSection->VirtualAddress : 0;

	ExportData.sectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT && ExportData.sectionSize) {
		DWORD directoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		ExportData.directory = *(PIMAGE_EXPORT_DIRECTORY) (lpFile + directoryRVA + rdataOffsetOnFile);
		ExportData.name.assign((CHAR *) lpFile + ExportData.directory.Name + rdataOffsetOnFile);

		LPDWORD addressTable = (LPDWORD) (lpFile + ExportData.directory.AddressOfFunctions + rdataOffsetOnFile);
		LPDWORD namePointerTable = (LPDWORD) (lpFile + ExportData.directory.AddressOfNames + rdataOffsetOnFile);
		LPWORD ordinalTable = (LPWORD) (lpFile + ExportData.directory.AddressOfNameOrdinals + rdataOffsetOnFile);

		for(DWORD i = 0; i < ExportData.directory.NumberOfFunctions; ++i) {
			EXPORT_TABLE_ENTRY temp;
			temp.ordinal = i;
			temp.ordinalBased = i + ExportData.directory.Base;
			temp.exportRVA = addressTable[i];
			temp.isForwarderRVA = (addressTable[i] >= directoryRVA && addressTable[i] <= directoryRVA + ExportData.sectionSize);

			if(temp.isForwarderRVA) {
				temp.exportRaw = addressTable[i] + rdataOffsetOnFile;
				temp.forwarder.assign((LPCSTR) (lpFile + addressTable[i] + rdataOffsetOnFile));
			} else {
				temp.exportRaw = addressTable[i] + codeOffsetOnFile;
			}

			for(DWORD j = 0; j < ExportData.directory.NumberOfNames; ++j) {
				if(ordinalTable[j] == i) {
					temp.name.assign((LPCSTR) (lpFile + namePointerTable[j] + rdataOffsetOnFile));
				}
			}

			ExportData.exportTable.push_back(temp);
		}
	}

	ImportData.sectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT && ImportData.sectionSize) {
		DWORD directoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		PIMAGE_IMPORT_DESCRIPTOR importEntry = (PIMAGE_IMPORT_DESCRIPTOR) (lpFile + directoryRVA + rdataOffsetOnFile);

		while(importEntry->Characteristics) {
			IMPORT_TABLE_ENTRY temp;
			memcpy(&temp, importEntry, sizeof(IMAGE_IMPORT_DESCRIPTOR));
			temp.name.assign((LPCSTR) (lpFile + temp.nameRVA + rdataOffsetOnFile));

			PULONG functionEntry = (PULONG) (lpFile + importEntry->OriginalFirstThunk + rdataOffsetOnFile);

			while(*functionEntry) {
				IMPORT_FUNCTION_ENTRY tempFunc;

				if(*functionEntry & IMAGE_ORDINAL_FLAG32) {
					tempFunc.isImportByOrdinal = TRUE;
					tempFunc.ordinal = IMAGE_ORDINAL32(*functionEntry);
				} else {
					tempFunc.isImportByOrdinal = FALSE;
					LPBYTE nameTable = (LPBYTE) (lpFile + (*functionEntry) + rdataOffsetOnFile);
					tempFunc.hint = *((LPWORD) nameTable);
					tempFunc.name.assign((LPCSTR) (nameTable + sizeof(WORD)));
				}

				temp.functions.push_back(tempFunc);
				++functionEntry;
			}

			ImportData.importTable.push_back(temp);
			++importEntry;
		}
	}

	RelocData.sectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC && RelocData.sectionSize) {
		DWORD directoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION) (lpFile + directoryRVA + relocOffsetOnFile);

		DWORD blockSize;
		for(DWORD sz = RelocData.sectionSize; sz > 0; sz -= blockSize) {
			blockSize = reloc->SizeOfBlock;
			PWORD relocations = (PWORD) (reloc + 1); // right after relocation block header

			for(DWORD i = 0; i < (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++i) {
				BASERELOC_TABLE_ENTRY temp;
				temp.type = relocations[i] >> 12;

				if(temp.type == IMAGE_REL_BASED_ABSOLUTE) continue;

				temp.offset = reloc->VirtualAddress + (relocations[i] & 0x0FFF);
				RelocData.baserelocTable.push_back(temp);
			}
			reloc = (PIMAGE_BASE_RELOCATION) ((LPBYTE) reloc + blockSize);
		}
	}

	return TRUE;
}