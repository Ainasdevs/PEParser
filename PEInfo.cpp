#include "PEInfo.h"
#include <shlobj_core.h>
#include <stdexcept>

PEInfo::PEInfo(LPCTSTR szFilePath) {
	hFile = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE) throw std::runtime_error("File could not be opened");

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if(hFileMapping == NULL) throw std::runtime_error("Could not create a file mapping");

	lpFile = (LPBYTE) MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if(lpFile == NULL) throw std::runtime_error("Could not map file view");

	Parse(lpFile);
	Close();
}

PEInfo::PEInfo(LPBYTE lpFileBuffer) {
	Parse(lpFileBuffer);
	Close();
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

	PIMAGE_SECTION_HEADER pCodeSection = NULL;

	PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER) (lpFile + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64));
	for(WORD i = 0; i < FileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER temp;
		memcpy(&temp, &sectionHeaders[i], sizeof(IMAGE_SECTION_HEADER));

		if(!strcmp((LPCSTR) temp.Name, ".text")) {
			pCodeSection = &sectionHeaders[i];
		}

		SectionHeaders.push_back(temp);
	}

	INT iCodeOffsetOnFile = pCodeSection != NULL ? pCodeSection->PointerToRawData - pCodeSection->VirtualAddress : 0;

	ExportData.SectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT && ExportData.SectionSize) {
		DWORD dwDirectoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		PIMAGE_SECTION_HEADER pSection = GetSectionOfRVA(dwDirectoryRVA);
		INT iSectionOffset = pSection->PointerToRawData - pSection->VirtualAddress;

		ExportData.Directory = *(PIMAGE_EXPORT_DIRECTORY) (lpFile + dwDirectoryRVA + iSectionOffset);
		ExportData.Name.assign((CHAR *) lpFile + ExportData.Directory.Name + iSectionOffset);

		LPDWORD addressTable = (LPDWORD) (lpFile + ExportData.Directory.AddressOfFunctions + iSectionOffset);
		LPDWORD namePointerTable = (LPDWORD) (lpFile + ExportData.Directory.AddressOfNames + iSectionOffset);
		LPWORD ordinalTable = (LPWORD) (lpFile + ExportData.Directory.AddressOfNameOrdinals + iSectionOffset);

		for(DWORD i = 0; i < ExportData.Directory.NumberOfFunctions; ++i) {
			EXPORT_TABLE_ENTRY temp;
			temp.Ordinal = i;
			temp.OrdinalBased = i + ExportData.Directory.Base;
			temp.ExportRVA = addressTable[i];
			temp.IsForwarderRVA = (addressTable[i] >= dwDirectoryRVA && addressTable[i] < dwDirectoryRVA + ExportData.SectionSize);

			if(temp.IsForwarderRVA) {
				temp.ExportRaw = addressTable[i] + iSectionOffset;

				LPSTR szForwarder = (LPSTR) (lpFile + addressTable[i] + iSectionOffset);
				const CHAR *separator = strchr(szForwarder, '.');

				temp.ForwarderDll.assign(szForwarder, separator - szForwarder).append(".dll");
				temp.ForwarderFunc.assign(separator + 1);
			} else {
				temp.ExportRaw = addressTable[i] + iCodeOffsetOnFile;
			}

			for(DWORD j = 0; j < ExportData.Directory.NumberOfNames; ++j) {
				if(ordinalTable[j] == i) {
					temp.Name.assign((LPCSTR) (lpFile + namePointerTable[j] + iSectionOffset));
				}
			}

			ExportData.ExportTable.push_back(temp);
		}
	}

	ImportData.SectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT && ImportData.SectionSize) {
		DWORD dwDirectoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		PIMAGE_SECTION_HEADER pSection = GetSectionOfRVA(dwDirectoryRVA);
		INT iSectionOffset = pSection->PointerToRawData - pSection->VirtualAddress;

		PIMAGE_IMPORT_DESCRIPTOR importEntry = (PIMAGE_IMPORT_DESCRIPTOR) (lpFile + dwDirectoryRVA + iSectionOffset);

		while(importEntry->Characteristics) {
			IMPORT_TABLE_ENTRY temp;
			memcpy(&temp, importEntry, sizeof(IMAGE_IMPORT_DESCRIPTOR));
			temp.Name.assign((LPCSTR) (lpFile + temp.NameRVA + iSectionOffset));

			PULONGLONG functionEntry = (PULONGLONG) (lpFile + importEntry->OriginalFirstThunk + iSectionOffset);

			while(*functionEntry) {
				IMPORT_FUNCTION_ENTRY tempFunc;

				if(*functionEntry & IMAGE_ORDINAL_FLAG64) {
					tempFunc.IsImportByOrdinal = TRUE;
					tempFunc.Ordinal = IMAGE_ORDINAL64(*functionEntry);
				} else {
					tempFunc.IsImportByOrdinal = FALSE;
					LPBYTE nameTable = (LPBYTE) (lpFile + (*functionEntry & 0xffffffff) + iSectionOffset);
					tempFunc.Hint = *((LPWORD) nameTable);
					tempFunc.Name.assign((LPCSTR) (nameTable + sizeof(WORD)));
				}

				temp.Functions.push_back(tempFunc);
				++functionEntry;
			}

			ImportData.ImportTable.push_back(temp);
			++importEntry;
		}
	}

	RelocData.SectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC && RelocData.SectionSize) {
		DWORD dwDirectoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		PIMAGE_SECTION_HEADER pSection = GetSectionOfRVA(dwDirectoryRVA);
		INT iSectionOffset = pSection->PointerToRawData - pSection->VirtualAddress;

		PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION) (lpFile + dwDirectoryRVA + iSectionOffset);

		DWORD blockSize;
		for(DWORD sz = RelocData.SectionSize; sz > 0; sz -= blockSize) {
			blockSize = reloc->SizeOfBlock;
			PWORD relocations = (PWORD) (reloc + 1); // right after relocation block header

			for(DWORD i = 0; i < (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++i) {
				BASERELOC_TABLE_ENTRY temp;
				temp.Type = relocations[i] >> 12;

				if(temp.Type == IMAGE_REL_BASED_ABSOLUTE) continue;

				temp.RVA = reloc->VirtualAddress + (relocations[i] & 0x0FFF);
				RelocData.BaserelocTable.push_back(temp);
			}
			reloc = (PIMAGE_BASE_RELOCATION) ((LPBYTE) reloc + blockSize);
		}
	}

	SehData.SectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION && SehData.SectionSize) {
		DWORD dwDirectoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
		PIMAGE_SECTION_HEADER pSection = GetSectionOfRVA(dwDirectoryRVA);
		INT iSectionOffset = pSection->PointerToRawData - pSection->VirtualAddress;

		PDWORD entry = (PDWORD)(lpFile + dwDirectoryRVA + iSectionOffset);
		for(int i = 0; i < SehData.SectionSize / (3 * sizeof(DWORD)); ++i) {
			SEH_TABLE_ENTRY temp;
			temp.BeginRVA = *(entry++);
			temp.EndRVA = *(entry++);
			temp.UnwindRVA = *(entry++);
			SehData.SehTable.push_back(temp);
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

	PIMAGE_SECTION_HEADER pCodeSection = NULL;

	PIMAGE_SECTION_HEADER pSectionHeaders = (PIMAGE_SECTION_HEADER) (lpFile + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	for(WORD i = 0; i < FileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER temp;
		memcpy(&temp, &pSectionHeaders[i], sizeof(IMAGE_SECTION_HEADER));

		if(!strcmp((LPCSTR) temp.Name, ".text")) {
			pCodeSection = &pSectionHeaders[i];
		}

		SectionHeaders.push_back(temp);
	}

	INT iCodeOffsetOnFile = pCodeSection != NULL ? pCodeSection->PointerToRawData - pCodeSection->VirtualAddress : 0;

	ExportData.SectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT && ExportData.SectionSize) {
		DWORD dwDirectoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		PIMAGE_SECTION_HEADER pSection = GetSectionOfRVA(dwDirectoryRVA);
		INT iSectionOffset = pSection->PointerToRawData - pSection->VirtualAddress;

		ExportData.Directory = *(PIMAGE_EXPORT_DIRECTORY) (lpFile + dwDirectoryRVA + iSectionOffset);
		ExportData.Name.assign((CHAR *) lpFile + ExportData.Directory.Name + iSectionOffset);

		LPDWORD lpAddressTable = (LPDWORD) (lpFile + ExportData.Directory.AddressOfFunctions + iSectionOffset);
		LPDWORD lpNamePointerTable = (LPDWORD) (lpFile + ExportData.Directory.AddressOfNames + iSectionOffset);
		LPWORD lpOrdinalTable = (LPWORD) (lpFile + ExportData.Directory.AddressOfNameOrdinals + iSectionOffset);

		for(DWORD i = 0; i < ExportData.Directory.NumberOfFunctions; ++i) {
			EXPORT_TABLE_ENTRY temp;
			temp.Ordinal = i;
			temp.OrdinalBased = i + ExportData.Directory.Base;
			temp.ExportRVA = lpAddressTable[i];
			temp.IsForwarderRVA = (lpAddressTable[i] >= dwDirectoryRVA && lpAddressTable[i] < dwDirectoryRVA + ExportData.SectionSize);

			if(temp.IsForwarderRVA) {
				temp.ExportRaw = lpAddressTable[i] + iSectionOffset;

				LPSTR szForwarder = (LPSTR) (lpFile + lpAddressTable[i] + iSectionOffset);
				const CHAR *separator = strchr(szForwarder, '.');

				temp.ForwarderDll.assign(szForwarder, separator - szForwarder).append(".dll");
				temp.ForwarderFunc.assign(separator + 1);
			} else {
				temp.ExportRaw = lpAddressTable[i] + iCodeOffsetOnFile; // 0x001842f0
			}

			for(DWORD j = 0; j < ExportData.Directory.NumberOfNames; ++j) {
				if(lpOrdinalTable[j] == i) {
					temp.Name.assign((LPCSTR) (lpFile + lpNamePointerTable[j] + iSectionOffset));
				}
			}

			ExportData.ExportTable.push_back(temp);
		}
	}

	ImportData.SectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT && ImportData.SectionSize) {
		DWORD dwDirectoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		PIMAGE_SECTION_HEADER pSection = GetSectionOfRVA(dwDirectoryRVA);
		INT iSectionOffset = pSection->PointerToRawData - pSection->VirtualAddress;

		PIMAGE_IMPORT_DESCRIPTOR lpImportEntry = (PIMAGE_IMPORT_DESCRIPTOR) (lpFile + dwDirectoryRVA + iSectionOffset);

		while(lpImportEntry->Characteristics) {
			IMPORT_TABLE_ENTRY temp;
			memcpy(&temp, lpImportEntry, sizeof(IMAGE_IMPORT_DESCRIPTOR));
			temp.Name.assign((LPCSTR) (lpFile + temp.NameRVA + iSectionOffset));

			PULONG pFunctionEntry = (PULONG) (lpFile + lpImportEntry->OriginalFirstThunk + iSectionOffset);

			while(*pFunctionEntry) {
				IMPORT_FUNCTION_ENTRY tempFunc;

				if(*pFunctionEntry & IMAGE_ORDINAL_FLAG32) {
					tempFunc.IsImportByOrdinal = TRUE;
					tempFunc.Ordinal = IMAGE_ORDINAL32(*pFunctionEntry);
				} else {
					tempFunc.IsImportByOrdinal = FALSE;
					LPBYTE nameTable = (LPBYTE) (lpFile + (*pFunctionEntry) + iSectionOffset);
					tempFunc.Hint = *((LPWORD) nameTable);
					tempFunc.Name.assign((LPCSTR) (nameTable + sizeof(WORD)));
				}

				temp.Functions.push_back(tempFunc);
				++pFunctionEntry;
			}

			ImportData.ImportTable.push_back(temp);
			++lpImportEntry;
		}
	}

	RelocData.SectionSize = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if(OptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC && RelocData.SectionSize) {
		DWORD dwDirectoryRVA = OptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		PIMAGE_SECTION_HEADER pSection = GetSectionOfRVA(dwDirectoryRVA);
		INT iSectionOffset = pSection->PointerToRawData - pSection->VirtualAddress;

		PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION) (lpFile + dwDirectoryRVA + iSectionOffset);

		DWORD dwBlockSize;
		for(DWORD sz = RelocData.SectionSize; sz > 0; sz -= dwBlockSize) {
			dwBlockSize = pReloc->SizeOfBlock;
			PWORD relocations = (PWORD) (pReloc + 1); // right after relocation block header

			for(DWORD i = 0; i < (dwBlockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++i) {
				BASERELOC_TABLE_ENTRY temp;
				temp.Type = relocations[i] >> 12;

				if(temp.Type == IMAGE_REL_BASED_ABSOLUTE) continue;

				temp.RVA = pReloc->VirtualAddress + (relocations[i] & 0x0FFF);
				RelocData.BaserelocTable.push_back(temp);
			}
			pReloc = (PIMAGE_BASE_RELOCATION) ((LPBYTE) pReloc + dwBlockSize);
		}
	}

	return TRUE;
}

IMAGE_SECTION_HEADER *PEInfo::GetSection(LPCSTR szSectionName) {
	for(INT i = 0; i < SectionHeaders.size(); i++) {
		if(!strcmp(szSectionName, (LPCSTR) SectionHeaders[i].Name)) {
			return &SectionHeaders[i];
		}
	}

	return NULL;
}

IMAGE_SECTION_HEADER *PEInfo::GetSectionOfRVA(DWORD RVA) {
	for(DWORD i = 0; i < SectionHeaders.size(); i++) {
		if(RVA >= SectionHeaders[i].VirtualAddress && RVA < SectionHeaders[i].VirtualAddress + SectionHeaders[i].SizeOfRawData) {
			return &SectionHeaders[i];
		}
	}

	return NULL;
}

EXPORT_TABLE_ENTRY *PEInfo::GetExport(std::string functionName) {
	for(INT i = 0; i < ExportData.ExportTable.size(); i++) {
		EXPORT_TABLE_ENTRY &entry = ExportData.ExportTable[i];
		if(entry.Name == functionName) {
			return &entry;
		}
	}

	return NULL;
}