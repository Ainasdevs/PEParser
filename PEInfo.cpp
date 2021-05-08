#include "PEInfo.h"

PEInfo::PEInfo(LPCTSTR szFilePath) {
	hFile = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE) throw std::runtime_error("File could not be opened");

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if(hFileMapping == NULL) throw std::runtime_error("Could not create a file mapping");

	lpFile = (LPBYTE) MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if(lpFile == NULL) throw std::runtime_error("Could not map file view");

	imageDosHeader = *(PIMAGE_DOS_HEADER) lpFile;
	imageFileHeader = *(PIMAGE_FILE_HEADER) (lpFile + imageDosHeader.e_lfanew + sizeof(DWORD));

	DWORD ntSignature = *(PDWORD) (lpFile + imageDosHeader.e_lfanew);

	if(imageDosHeader.e_magic != IMAGE_DOS_SIGNATURE || ntSignature != IMAGE_NT_SIGNATURE)
		throw std::runtime_error("File is not a valid PE file");

	switch(imageFileHeader.Machine) {
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
	if(hFileMapping) {
		CloseHandle(hFileMapping);
		hFileMapping = INVALID_HANDLE_VALUE;
	}
	if(hFile) {
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}
}

BOOL PEInfo::getState() {
	return state;
}

BOOL PEInfo::Parse64() {
	imageOptHeader = *(PIMAGE_OPTIONAL_HEADER64) (lpFile + imageDosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

	PIMAGE_SECTION_HEADER rdataSection = NULL;
	PIMAGE_SECTION_HEADER textSection = NULL;
	PIMAGE_SECTION_HEADER relocSection = NULL;
	PIMAGE_SECTION_HEADER pdataSection = NULL;

	PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER) (lpFile + imageDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64));
	for(WORD i = 0; i < imageFileHeader.NumberOfSections; ++i) {
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

		imageSectionHeaders.push_back(temp);
	}

	INT rdataOffsetOnFile = rdataSection != NULL ? rdataSection->PointerToRawData - rdataSection->VirtualAddress : 0;
	INT codeOffsetOnFile = textSection != NULL ? textSection->PointerToRawData - textSection->VirtualAddress : 0;
	INT relocOffsetOnFile = relocSection != NULL ? relocSection->PointerToRawData - relocSection->VirtualAddress : 0;
	INT pdataOffsetOnFile = pdataSection != NULL ? pdataSection->PointerToRawData - pdataSection->VirtualAddress : 0;

	imageExportData.sectionSize = imageOptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if(imageOptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT && imageExportData.sectionSize) {
		DWORD directoryRVA = imageOptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		imageExportData.directory = *(PIMAGE_EXPORT_DIRECTORY) (lpFile + directoryRVA + rdataOffsetOnFile);
		imageExportData.name.assign((CHAR *) lpFile + imageExportData.directory.Name + rdataOffsetOnFile);

		LPDWORD addressTable = (LPDWORD) (lpFile + imageExportData.directory.AddressOfFunctions + rdataOffsetOnFile);
		LPDWORD namePointerTable = (LPDWORD) (lpFile + imageExportData.directory.AddressOfNames + rdataOffsetOnFile);
		LPWORD ordinalTable = (LPWORD) (lpFile + imageExportData.directory.AddressOfNameOrdinals + rdataOffsetOnFile);

		for(DWORD i = 0; i < imageExportData.directory.NumberOfFunctions; ++i) {
			EXPORT_TABLE_ENTRY temp;
			temp.ordinal = i;
			temp.ordinalBiased = i + imageExportData.directory.Base;
			temp.exportRVA = addressTable[i];
			temp.isForwarderRVA = (addressTable[i] >= directoryRVA && addressTable[i] <= directoryRVA + imageExportData.sectionSize);

			if(temp.isForwarderRVA) {
				temp.exportRaw = addressTable[i] + rdataOffsetOnFile;
				temp.forwarder.assign((LPCSTR) (lpFile + addressTable[i] + rdataOffsetOnFile));
			} else {
				temp.exportRaw = addressTable[i] + codeOffsetOnFile;
			}

			for(DWORD j = 0; j < imageExportData.directory.NumberOfNames; ++j) {
				if(ordinalTable[j] == i) {
					temp.name.assign((LPCSTR) (lpFile + namePointerTable[j] + rdataOffsetOnFile));
				}
			}

			imageExportData.exportTable.push_back(temp);
		}
	}

	imageImportData.sectionSize = imageOptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if(imageOptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT && imageImportData.sectionSize) {
		DWORD directoryRVA = imageOptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
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

			imageImportData.importTable.push_back(temp);
			++importEntry;
		}
	}

	imageRelocData.sectionSize = imageOptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if(imageOptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC && imageRelocData.sectionSize) {
		DWORD directoryRVA = imageOptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION) (lpFile + directoryRVA + relocOffsetOnFile);

		DWORD blockSize;
		for(DWORD sz = imageRelocData.sectionSize; sz > 0; sz -= blockSize) {
			blockSize = reloc->SizeOfBlock;
			PWORD relocations = (PWORD) (reloc + 1); // right after relocation block header

			for(DWORD i = 0; i < (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++i) {
				BASERELOC_TABLE_ENTRY temp;
				temp.type = relocations[i] >> 12;
				temp.offset = reloc->VirtualAddress + (relocations[i] & 0x0FFF);
				imageRelocData.baserelocTable.push_back(temp);
			}
			reloc = (PIMAGE_BASE_RELOCATION) ((LPBYTE) reloc + blockSize);
		}
	}

	imageSehData.sectionSize = imageOptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
	if(imageOptHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION && imageSehData.sectionSize) {
		DWORD directoryRVA = imageOptHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;

		PDWORD entry = (PDWORD)(lpFile + directoryRVA + pdataOffsetOnFile);
		for(int i = 0; i < imageSehData.sectionSize / (3 * sizeof(DWORD)); ++i) {
			SEH_TABLE_ENTRY temp;
			temp.win64.beginRVA = *(entry++);
			temp.win64.endRVA = *(entry++);
			temp.win64.unwindRVA = *(entry++);
			imageSehData.sehTable.push_back(temp);
		}
	}

	return TRUE;
}

BOOL PEInfo::Parse32() {
	PIMAGE_OPTIONAL_HEADER32 pImageOptHeader = (PIMAGE_OPTIONAL_HEADER32) (lpFile + imageDosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	memcpy(&imageOptHeader, pImageOptHeader, (LPBYTE) &pImageOptHeader->BaseOfData - (LPBYTE) pImageOptHeader);
	imageOptHeader.ImageBase = pImageOptHeader->ImageBase;
	memcpy(&imageOptHeader.SectionAlignment, &pImageOptHeader->SectionAlignment, (LPBYTE) &pImageOptHeader->SizeOfStackReserve - (LPBYTE) &pImageOptHeader->SectionAlignment);
	imageOptHeader.SizeOfStackReserve = pImageOptHeader->SizeOfStackReserve;
	imageOptHeader.SizeOfStackCommit = pImageOptHeader->SizeOfStackCommit;
	imageOptHeader.SizeOfHeapReserve = pImageOptHeader->SizeOfHeapReserve;
	imageOptHeader.SizeOfHeapCommit = pImageOptHeader->SizeOfHeapCommit;
	memcpy(&imageOptHeader.LoaderFlags, &pImageOptHeader->LoaderFlags, (LPBYTE) &pImageOptHeader->DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] - (LPBYTE) &pImageOptHeader->LoaderFlags);



	return TRUE;
}