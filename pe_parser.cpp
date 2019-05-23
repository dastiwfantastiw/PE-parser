#include <Windows.h>
#include <stdio.h>

PIMAGE_SECTION_HEADER FindSectionHeader(DWORD_PTR rva, PIMAGE_NT_HEADERS pNTHeader)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);

	for (WORD i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
	{
		if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + section->Misc.VirtualSize)))
			return section;
	}

	return 0;
}

LPVOID RvaToRaw(DWORD_PTR RVA, PIMAGE_NT_HEADERS pNTHeader, DWORD_PTR ImageBase)
{
	PIMAGE_SECTION_HEADER pSectionHdr = FindSectionHeader(RVA, pNTHeader);

	if (!pSectionHdr)
		return 0;

	INT* delta = (INT*)(pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData);
	return (PVOID)(ImageBase + RVA - (INT)delta);
}


int main()
{
	INT args_count = 0;
	LPWSTR* lpCmdLine = CommandLineToArgvW(GetCommandLineW(), &args_count);
	if (args_count > 1)
	{
		HANDLE hFile = CreateFile(lpCmdLine[1], GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile == INVALID_HANDLE_VALUE)
			printf("[-] Cannot open the file, error code = 0x%08X\n", GetLastError());

		DWORD dwSize = GetFileSize(hFile, nullptr);
		if (dwSize == INVALID_FILE_SIZE)
			printf("[-] Cannot get file size, error code = 0x%08X\n", GetLastError());

		HANDLE hMapping = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
		if (hMapping == nullptr)
			printf("[-] CreateFileMapping failed with error code = 0x%08X\n", GetLastError());

		wprintf(L"File = %s (0x%x)\n\n", lpCmdLine[1], dwSize);

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, dwSize);

		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			printf("[-] Invalid DOS signature.\n");
			return 1;
		}

		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

		if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			printf("[-] Invalid NT signature.\n");
			return 1;
		}

		IMAGE_OPTIONAL_HEADER OptionalHeader = (IMAGE_OPTIONAL_HEADER)pNtHeader->OptionalHeader;
		IMAGE_FILE_HEADER FileHeader = (IMAGE_FILE_HEADER)pNtHeader->FileHeader;

		IMAGE_DATA_DIRECTORY DataDir = (IMAGE_DATA_DIRECTORY)OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToRaw(DataDir.VirtualAddress, pNtHeader, (DWORD_PTR)pDosHeader));

		printf("\n[IMPORT TABLE]\n\n");

		printf("%-5s\t%-20s\t[%s]\n", "Hint", "Name", (CHAR*)RvaToRaw(pImportDescriptor->Name, pNtHeader, (DWORD_PTR)pDosHeader));

		while (pImportDescriptor->FirstThunk)
		{
			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)RvaToRaw(pImportDescriptor->FirstThunk, pNtHeader, (DWORD_PTR)pDosHeader);
			for (; pThunk->u1.AddressOfData; pThunk++)
			{
				PIMAGE_IMPORT_BY_NAME  pIMPORT_BY_NAME = (PIMAGE_IMPORT_BY_NAME)RvaToRaw(pThunk->u1.Function, pNtHeader, (DWORD_PTR)pDosHeader);
				if (pIMPORT_BY_NAME != nullptr)
					printf("%-5d\t%-20s\n", pIMPORT_BY_NAME->Hint, pIMPORT_BY_NAME->Name);
			}
			pImportDescriptor++;
		}

		printf("\n[EXPORT TABLE]\n\n");

		DataDir = (IMAGE_DATA_DIRECTORY)OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		PIMAGE_EXPORT_DIRECTORY pDataDirExport = (PIMAGE_EXPORT_DIRECTORY)RvaToRaw(DataDir.VirtualAddress, pNtHeader, (DWORD_PTR)pDosHeader);
		if (!pDataDirExport)
		{
			printf("The file has no export directory!\n");
			return 1;
		}

		DWORD* AddressOfNames = (DWORD*)RvaToRaw(pDataDirExport->AddressOfNames, pNtHeader, (DWORD_PTR)pDosHeader);
		WORD*  AddressOfNameOrdinals = (WORD*)RvaToRaw(pDataDirExport->AddressOfNameOrdinals, pNtHeader, (DWORD_PTR)pDosHeader);
		DWORD* AddressOfFunctions = (DWORD*)RvaToRaw(pDataDirExport->AddressOfFunctions, pNtHeader, (DWORD_PTR)pDosHeader);

		if (pDataDirExport->NumberOfNames != 0)
		{
			printf("%-5c\t%-10s\t%-15s\t%-25s\t[%s]\n", 'N', "Addr", "Ord", "Name", (CHAR*)RvaToRaw(pDataDirExport->Name, pNtHeader, (DWORD_PTR)pDosHeader));
			for (INT i = 0; i < pDataDirExport->NumberOfNames; i++)
			{
				WORD Addr = (DWORD)RvaToRaw(AddressOfFunctions[AddressOfNameOrdinals[i]], pNtHeader, (DWORD_PTR)pDosHeader);
				WORD Ord = (WORD)AddressOfNameOrdinals[i];
				CHAR* Name = (CHAR*)RvaToRaw(AddressOfNames[i], pNtHeader, (DWORD_PTR)pDosHeader);
				printf("%-5d\t0x%-10X\t%-15d\t%-25s\n", i + 1, Addr, Ord, Name);
			}
		}

		UnmapViewOfFile(hMapping);

		CloseHandle(hMapping);
		CloseHandle(hFile);
	}
	else
		printf("usage: pe_parser.exe <path_to_file>\n");

	return 0;
}
