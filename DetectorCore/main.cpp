#include "DetectorCore.h"
#include "main.h"

#include <windows.h>
#include <iostream>
#include <Psapi.h>
#pragma comment( lib, "psapi.lib" )


DWORD GetPEHeaderSize(DWORD dwBaseAddr)
{
	auto pDosHeader = (PIMAGE_DOS_HEADER)dwBaseAddr;
	auto pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	if (!pNTHeader->FileHeader.SizeOfOptionalHeader)
		return 0;

	auto wSize = pNTHeader->FileHeader.SizeOfOptionalHeader;
	return wSize;
}

bool ModuleHasLoaded(DWORD dwAddress)
{
	PPEB pPEB = (PPEB)__readfsdword(0x30);
	PLDR_DATA_TABLE_ENTRY Current = NULL;
	PLIST_ENTRY CurrentEntry = pPEB->Ldr->InLoadOrderModuleList.Flink;

	while (CurrentEntry != &pPEB->Ldr->InLoadOrderModuleList && CurrentEntry != NULL)
	{
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (dwAddress == (DWORD)Current->DllBase)
			return true;

		CurrentEntry = CurrentEntry->Flink;
	}
	return false;
}

int ProcessSectionScan(int iType, PBYTE pCurAddr, MEMORY_BASIC_INFORMATION mbi)
{
	// Check page states
	if (!(mbi.State & MEM_COMMIT))
		return -1;

	if (mbi.State & MEM_RELEASE)
		return -2;

	if (mbi.Protect == PAGE_NOACCESS || mbi.Protect & PAGE_GUARD)
		return -3;


	// Just DLL Pages
	if (mbi.Type != MEM_IMAGE)
		return -4;

	if (!mbi.AllocationBase || pCurAddr != mbi.AllocationBase)
		return -5;


	// Parse informations
	char cFileName[2048] = { 0 };
	GetMappedFileNameA(GetCurrentProcess(), (LPVOID)pCurAddr, cFileName, 2048);

	auto bHasLoaded = ModuleHasLoaded((DWORD)pCurAddr);

	BYTE nullByte[] = { 0x0 };
	const auto dwPEHeaderSize = GetPEHeaderSize((DWORD)pCurAddr);
	auto bHasErasedHeader = (!memcmp(pCurAddr, nullByte, dwPEHeaderSize));

	if (iType == 0 /* Get informations before than any operation */ ||
		iType == 1 && !bHasLoaded /* Target module's links has been removed, check it! */ ||
		iType == 2 && bHasErasedHeader /* Target module's pe header cleaned, check it! */)

	printf("A module detected! Base: %p Owner: %s Unlinked: %d Erased Header: %d\n", pCurAddr, cFileName, !bHasLoaded, bHasErasedHeader);

	return 1;
}

void DetectorCore::CDetectorCore::ScanSections(int iType)
{
	SYSTEM_INFO sysINFO;
	GetSystemInfo(&sysINFO);

	PBYTE pCurAddr = (PBYTE)sysINFO.lpMinimumApplicationAddress;
	PBYTE pMaxAddr = (PBYTE)sysINFO.lpMaximumApplicationAddress;


	MEMORY_BASIC_INFORMATION mbi;
	while (pCurAddr < pMaxAddr)
	{
		if (VirtualQuery(pCurAddr, &mbi, sizeof(mbi)))
			ProcessSectionScan(iType, pCurAddr, mbi);

		pCurAddr += mbi.RegionSize;
	}
}

