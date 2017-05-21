#include "main.h"

#include "../DetectorCore/DetectorCore.h"
#ifdef _DEBUG
#pragma comment( lib, "../Debug/DetectorCore.lib" )
#else
#pragma comment( lib, "../Release/DetectorCore.lib" )
#endif
using namespace DetectorCore;
static CDetectorCore detectorCore;


HMODULE hMyModule = nullptr;


void OpenConsoleWindow()
{
	AllocConsole();

	freopen("CONOUT$", "a", stdout);
	freopen("CONIN$", "r", stdin);
}

// Via: http://www.rohitab.com/discuss/topic/41944-module-pebldr-hiding-all-4-methods/
void UnlinkModule(const char* c_szModuleName)
{
	DWORD dwPEB = 0, dwOffset = 0;
	PLIST_ENTRY pUserModuleHead, pUserModule;
	PPEB_LDR_DATA pLdrData;
	PLDR_MODULE pLdrModule = NULL;
	PUNICODE_STRING lpModule = NULL;
	char szModuleName[512];
	int i = 0, n = 0;

	_asm
	{
		pushad
		mov eax, fs: [48]
		mov dwPEB, eax
		popad
	}

	pLdrData = (PPEB_LDR_DATA)(PDWORD)(*(PDWORD)(dwPEB + 12));

	for (; i < 3; i++)
	{
		switch (i)
		{
		case 0:
			pUserModuleHead = pUserModule = (PLIST_ENTRY)(&(pLdrData->InLoadOrderModuleList));
			dwOffset = 0;
			break;

		case 1:
			pUserModuleHead = pUserModule = (PLIST_ENTRY)(&(pLdrData->InMemoryOrderModuleList));
			dwOffset = 8;
			break;
		case 2:
			pUserModuleHead = pUserModule = (PLIST_ENTRY)(&(pLdrData->InInitializationOrderModuleList));
			dwOffset = 16;
			break;
		}

		while (pUserModule->Flink != pUserModuleHead)
		{
			pUserModule = pUserModule->Flink;
			lpModule = (PUNICODE_STRING)(((DWORD)(pUserModule)) + (36 - dwOffset));

			for (n = 0; n <(lpModule->Length) / 2 && n < 512; n++)
				szModuleName[n] = (CHAR)(*((lpModule->Buffer) + (n)));

			szModuleName[n] = '\0';
			if (strstr(szModuleName, c_szModuleName))
			{
				printf("[*] Module links found!\n");

				if (!pLdrModule)
					pLdrModule = (PLDR_MODULE)(((DWORD)(pUserModule)) - dwOffset);
				pUserModule->Blink->Flink = pUserModule->Flink;
				pUserModule->Flink->Blink = pUserModule->Blink;
			}
		}
	}

	if (pLdrModule)
	{
		pLdrModule->HashTableEntry.Blink->Flink = pLdrModule->HashTableEntry.Flink;
		pLdrModule->HashTableEntry.Flink->Blink = pLdrModule->HashTableEntry.Blink;
	}
}

void RemovePeHeader(HMODULE hModule)
{
	auto pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	auto pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return;

	if (!pNTHeader->FileHeader.SizeOfOptionalHeader)
		return;

	DWORD dwProtect;
	auto wSize = pNTHeader->FileHeader.SizeOfOptionalHeader;
	VirtualProtect((void*)hModule, wSize, PAGE_EXECUTE_READWRITE, &dwProtect);
	RtlZeroMemory((void*)hModule, wSize);
	VirtualProtect((void*)hModule, wSize, dwProtect, &dwProtect);
}




void Init()
{
	OpenConsoleWindow();
	printf("- Started!\n");

	detectorCore.ScanSections(0);
	printf("\t#Scan(0) completed. All modules listed.\n\n");


	TCHAR szName[MAX_PATH] = { 0 };
	GetModuleFileNameA((HMODULE)hMyModule, szName, _countof(szName));
	printf("[*] Module name: %s\n", szName);

	UnlinkModule(szName);
	printf("- Unlink completed!\n");

	detectorCore.ScanSections(1);
	printf("\t# Scan(1) completed. Unlinked modules listed.\n\n");



	RemovePeHeader(hMyModule);
	printf("- Remove Header completed!\n");

	detectorCore.ScanSections(2);
	printf("\t#Scan(2) completed. PE Header's erased modules listed.\n\n");
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (!hMyModule) hMyModule = hModule;

	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			Init();
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}
