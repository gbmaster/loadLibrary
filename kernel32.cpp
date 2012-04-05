#include <Windows.h>
#include <winnt.h>
#include "kernel32.hpp"
#include "common.h"

kernel32* kernel32::instance_ptr = NULL;

/**
  * _LoadLibraryExA
  * replacement function used when the module is trying to import LoadLibraryExA
  */
HMODULE WINAPI _LoadLibraryExA(LPCSTR lpFileName, HANDLE hFile, DWORD dwFlags)
{
	if(!(dwFlags & LOAD_WITH_ALTERED_SEARCH_PATH))
		return kernel32::get_instance()->LoadLibraryEx(lpFileName, hFile, dwFlags);
	else
		return NULL;
}

/**
  * _LoadLibraryA
  * replacement function used when the module is trying to import LoadLibraryA
  */
HMODULE WINAPI _LoadLibraryA(LPCSTR lpFileName)
{
	return _LoadLibraryExA(lpFileName, 0, 0);
}

/**
  * _LoadLibraryExW
  * replacement function used when the module is trying to import LoadLibraryExW
  * Just a simple wrapper for LoadLibraryExA
  */
HMODULE WINAPI _LoadLibraryExW(LPCTSTR lpFileName, HANDLE hFile, DWORD dwFlags)
{
 	char *string = new char[wcslen(lpFileName) + 1];

	WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, string, wcslen(lpFileName) + 1, NULL, NULL);
	HMODULE hModule = _LoadLibraryExA(string, hFile, dwFlags);

	delete[] string;

	return hModule;
}

/**
  * _LoadLibraryW
  * replacement function used when the module is trying to import LoadLibraryW
  */
HMODULE WINAPI _LoadLibraryW(LPCTSTR lpFileName)
{
	return _LoadLibraryExW(lpFileName, 0, 0);
}

/**
  * _GetModuleHandleW
  * replacement function used when the module is trying to import GetModuleHandleW
  */
HMODULE WINAPI _GetModuleHandleW(LPCTSTR lpModuleName)
{
	return kernel32::get_instance()->GetModuleHandle(hash_uppercaseW(lpModuleName));
}

/**
  * _GetModuleHandleA
  * replacement function used when the module is trying to import GetModuleHandleA
  */
HMODULE WINAPI _GetModuleHandleA(LPCSTR lpModuleName)
{
	return kernel32::get_instance()->GetModuleHandle(hash_uppercase(lpModuleName));
}

/**
  * _FreeLibrary
  * replacement function used when the module is trying to import FreeLibrary
  */
BOOL WINAPI _FreeLibrary(HMODULE hModule)
{
	if(!kernel32::get_instance()->FreeLibrary(hModule))
		return kernel32::get_instance()->OrigFreeLibrary(hModule);
	return TRUE;
}

/**
  * _Constructor
  * it just loads the needed functions dinamically and initializes the critical sections
  */
kernel32::kernel32()
{
	// Our private loader, huhuhu
	HMODULE hKernel32 = GetModuleHandle(KERNEL32);

	CloseHandle = (_CLOSEHANDLE)GetProcAddress(hKernel32, CLOSEHANDLE, 0);
	CreateFile = (_CREATEFILEA)GetProcAddress(hKernel32, CREATEFILEA, 0);
	CreateFileMapping = (_CREATEFILEMAPPINGA)GetProcAddress(hKernel32, CREATEFILEMAPPINGA, 0);
	DeleteCriticalSection = (_DELETECRITICALSECTION)GetProcAddress(hKernel32, DELETECRITICALSECTION, 0);
	EnterCriticalSection = (_ENTERCRITICALSECTION)GetProcAddress(hKernel32, ENTERCRITICALSECTION, 0);
	GetCurrentDirectory = (_GETCURRENTDIRECTORYA)GetProcAddress(hKernel32, GETCURRENTDIRECTORYA, 0);
	GetFullPathName = (_GETFULLPATHNAMEA)GetProcAddress(hKernel32, GETFULLPATHNAMEA, 0);
	GetSystemDirectory = (_GETSYSTEMDIRECTORYA)GetProcAddress(hKernel32, GETSYSTEMDIRECTORYA, 0);
	InitializeCriticalSection = (_INITIALIZECRITICALSECTION)GetProcAddress(hKernel32, INITIALIZECRITICALSECTION, 0);
	LeaveCriticalSection = (_LEAVECRITICALSECTION)GetProcAddress(hKernel32, LEAVECRITICALSECTION, 0);
	MapViewOfFile = (_MAPVIEWOFFILE)GetProcAddress(hKernel32, MAPVIEWOFFILE, 0);
	MapViewOfFileEx = (_MAPVIEWOFFILEEX)GetProcAddress(hKernel32, MAPVIEWOFFILEEX, 0);
	WideCharToMultiByte = (_WIDECHARTOMULTIBYTE)GetProcAddress(hKernel32, WIDECHARTOMULTIBYTE, 0);
	UnmapViewOfFile = (_UNMAPVIEWOFFILE)GetProcAddress(hKernel32, UNMAPVIEWOFFILE, 0);
	VirtualAlloc = (_VIRTUALALLOC)GetProcAddress(hKernel32, VIRTUALALLOC, 0);
	VirtualFree = (_VIRTUALFREE)GetProcAddress(hKernel32, VIRTUALFREE, 0);
	VirtualProtect = (_VIRTUALPROTECT)GetProcAddress(hKernel32, VIRTUALPROTECT, 0);

	OrigFreeLibrary = (_FREELIBRARY)GetProcAddress(hKernel32, FREELIBRARY, 0);

	InitializeCriticalSection(&libCritical);
}

/**
  * Destructor
  */
kernel32::~kernel32()
{
	DeleteCriticalSection(&libCritical);
}

/**
  * FreeLibraryWrapped
  * frees the selected library, decreases the dependency counter and, if
  * necessary, frees the not-needed-anymore libraries
  */
BOOL kernel32::FreeLibraryWrapped(HMODULE hModule)
{
	std::map<HMODULE, MODULES_LIST *>::iterator& module_entryit = libInstancesMap.find(hModule);
	MODULES_LIST *module_entry, *entry, *tmp;
	if(module_entryit != libInstancesMap.end())
	{
		BOOL bRet = TRUE;

		module_entry = module_entryit->second;
		// already marked for deletion
		if(module_entry->markedForDeletion)
			return TRUE;

		if(module_entry->instances > 0 && module_entry->instances != 0xFFFF)
		{
			module_entry->instances--;
			if(module_entry->instances == 0)
			{
				// we are deleting it
				module_entry->markedForDeletion = TRUE;

				PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
				if(dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
					return NULL;
				PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((LONG)dosHeader + dosHeader->e_lfanew);

				// call the DLL_PROCESS_DETACH routine
				if(!(module_entry->flags & (LOAD_LIBRARY_AS_DATAFILE | DONT_RESOLVE_DLL_REFERENCES)))
				{
					DllEntryProc entryPoint = (DllEntryProc)((PBYTE)hModule + pNTHeader->OptionalHeader.AddressOfEntryPoint);
 					(*entryPoint)((HINSTANCE)hModule, DLL_PROCESS_DETACH, 0);
				}

				if(!(module_entry->flags & DONT_RESOLVE_DLL_REFERENCES))
				{
					// lemme analyze the modules loaded by this one
					entry = module_entry->next;
					for(EVER)
					{
						if(entry == NULL) break;

						FreeLibrary(entry->hModule);

						tmp = entry->next;
						delete entry;
						entry = tmp;
					}
				}

				bRet = UnmapViewOfFile(hModule);

				libInstancesMap.erase(module_entryit);
				delete module_entry;
			}
		}

		return bRet;
	}
	else
		return kernel32::get_instance()->OrigFreeLibrary(hModule);
}

/**
  * GetModuleHandle
  * Scans the whole PEB, looking for the selected module.
  * If not found, it scans the internal list for it.
  * byWindows says if the module was loaded by Windows or by this library.
  */
HMODULE kernel32::GetModuleHandle(unsigned int hash, BOOL& byWindows)
{
	PPEB peb;
	PLIST_ENTRY listEntry, headEntry;
	byWindows = TRUE;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY     LoadOrder;
		LIST_ENTRY     MemoryOrder;
		LIST_ENTRY     InitializationOrder;
		PVOID          ModuleBaseAddress;
		PVOID          EntryPoint;
		ULONG          ModuleSize;
		UNICODE_STRING FullModuleName;
		UNICODE_STRING ModuleName;
		ULONG          Flags;
		USHORT         LoadCount;
		USHORT         TlsIndex;
		union {
			LIST_ENTRY Hash;
			struct {
				PVOID SectionPointer;
				ULONG CheckSum;
			};
		};
		ULONG   TimeStamp;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

	PLDR_DATA_TABLE_ENTRY dataTableEntry;

	__asm
	{
		mov edx, fs:[0x30]			// PEB
		mov peb, edx
	}

	headEntry = peb->Ldr->InMemoryOrderModuleList.Flink;
	for(listEntry = headEntry; listEntry != headEntry->Blink; listEntry = listEntry->Flink)
	{
		dataTableEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)listEntry - 8 * sizeof(BYTE));
		if(hash_uppercaseW(dataTableEntry->ModuleName.Buffer) == hash)
			return (HMODULE)dataTableEntry->ModuleBaseAddress;
		if((DWORD)(dataTableEntry->ModuleBaseAddress) == 0)
			break;
	}

	// Let's try to check if we loaded the module with our tricky functions
	std::map<HMODULE, MODULES_LIST *>::const_iterator& theEnd = libInstancesMap.end();
	for(std::map<HMODULE, MODULES_LIST *>::const_iterator& module_entryit = libInstancesMap.begin();
		module_entryit != theEnd;
		module_entryit++)
	{
		if(module_entryit->second->hashName == hash)
		{
			byWindows = FALSE;
			return module_entryit->second->hModule;
		}
	}
	return NULL;
}

/**
  * GetModuleHandle
  * Public function that hides the byWindows parameter.
  * hash HAS to be the hash of the absolute path.
  */
HMODULE kernel32::GetModuleHandle(unsigned int hash)
{
	BOOL byWindows;
	return GetModuleHandle(hash, byWindows);
}

/**
  * GetModuleHandleByString
  * Internal function: like GetModuleHandle, but it uses a string instead of a hash
  */
HMODULE kernel32::GetModuleHandleByString(LPCSTR lpModuleName, BOOL& byWindows)
{
	HMODULE handle;

	if((handle = GetModuleHandle(hash_uppercase(lpModuleName), byWindows)) == NULL)
	{
		char curDir[MAX_PATH];
		GetCurrentDirectory(MAX_PATH - 1, curDir);
		lstrcatA(curDir, "\\");
		lstrcpynA(curDir + lstrlenA(curDir), lpModuleName, MAX_PATH - lstrlenA(lpModuleName));
		if((handle = GetModuleHandle(hash_uppercase(curDir), byWindows)) == NULL)
		{
			char sysDir[MAX_PATH];
			GetSystemDirectory(sysDir, MAX_PATH - 1);
			lstrcatA(sysDir, "\\");
			lstrcpynA(sysDir + lstrlenA(sysDir), lpModuleName, MAX_PATH - lstrlenA(lpModuleName));
			handle = GetModuleHandle(hash_uppercase(sysDir), byWindows);
		}
	}

	return handle;
}

/**
  * GetModuleHandleByString
  * Public function that hides the byWindows parameter. 
  */
HMODULE kernel32::GetModuleHandleByString(LPCSTR lpModuleName)
{
	BOOL byWindows;
	return GetModuleHandleByString(lpModuleName, byWindows);
}

/**
  * GetProcAddress
  * Seeks for a function (given the hash of the name) in the hModule module.
  * If the hash is 0, it uses the ordinal number.
  */
FARPROC kernel32::GetProcAddress(HMODULE hModule, unsigned int hash, unsigned int ordinal)
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS pNTHeader;
	PBYTE baseImage = (PBYTE)hModule;

	dosHeader = (PIMAGE_DOS_HEADER)hModule;
	// Really an MZ file ?
	if(dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// Get the NT header
	pNTHeader = (PIMAGE_NT_HEADERS)((LONG)dosHeader + dosHeader->e_lfanew);

	// This value is always set to 16 by the current tools
	if(pNTHeader->OptionalHeader.NumberOfRvaAndSizes != 16)
		return NULL;

	// The first entry of the export DataDirectory
	if(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
		return NULL;
	PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + baseImage);

	DWORD numberOfFunctions = exportTable->NumberOfFunctions;
	DWORD *addressOfNames = (DWORD *)(baseImage + exportTable->AddressOfNames);
	WORD *addressOfNameOrdinals = (WORD *)(baseImage + exportTable->AddressOfNameOrdinals);
	PDWORD *addressOfFunctions = (PDWORD *)(baseImage + exportTable->AddressOfFunctions);

	FARPROC funcAddress = NULL;
	if(hash)
	{
		// by hash
		unsigned int function_hash;
		for(DWORD i = 0; i < numberOfFunctions; i++)
		{
			function_hash = hash_uppercase((char *)(addressOfNames[i] + baseImage));
			if(function_hash == hash)
			{
				funcAddress = (FARPROC)(baseImage + (DWORD)addressOfFunctions[addressOfNameOrdinals[i]]);
				break;
			}
		}
	}
	else
	{
		// by ordinal
		ordinal -= exportTable->Base;
		if(ordinal >= numberOfFunctions)
			return NULL;

		funcAddress = (FARPROC)(baseImage + (DWORD)addressOfFunctions[ordinal]);
	}

	if(funcAddress > (FARPROC)exportTable &&
		funcAddress < (FARPROC)((PBYTE)exportTable + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
	{
		// forwarded functions cause problems
		char *dllName = new char[MAX_PATH];
		char *funcName = new char[256];

		char *thedot = strchr((char *)funcAddress, '.');

		lstrcpynA(funcName, ++thedot, 256);
		lstrcpynA(dllName, (char *)funcAddress, (thedot - (char *)funcAddress));
		lstrcatA(dllName, ".dll");

		HMODULE hFwdModule = GetModuleHandleByString(dllName);
		if(hFwdModule == NULL)
		{
			hFwdModule = LoadLibrary(dllName);
					
			if(hFwdModule == NULL)
				return NULL;
		}

		if((lstrlenA(funcName) > 1) && (funcName[0] == '#'))
			funcAddress = GetProcAddress(hFwdModule, 0, funcName[1]);
		else
			funcAddress = GetProcAddress(hFwdModule, hash_uppercase(funcName), 0);

		delete funcName;
		delete dllName;
	}

	return funcAddress;
}

/**
  * LoadLibraryExWrapped
  * The core of the library. It loads the specified library.
  * Just some of the flags are implemented, i.e. LOAD_LIBRARY_AS_DATAFILE and DONT_RESOLVE_DLL_REFERENCES.
  */
HMODULE kernel32::LoadLibraryExWrapped(LPCSTR lpFileName, HANDLE hFile, DWORD dwFlags)
{
	char lpFilePath[MAX_PATH], sysDir[MAX_PATH], curDir[MAX_PATH];
	GetSystemDirectory(sysDir, MAX_PATH - 1);
	GetCurrentDirectory(MAX_PATH - 1, curDir);
	lstrcatA(curDir, "\\");
	lstrcpynA(curDir + lstrlenA(curDir), lpFileName, MAX_PATH - lstrlenA(lpFileName));
	lstrcatA(sysDir, "\\");
	lstrcpynA(sysDir + lstrlenA(sysDir), lpFileName, MAX_PATH - lstrlenA(lpFileName));

	// Already loaded ?
	BOOL byWindows;
	HMODULE hModule = GetModuleHandleByString(lpFileName, byWindows);
	if(hModule != NULL)
	{
		if(!byWindows)
		{
			// If we loaded it, add 1 to the number of instances
			std::map<HMODULE, MODULES_LIST *>::iterator& module_entryit = libInstancesMap.find(hModule);
			if(module_entryit != libInstancesMap.end() && module_entryit->second->instances != 0xFFFF)
				module_entryit->second->instances++;
		}
		return hModule;
	}

	// Open the library, please
	HANDLE handle = CreateFile(curDir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(handle == INVALID_HANDLE_VALUE)
	{
		// No luck with local path, let's try to search in system32
		handle = CreateFile(sysDir, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if(handle == INVALID_HANDLE_VALUE)
		{
			// No luck at all
			return NULL;
		}
		else
			lstrcpyA(lpFilePath, sysDir);
	}
	else
		lstrcpyA(lpFilePath, curDir);

	// Map the file in memory
	HANDLE hMapping = CreateFileMapping(handle, NULL, PAGE_READONLY, 0, 0, NULL);
	if(hMapping == INVALID_HANDLE_VALUE)
	{
		CloseHandle(handle);
		return NULL;
	}

	LPVOID baseAddress = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

	// Not needed anymore, we have the mapping now
	CloseHandle(hMapping);
	CloseHandle(handle);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	PIMAGE_NT_HEADERS pNTHeader;
	// Really an MZ file ?
	if(dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		UnmapViewOfFile(baseAddress);
		return NULL;
	}

	// Get the NT header
	pNTHeader = (PIMAGE_NT_HEADERS)((LONG)dosHeader + dosHeader->e_lfanew);

	// Reserve memory please at the ImageBase
	// If this is not possible, base relocation is required
	hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, pNTHeader->OptionalHeader.SizeOfImage, NULL);
	if(hMapping == NULL)
	{
		UnmapViewOfFile(baseAddress);
		return NULL;
	}

	LPVOID baseDll = MapViewOfFileEx(hMapping, FILE_EXECUTE | FILE_MAP_WRITE, 0, 0, 0, (LPVOID)(pNTHeader->OptionalHeader.ImageBase));
	if(baseDll == NULL)
	{
		baseDll = MapViewOfFileEx(hMapping, FILE_EXECUTE | FILE_MAP_WRITE, 0, 0, 0, NULL);
		if(baseDll == NULL)
		{
			CloseHandle(hMapping);
			UnmapViewOfFile(baseAddress);
			return NULL;
		}
	}
	CloseHandle(hMapping);

	// Copy the headers
	memcpy(baseDll, baseAddress, pNTHeader->OptionalHeader.SizeOfHeaders);
	// Point the headers variable to the new version
	dosHeader = (PIMAGE_DOS_HEADER)baseDll;
	pNTHeader = (PIMAGE_NT_HEADERS)((LONG)dosHeader + dosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNTHeader);
	for(int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, pSection++)
		memcpy((PBYTE)baseDll + pSection->VirtualAddress, (PBYTE)baseAddress + pSection->PointerToRawData, pSection->SizeOfRawData);

	if(!(dwFlags & LOAD_LIBRARY_AS_DATAFILE))
	{
		// Base relocation if the base address is not the expected one
		if((DWORD)baseDll != pNTHeader->OptionalHeader.ImageBase)
		{
			PIMAGE_DATA_DIRECTORY relocDir = (PIMAGE_DATA_DIRECTORY)&(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
			if(relocDir->Size)
			{
				PIMAGE_BASE_RELOCATION baseRel = (PIMAGE_BASE_RELOCATION)((PBYTE)baseDll + relocDir->VirtualAddress);

				while(baseRel->VirtualAddress)
				{
					// We need a 16bit type
					unsigned short *relValue = (unsigned short *)((PBYTE)baseRel + sizeof(IMAGE_BASE_RELOCATION));
					DWORD nEntries = (baseRel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
					PBYTE pageAddress = (PBYTE)baseDll + baseRel->VirtualAddress;

					for(DWORD i = 0; i < nEntries; i++, relValue++)
					{
						unsigned short pageOffset = *relValue & 0x0FFF;
						unsigned char type = *relValue >> 12;

						switch(type)
						{
						case IMAGE_REL_BASED_ABSOLUTE:
							// This is a no-op; it is used to align the chunk to a 32-bits-
							// border. The position should be 0.
							break;
						case IMAGE_REL_BASED_HIGHLOW:
							// The entire 32-bit-relocation must be applied to the entire 32
							// bits in question. This (and the no-op '0') is the only
							// relocation type I've actually found in binaries.
							*((DWORD *)(pageAddress + pageOffset)) += ((DWORD)baseDll - pNTHeader->OptionalHeader.ImageBase);
							break;
						default:
							break;
						}
					}

					baseRel = (PIMAGE_BASE_RELOCATION)((PBYTE)baseRel + baseRel->SizeOfBlock);
				}
			}
			pNTHeader->OptionalHeader.ImageBase = (DWORD)baseDll;
		}
	}

	// New entry in the map
	MODULES_LIST *entry;

	entry = new MODULES_LIST;
	entry->hashName = hash_uppercase(lpFilePath);
	entry->hModule = (HMODULE)baseDll;
	entry->instances = 1;
	entry->flags = dwFlags;
	entry->markedForDeletion = FALSE;
	entry->next = NULL;

	// WINDOWS 7 MESS
	char targetName[MAX_PATH], *filePart, system32Dir[MAX_PATH];
	GetFullPathName(lpFilePath, MAX_PATH, targetName, &filePart);
	GetSystemDirectory(system32Dir, MAX_PATH - 1);
	lstrcpynA(filePart, filePart, 16);
	lstrcatA(system32Dir, "\\");
	if(hash_uppercase(filePart) == 0x5DE52DB9)
	{
		filePart[0] = 0;
		// Is the file in system32 ?
		if(hash_uppercase(targetName) == hash_uppercase(system32Dir))
			entry->bMsWinCore = TRUE;
		else
			entry->bMsWinCore = FALSE;
	}
	else
		entry->bMsWinCore = FALSE;

	libInstancesMap[(HMODULE)baseDll] = entry;

	if(!(dwFlags & LOAD_LIBRARY_AS_DATAFILE))
	{
		if(!(dwFlags & DONT_RESOLVE_DLL_REFERENCES))
		{
			// Resolving imports
			PIMAGE_DATA_DIRECTORY importsDir = (PIMAGE_DATA_DIRECTORY)&(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
			if(importsDir->Size)
			{
				PIMAGE_IMPORT_DESCRIPTOR baseImp = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)baseDll + importsDir->VirtualAddress);

				while(baseImp->OriginalFirstThunk)
				{
					// List of imports
					PDWORD nameRef = (DWORD *)((PBYTE)baseDll + baseImp->OriginalFirstThunk);
					// Address entries
					PDWORD symbolRef = (DWORD *)((PBYTE)baseDll + baseImp->FirstThunk);

					// I know, I know, I know. This could be done just with a
					// LoadLibrary call but I need to know, before calling LoadLibrary,
					// if we already have an instance of the module available
					char importName[MAX_PATH];
					lstrcpyA(importName, (const char*)((PBYTE)baseDll + baseImp->Name));
					HMODULE hLib = GetModuleHandleByString(importName, byWindows);
					if(hLib == NULL)
					{
						// Load the library
						hLib = LoadLibraryEx((const char *)((PBYTE)baseDll + baseImp->Name), 0, dwFlags);

						if(hLib == NULL)
						{
							FreeLibrary((HMODULE)baseDll);
							UnmapViewOfFile(baseAddress);
							return NULL;
						}
						else
						{
							entry->next = new MODULES_LIST;
							entry = entry->next;
							entry->hashName = 0; // useless here
							entry->hModule = hLib;
							entry->markedForDeletion = FALSE; // useless here
							entry->instances = 0; // useless here
							entry->flags = 0; // useless here
							entry->bMsWinCore = FALSE; // useless here
							entry->next = NULL;
						}
					}
					else if(!byWindows)
					{
						// We loaded the library: add it to the dependencies
						entry->next = new MODULES_LIST;
						entry = entry->next;
						entry->hashName = 0; // useless here
						entry->hModule = hLib;
						entry->markedForDeletion = FALSE; // useless here
						entry->instances = 0; // useless here
						entry->flags = 0; // useless here
						entry->bMsWinCore = FALSE; // useless here
						entry->next = NULL;

						// Add 1 to the number of instances
						std::map<HMODULE, MODULES_LIST *>::iterator& module_entryit = libInstancesMap.find(hLib);
						if(module_entryit != libInstancesMap.end() && module_entryit->second->instances != 0xFFFF)
							module_entryit->second->instances++;
					}

					// If it's one of the new messy DLL files, then hijack to kernel32.dll
					std::map<HMODULE, MODULES_LIST *>::const_iterator& moduleit = libInstancesMap.find(hLib);
					if(moduleit != libInstancesMap.end() && moduleit->second->bMsWinCore)
						hLib = GetModuleHandle(KERNEL32);

					for (; *nameRef; nameRef++, symbolRef++)
					{
						if(((PIMAGE_THUNK_DATA)nameRef)->u1.Ordinal & 0x80000000)
						{
							DWORD nOrdinal = (((PIMAGE_THUNK_DATA)nameRef)->u1.Ordinal & 0xFFFF);
/*
							if(hash_uppercase((const char *)((PBYTE)baseDll + baseImp->Name)) == KERNEL32)
							{
								if(nOrdinal == 241) *symbolRef = (DWORD)_FreeLibrary;
								else if(nOrdinal == 376) *symbolRef = (DWORD)_GetModuleHandleA;
								else if(nOrdinal == 377) *symbolRef = (DWORD)_GetModuleHandleW;
								else if(nOrdinal == 581) *symbolRef = (DWORD)_LoadLibraryA;
								else if(nOrdinal == 584) *symbolRef = (DWORD)_LoadLibraryW;
								else if(nOrdinal == 582) *symbolRef = (DWORD)_LoadLibraryExA;
								else if(nOrdinal == 583) *symbolRef = (DWORD)_LoadLibraryExW;
								else *symbolRef = (DWORD)GetProcAddress(hLib, 0, nOrdinal);
							}
							else
*/
								*symbolRef = (DWORD)GetProcAddress(hLib, 0, nOrdinal);
						}
						else
						{
							const char *funcName = (const char *)((PIMAGE_IMPORT_BY_NAME)((PBYTE)baseDll + *nameRef))->Name;

							// remember the user32.dll hell ?
							unsigned int func_hash = hash_uppercase(funcName);
							if(hash_uppercase((const char *)((PBYTE)baseDll + baseImp->Name)) == KERNEL32)
							{
								if(func_hash == FREELIBRARY) *symbolRef = (DWORD)_FreeLibrary;
								else if(func_hash == GETMODULEHANDLEA) *symbolRef = (DWORD)_GetModuleHandleA;
								else if(func_hash == GETMODULEHANDLEW) *symbolRef = (DWORD)_GetModuleHandleW;
								else if(func_hash == LOADLIBRARYA) *symbolRef = (DWORD)_LoadLibraryA;
								else if(func_hash == LOADLIBRARYW) *symbolRef = (DWORD)_LoadLibraryW;
								else if(func_hash == LOADLIBRARYEXA) *symbolRef = (DWORD)_LoadLibraryExA;
								else if(func_hash == LOADLIBRARYEXW) *symbolRef = (DWORD)_LoadLibraryExW;
								else *symbolRef = (DWORD)GetProcAddress(hLib, func_hash, 0);
							}
							else
								*symbolRef = (DWORD)GetProcAddress(hLib, func_hash, 0);
						}
					}

					baseImp++;
				}
			}
		}

		// Protecting sections
		pSection = IMAGE_FIRST_SECTION(pNTHeader);
		for(int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, pSection++)
		{
			DWORD size = pSection->SizeOfRawData;

			if(!size)
			{
				if(pSection->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
					size = pNTHeader->OptionalHeader.SizeOfInitializedData;
				else if(pSection->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
					size = pNTHeader->OptionalHeader.SizeOfUninitializedData;
				else
					continue;
			}

			DWORD oldProtect, newProtect;

			BOOL protectR = (pSection->Characteristics & IMAGE_SCN_MEM_READ) ? TRUE : FALSE;
			BOOL protectW = (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) ? TRUE : FALSE;
			BOOL protectX = (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? TRUE : FALSE;

			if(!protectR && !protectW && protectX) newProtect = PAGE_EXECUTE;
			else if(protectR && !protectW && protectX) newProtect = PAGE_EXECUTE_READ;
			else if(protectR && !protectW && protectX) newProtect = PAGE_EXECUTE_READWRITE;
			else if(!protectR && protectW && protectX) newProtect = PAGE_EXECUTE_WRITECOPY;
			else if(!protectR && !protectW && !protectX) newProtect = PAGE_NOACCESS;
			else if(!protectR && protectW && !protectX) newProtect = PAGE_WRITECOPY;
			else if(protectR && !protectW && !protectX) newProtect = PAGE_READONLY;
			else if(protectR && protectW && !protectX) newProtect = PAGE_READWRITE;
				
 			if(pSection->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
				newProtect |= PAGE_NOCACHE;

			VirtualProtect((PBYTE)baseDll + pSection->VirtualAddress, size, newProtect, &oldProtect);
		}

		if(!(dwFlags & DONT_RESOLVE_DLL_REFERENCES))
		{
			// Notify the library
			if(pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
			{
				DllEntryProc entryPoint = (DllEntryProc)((PBYTE)baseDll + pNTHeader->OptionalHeader.AddressOfEntryPoint);
 				(*entryPoint)((HINSTANCE)baseDll, DLL_PROCESS_ATTACH, 0);
			}
		}
	}

	// Unmap the file, please
	UnmapViewOfFile(baseAddress);

	return (HMODULE)baseDll;
}

/**
  * LoadLibraryWrapped
  * It loads the specified library. Just a simple wrapper for LoadLibraryEx.
  */
HMODULE kernel32::LoadLibraryWrapped(const char *lpFileName)
{
	return LoadLibraryEx(lpFileName, 0, 0);
}

/**
  * LoadLibraryEx
  * Wrapping the wrapper: initializes the critical sections and calls LoadLibraryExWrapped
  */
HMODULE kernel32::LoadLibraryEx(LPCSTR lpFileName, HANDLE hFile, DWORD dwFlags)
{
	EnterCriticalSection(&libCritical);
	HMODULE hMod = LoadLibraryExWrapped(lpFileName, hFile, dwFlags);
	LeaveCriticalSection(&libCritical);

	return hMod;
}

/**
  * LoadLibrary
  * Loads the library.
  */
HMODULE kernel32::LoadLibrary(const char *lpFileName)
{
	EnterCriticalSection(&libCritical);
	HMODULE hMod = LoadLibraryWrapped(lpFileName);
	LeaveCriticalSection(&libCritical);

	return hMod;
}

/**
  * FreeLibrary
  * Critical section initialization and library freeing.
  */
BOOL kernel32::FreeLibrary(HMODULE hModule)
{
	EnterCriticalSection(&libCritical);
	BOOL bRet = FreeLibraryWrapped(hModule);
	LeaveCriticalSection(&libCritical);

	return bRet;
}