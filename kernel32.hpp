#ifndef KERNEL32_H
#define KERNEL32_H

#include <map>
#include <winternl.h>

#define KERNEL32 0xE131018A
#define CLOSEHANDLE 0x9CB0FBBC
#define CREATEFILEA 0xD8619938
#define CREATEFILEMAPPINGA 0xDAE26CA1
#define DELETECRITICALSECTION 0x97253ADB
#define ENTERCRITICALSECTION 0x85229C0A
#define FREELIBRARY 0x5851BAE6
#define GETMODULEHANDLEA 0x882B78CD
#define GETMODULEHANDLEW 0x882B78A3
#define GETCURRENTDIRECTORYA 0x35EC0A05
#define GETFULLPATHNAMEA 0xC6BAF103
#define GETSYSTEMDIRECTORYA 0x86A4CF5F
#define INITIALIZECRITICALSECTION 0xF7302BAC
#define LEAVECRITICALSECTION 0xB7EC5A7B
#define LOADLIBRARYA 0xD3733FAF
#define LOADLIBRARYW 0xD3733F99
#define LOADLIBRARYEXA 0x533AC5EA
#define LOADLIBRARYEXW 0x533AC5F0
#define MAPVIEWOFFILE 0xDF4FD8BB
#define MAPVIEWOFFILEEX 0xF13A37DA
#define WIDECHARTOMULTIBYTE 0xB5117319
#define UNMAPVIEWOFFILE 0x39CE13A2
#define VIRTUALALLOC 0x7CE8F471
#define VIRTUALFREE 0x492BA01E
#define VIRTUALPROTECT 0x8468E8D7

// Each module will have an entry called MODULES_LIST
// containing the HMODULE, the hash name, the number
// of instances and a link to the loaded modules by
// the module itself
typedef struct _MODULES_LIST
{
	HMODULE hModule;
	unsigned int hashName;
	unsigned long instances;
	BOOL markedForDeletion;
	BOOL bMsWinCore;
	DWORD flags;
	struct _MODULES_LIST *next;
} MODULES_LIST;

typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef BOOL (WINAPI *_FREELIBRARY)(HMODULE hModule);

typedef BOOL (WINAPI *_CLOSEHANDLE)(HANDLE hObject);
typedef HANDLE (WINAPI *_CREATEFILEA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef HANDLE (WINAPI *_CREATEFILEMAPPINGA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName);
typedef void (WINAPI *_DELETECRITICALSECTION)(LPCRITICAL_SECTION lpCriticalSection);
typedef void (WINAPI *_ENTERCRITICALSECTION)(LPCRITICAL_SECTION lpCriticalSection);
typedef DWORD (WINAPI *_GETCURRENTDIRECTORYA)(DWORD nBufferLength, LPSTR lpBuffer);
typedef DWORD (WINAPI *_GETFULLPATHNAMEA)(LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR *lpFilePart);
typedef UINT (WINAPI *_GETSYSTEMDIRECTORYA)(LPSTR lpBuffer, UINT uSize);
typedef void (WINAPI *_INITIALIZECRITICALSECTION)(LPCRITICAL_SECTION lpCriticalSection);
typedef void (WINAPI *_LEAVECRITICALSECTION)(LPCRITICAL_SECTION lpCriticalSection);
typedef LPVOID (WINAPI *_MAPVIEWOFFILE)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
typedef LPVOID (WINAPI *_MAPVIEWOFFILEEX)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, PVOID lpBaseAddress);
typedef int (WINAPI *_WIDECHARTOMULTIBYTE)(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar);
typedef BOOL (WINAPI *_UNMAPVIEWOFFILE)(LPCVOID lpBaseAddress);
typedef LPVOID (WINAPI *_VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL (WINAPI *_VIRTUALFREE)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef BOOL (WINAPI *_VIRTUALPROTECT)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

class kernel32
{
public:
	~kernel32();
	static kernel32* get_instance()
	{
		if(instance_ptr == NULL)
		{
			instance_ptr = new kernel32();
		}
		return instance_ptr;
	}

	BOOL FreeLibrary(HMODULE hModule);
	HMODULE GetModuleHandle(unsigned int hash);
	FARPROC GetProcAddress(HMODULE hModule, unsigned int hash, unsigned int ordinal);
	HMODULE LoadLibrary(const char *lpFileName);
	HMODULE LoadLibraryEx(LPCSTR lpFileName, HANDLE hFile, DWORD dwFlags);
	_FREELIBRARY OrigFreeLibrary;

private:
	static kernel32* instance_ptr;
	std::map<HMODULE, MODULES_LIST *> libInstancesMap;
	CRITICAL_SECTION libCritical;
	_CLOSEHANDLE CloseHandle;
	_CREATEFILEA CreateFile;
	_CREATEFILEMAPPINGA CreateFileMapping;
	_DELETECRITICALSECTION DeleteCriticalSection;
	_ENTERCRITICALSECTION EnterCriticalSection;
	_GETCURRENTDIRECTORYA GetCurrentDirectory;
	_GETFULLPATHNAMEA GetFullPathName;
	_GETSYSTEMDIRECTORYA GetSystemDirectory;
	_INITIALIZECRITICALSECTION InitializeCriticalSection;
	_LEAVECRITICALSECTION LeaveCriticalSection;
	_MAPVIEWOFFILE MapViewOfFile;
	_MAPVIEWOFFILEEX MapViewOfFileEx;
	_UNMAPVIEWOFFILE UnmapViewOfFile;
	_VIRTUALALLOC VirtualAlloc;
	_VIRTUALFREE VirtualFree;
	_VIRTUALPROTECT VirtualProtect;
	_WIDECHARTOMULTIBYTE WideCharToMultiByte;
	BOOL FreeLibraryWrapped(HMODULE hModule);
	HMODULE GetModuleHandleByString(LPCSTR lpModuleName);
	HMODULE GetModuleHandleByString(LPCSTR lpModuleName, BOOL& byWindows);
	HMODULE GetModuleHandle(unsigned int hash, BOOL& byWindows);
	HMODULE LoadLibraryWrapped(const char *lpFileName);
	HMODULE LoadLibraryExWrapped(LPCSTR lpFileName, HANDLE hFile, DWORD dwFlags);
	kernel32();
};

#endif