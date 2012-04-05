#include "common.h"

unsigned int hash_uppercase(const char *string)
{
	unsigned int hash = 0;
	char *p = (char *)string;

	while (*p != NULL)
	{
		hash ^= (hash << 5) + (hash >> 2) + ((*p >= 'a' && *p <= 'z') ? *p - 0x20 : *p);
		p++;
	}

	return hash;
}

unsigned int hash_uppercaseW(const wchar_t* wstring)
{
	// Shift-Add-XOR hash
	unsigned int hash = 0;

	char *string = new char[wcslen(wstring) + 1];

	WideCharToMultiByte(CP_ACP, 0, wstring, -1, string, wcslen(wstring) + 1, NULL, NULL);
	hash = hash_uppercase(string);
	
	delete[] string;

	return hash;
}