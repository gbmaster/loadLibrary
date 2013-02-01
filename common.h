#ifndef COMMON_H
#define COMMON_H

#include <Windows.h>

#define EVER ;;

extern unsigned int hash_uppercase(const char *string);
extern unsigned int hash_uppercaseW(const wchar_t* wstring);

#endif