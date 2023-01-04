#include <windef.h>
#define EXPORT __declspec(dllexport)
#pragma once

BOOL hasresolved = FALSE;
extern EXPORT int WINAPI patch_amsi();
extern EXPORT int WINAPI patch_etw();
