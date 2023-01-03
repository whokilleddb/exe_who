#include <stdio.h>
#include <windows.h>
#include <sysinfoapi.h>
#define NL() (printf("\n"))
#pragma once

// print hex
static inline void phex(unsigned char bytes[], int size) {
    for (int i=0; i<size; i++) {
        printf("0x%X ", bytes[i]);
    }
    NL();
}

