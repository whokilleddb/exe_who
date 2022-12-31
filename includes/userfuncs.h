#include <windows.h>
#include <sysinfoapi.h>
#pragma once

// print new line
static inline nl(){
    printf("\n");
}

// print hex
static inline phex(unsigned char bytes[], int size) {
    for (int i=0; i<size; i++) {
        printf("0x%X ", bytes[i]);
    }
}

