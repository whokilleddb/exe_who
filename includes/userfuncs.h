#include <stdio.h>
#include <windows.h>
#include <sysinfoapi.h>
#define NL() (printf("\n"))
#define LEN(x) ((int)(sizeof(x)/sizeof(x[0])))  // See: https://stackoverflow.com/questions/4415524/common-array-length-macro-for-c#:~:text=%23define%20length(array)%20(,((array)%5B0%5D))
#pragma once

// print hex
static inline void phex(unsigned char bytes[], int size) {
    for (int i=0; i<size; i++) {
        printf("0x%X ", bytes[i]);
    }
    NL();
}

void XOR(unsigned char * payload, unsigned int payload_len, const char * xor_key, unsigned int xor_key_len){
    int j = 0;
    for (int i = 0; i < payload_len; i++) {
        if (j == xor_key_len) j = 0;
        payload[i] = payload[i] ^ xor_key[j];
        j++;
    }
}
