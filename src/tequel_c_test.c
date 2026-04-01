#include "tequel.h"
#include <stdio.h>

int main() {

    uint8_t hash[48];
    char* msg = "Tequel in C";
    
    tequel_hash_raw((uint8_t*)msg, 20, hash);
    
    if (isv_tequel_hash_raw(hash, (uint8_t*)msg, 20)) {
        printf("Tequel: Validate with success in C!\n");
    }
    
    return 0;

}