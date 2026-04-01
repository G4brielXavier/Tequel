#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>


/**
 * @brief Tequel High-Density Hash (384-bit)
 * @param data Pointer to the input buffer
 * @param len Length of the input buffer
 * @param out Pointer to a 48-byte buffer to store the result
 */
void tequel_hash_raw(const uint8_t *data, uintptr_t len, uint8_t *out);

/**
 * @brief Tequel High-Density Hash (384-bit)
 * @param hash Pointer to the hash buffer
 * @param input Pointer to the input 48-byte buffer
 * @param input_len Length of the input buffer
 */
bool isv_tequel_hash_raw(const uint8_t* hash, const uint8_t* input, uintptr_t input_len);