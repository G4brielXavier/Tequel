## Tequel v0.7.0 

### 🚀 Added
- **Full AVX2 SIMD Support**: Implemented 32-byte chunk processing for both `encrypt` and `decrypt` using x86_64 intrinsics.
- **Synchronized Scalar Fallback**: Robust handling of data remainders and non-AVX2 hardware using a mirrored scalar loop.
- **Professional rustdoc**: Comprehensive English documentation for `encrypt` and `decrypt` including usage examples, security notes, and error handling.

### 🛠️ Fixed
- **UTF-8 Decoding Errors**: Resolved a critical phase-shift bug where the SIMD loop and the remainder loop used different constant indices, causing data corruption.
- **Symmetric Indexing**: Standardized the use of a Global Index (`g_idx`) across both encryption and decryption to ensure keystream alignment regardless of data size.
- **Inverse Ladder Logic**: Corrected the decryption sequence to be the exact mathematical mirror of the encryption ladder (Verify-then-Decrypt).

### ⚡ Optimized
- **Zero-Allocation MAC Construction**: Replaced slow `String` and `format!` operations with a pre-allocated `Vec<u8>` buffer (`mixmac_buffer`).
- **Hex-to-Byte Integrity**: The MAC now processes raw bytes instead of hex strings, significantly reducing CPU overhead and memory pressure.
- **Buffer Management**: Implemented `with_capacity` in all internal buffers to prevent heap fragmentation during processing.

### ⚠️ Security
- **Integrity Enforcement**: Hardened the `decrypt` function to strictly follow the "Verify-then-Decrypt" pattern, ensuring no data is processed if the MAC check fails.