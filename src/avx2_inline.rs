use std::arch::x86_64::*;


#[inline(always)]
pub unsafe fn loadu(src: *const __m256i) -> __m256i {
    unsafe { _mm256_loadu_si256(src as *const __m256i) }
}


#[inline(always)]
pub unsafe fn storeu(dest: *mut __m256i, src: __m256i) {
    unsafe { _mm256_storeu_si256(dest, src) }
}


#[inline(always)]
pub unsafe fn add(a: __m256i, b: __m256i) -> __m256i {
    unsafe { _mm256_add_epi32(a, b) }
}


#[inline(always)]
pub unsafe fn add_i8(a: __m256i, b: __m256i) -> __m256i {
    unsafe { _mm256_add_epi8(a, b) }
}


#[inline(always)]
pub unsafe fn sub(a: __m256i, b: __m256i) -> __m256i {
    unsafe { _mm256_sub_epi32(a, b) }
}


#[inline(always)]
pub unsafe fn sub_i8(a: __m256i, b: __m256i) -> __m256i {
    unsafe { _mm256_sub_epi8(a, b) }
}


#[inline(always)]
pub unsafe fn xor(a: __m256i, b: __m256i) -> __m256i {
    unsafe { _mm256_xor_si256(a, b) }
}


#[inline(always)]
pub unsafe fn or(a: __m256i, b: __m256i) -> __m256i {
    unsafe { _mm256_or_si256(a, b) }
}


#[inline(always)]
pub unsafe fn setzero() -> __m256i {
    unsafe { _mm256_setzero_si256() }
}


#[inline(always)]
pub unsafe fn setone_i8(v: i8) -> __m256i {
    unsafe { _mm256_set1_epi8(v) }
}

#[inline(always)]
pub unsafe fn setone_i32(v: i32) -> __m256i {
    unsafe { _mm256_set1_epi32(v) }
}


#[inline(always)]
pub unsafe fn rota_lf<const IMM8: i32>(c: __m256i) -> __m256i {
    unsafe { _mm256_slli_epi32(c, IMM8) }
}


#[inline(always)]
pub unsafe fn rota_rg<const IMM8: i32>(c: __m256i) -> __m256i {
    unsafe { _mm256_srli_epi32(c, IMM8) }
}



#[inline(always)]
pub unsafe fn horiz_add_avx2(v: __m256i) -> u32 {
    let mut arr = [0u32; 8];
    
    unsafe { storeu(arr.as_mut_ptr() as *mut __m256i, v) };          

    arr.iter().fold(0, |acc, &x| acc.wrapping_add(x))
}