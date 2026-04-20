// RIPEMD160 hash implementation for OpenCL
// 标准实现，修复变量轮换和填充长度错误

// RIPEMD160 functions
#define F0(x, y, z) (x ^ y ^ z)
#define F1(x, y, z) ((x & y) | (~x & z))
#define F2(x, y, z) ((x | ~y) ^ z)
#define F3(x, y, z) ((x & z) | (y & ~z))
#define F4(x, y, z) (x ^ (y | ~z))

#define ROL(x, n) ((x << n) | (x >> (32 - n)))

// RIPEMD160 constants
__constant uint K0[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
__constant uint K1[16] = {0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999};
__constant uint K2[16] = {0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1};
__constant uint K3[16] = {0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc};
__constant uint K4[16] = {0xa953fd4e, 0xa953fd4e, 0xa953fd4e, 0xa953fd4e, 0xa953fd4e, 0xa953fd4e, 0xa953fd4e, 0xa953fd4e, 0xa953fd4e, 0xa953fd4e, 0xa953fd4e, 0xa953fd4e, 0xa953fd4e, 0xa953fd4e, 0xa953fd4e, 0xa953fd4e};

__constant uint KK0[16] = {0x50a28be6, 0x50a28be6, 0x50a28be6, 0x50a28be6, 0x50a28be6, 0x50a28be6, 0x50a28be6, 0x50a28be6, 0x50a28be6, 0x50a28be6, 0x50a28be6, 0x50a28be6, 0x50a28be6, 0x50a28be6, 0x50a28be6, 0x50a28be6};
__constant uint KK1[16] = {0x5c4dd124, 0x5c4dd124, 0x5c4dd124, 0x5c4dd124, 0x5c4dd124, 0x5c4dd124, 0x5c4dd124, 0x5c4dd124, 0x5c4dd124, 0x5c4dd124, 0x5c4dd124, 0x5c4dd124, 0x5c4dd124, 0x5c4dd124, 0x5c4dd124, 0x5c4dd124};
__constant uint KK2[16] = {0x6d703ef3, 0x6d703ef3, 0x6d703ef3, 0x6d703ef3, 0x6d703ef3, 0x6d703ef3, 0x6d703ef3, 0x6d703ef3, 0x6d703ef3, 0x6d703ef3, 0x6d703ef3, 0x6d703ef3, 0x6d703ef3, 0x6d703ef3, 0x6d703ef3, 0x6d703ef3};
__constant uint KK3[16] = {0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9, 0x7a6d76e9};
__constant uint KK4[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// Message word selection
__constant int r0[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
__constant int r1[16] = {7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8};
__constant int r2[16] = {3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12};
__constant int r3[16] = {1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2};
__constant int r4[16] = {4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};

__constant int rr0[16] = {5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12};
__constant int rr1[16] = {6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2};
__constant int rr2[16] = {15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13};
__constant int rr3[16] = {8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14};
__constant int rr4[16] = {12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};

// Rotation amounts
__constant int s0[16] = {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8};
__constant int s1[16] = {7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12};
__constant int s2[16] = {11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5};
__constant int s3[16] = {11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12};
__constant int s4[16] = {9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};

__constant int ss0[16] = {8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6};
__constant int ss1[16] = {9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11};
__constant int ss2[16] = {9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5};
__constant int ss3[16] = {15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8};
__constant int ss4[16] = {8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};

// Initial hash values
__constant uint h0_init[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};

// Process one 512-bit block
void ripemd160_transform(uint* state, const uchar* block) {
    uint X[16];
    uint T;
    
    // Load message block (little-endian)
    for (int i = 0; i < 16; i++) {
        X[i] = (uint)block[i*4] | ((uint)block[i*4+1] << 8) | 
               ((uint)block[i*4+2] << 16) | ((uint)block[i*4+3] << 24);
    }
    
    // Initialize left line
    uint Al = state[0], Bl = state[1], Cl = state[2], Dl = state[3], El = state[4];
    // Initialize right line
    uint Ar = state[0], Br = state[1], Cr = state[2], Dr = state[3], Er = state[4];
    
    // ========== LEFT LINE ==========
    // Round 1
    for (int j = 0; j < 16; j++) {
        T = ROL(Al + F0(Bl, Cl, Dl) + X[r0[j]] + K0[j], s0[j]) + El;
        Al = El;
        El = Dl;
        Dl = ROL(Cl, 10);
        Cl = Bl;
        Bl = T;
    }
    
    // Round 2
    for (int j = 0; j < 16; j++) {
        T = ROL(Al + F1(Bl, Cl, Dl) + X[r1[j]] + K1[j], s1[j]) + El;
        Al = El;
        El = Dl;
        Dl = ROL(Cl, 10);
        Cl = Bl;
        Bl = T;
    }
    
    // Round 3
    for (int j = 0; j < 16; j++) {
        T = ROL(Al + F2(Bl, Cl, Dl) + X[r2[j]] + K2[j], s2[j]) + El;
        Al = El;
        El = Dl;
        Dl = ROL(Cl, 10);
        Cl = Bl;
        Bl = T;
    }
    
    // Round 4
    for (int j = 0; j < 16; j++) {
        T = ROL(Al + F3(Bl, Cl, Dl) + X[r3[j]] + K3[j], s3[j]) + El;
        Al = El;
        El = Dl;
        Dl = ROL(Cl, 10);
        Cl = Bl;
        Bl = T;
    }
    
    // Round 5
    for (int j = 0; j < 16; j++) {
        T = ROL(Al + F4(Bl, Cl, Dl) + X[r4[j]] + K4[j], s4[j]) + El;
        Al = El;
        El = Dl;
        Dl = ROL(Cl, 10);
        Cl = Bl;
        Bl = T;
    }
    
    // ========== RIGHT LINE ==========
    // Round 1
    for (int j = 0; j < 16; j++) {
        T = ROL(Ar + F4(Br, Cr, Dr) + X[rr0[j]] + KK0[j], ss0[j]) + Er;
        Ar = Er;
        Er = Dr;
        Dr = ROL(Cr, 10);
        Cr = Br;
        Br = T;
    }
    
    // Round 2
    for (int j = 0; j < 16; j++) {
        T = ROL(Ar + F3(Br, Cr, Dr) + X[rr1[j]] + KK1[j], ss1[j]) + Er;
        Ar = Er;
        Er = Dr;
        Dr = ROL(Cr, 10);
        Cr = Br;
        Br = T;
    }
    
    // Round 3
    for (int j = 0; j < 16; j++) {
        T = ROL(Ar + F2(Br, Cr, Dr) + X[rr2[j]] + KK2[j], ss2[j]) + Er;
        Ar = Er;
        Er = Dr;
        Dr = ROL(Cr, 10);
        Cr = Br;
        Br = T;
    }
    
    // Round 4
    for (int j = 0; j < 16; j++) {
        T = ROL(Ar + F1(Br, Cr, Dr) + X[rr3[j]] + KK3[j], ss3[j]) + Er;
        Ar = Er;
        Er = Dr;
        Dr = ROL(Cr, 10);
        Cr = Br;
        Br = T;
    }
    
    // Round 5
    for (int j = 0; j < 16; j++) {
        T = ROL(Ar + F0(Br, Cr, Dr) + X[rr4[j]] + KK4[j], ss4[j]) + Er;
        Ar = Er;
        Er = Dr;
        Dr = ROL(Cr, 10);
        Cr = Br;
        Br = T;
    }
    
    // Combine results
    T = state[1] + Cl + Dr;
    state[1] = state[2] + Dl + Er;
    state[2] = state[3] + El + Ar;
    state[3] = state[4] + Al + Br;
    state[4] = state[0] + Bl + Cr;
    state[0] = T;
}

// RIPEMD160 hash function
// input: data to hash
// input_len: length of data in bytes
// output: 20-byte hash
void ripemd160(const uchar* input, uint input_len, uchar* output) {
    uint state[5];
    uchar buffer[64];
    
    // Initialize state
    for (int i = 0; i < 5; i++) {
        state[i] = h0_init[i];
    }
    
    // Process all 512-bit blocks
    uint offset = 0;
    while (offset + 64 <= input_len) {
        ripemd160_transform(state, &input[offset]);
        offset += 64;
    }
    
    // Build final block(s)
    uint remaining = input_len - offset;
    for (uint i = 0; i < remaining; i++) {
        buffer[i] = input[offset + i];
    }
    
    // Padding
    buffer[remaining] = 0x80;
    
    // 使用 64 位比特长度（小端序）
    ulong bit_len = (ulong)input_len * 8;
    
    if (remaining < 56) {
        for (uint i = remaining + 1; i < 56; i++) {
            buffer[i] = 0;
        }
        // 填充 64 位比特长度（小端序）
        buffer[56] = (uchar)(bit_len);
        buffer[57] = (uchar)(bit_len >> 8);
        buffer[58] = (uchar)(bit_len >> 16);
        buffer[59] = (uchar)(bit_len >> 24);
        buffer[60] = (uchar)(bit_len >> 32);
        buffer[61] = (uchar)(bit_len >> 40);
        buffer[62] = (uchar)(bit_len >> 48);
        buffer[63] = (uchar)(bit_len >> 56);
        
        ripemd160_transform(state, buffer);
    } else {
        for (uint i = remaining + 1; i < 64; i++) {
            buffer[i] = 0;
        }
        ripemd160_transform(state, buffer);
        
        for (uint i = 0; i < 56; i++) {
            buffer[i] = 0;
        }
        // 填充 64 位比特长度（小端序）
        buffer[56] = (uchar)(bit_len);
        buffer[57] = (uchar)(bit_len >> 8);
        buffer[58] = (uchar)(bit_len >> 16);
        buffer[59] = (uchar)(bit_len >> 24);
        buffer[60] = (uchar)(bit_len >> 32);
        buffer[61] = (uchar)(bit_len >> 40);
        buffer[62] = (uchar)(bit_len >> 48);
        buffer[63] = (uchar)(bit_len >> 56);
        
        ripemd160_transform(state, buffer);
    }
    
    // Produce final hash value (little-endian)
    for (int i = 0; i < 5; i++) {
        output[i*4] = state[i] & 0xFF;
        output[i*4+1] = (state[i] >> 8) & 0xFF;
        output[i*4+2] = (state[i] >> 16) & 0xFF;
        output[i*4+3] = (state[i] >> 24) & 0xFF;
    }
}
