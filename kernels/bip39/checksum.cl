// BIP39 校验位验证 (OpenCL)
// 在PBKDF2之前验证助记词有效性，可减少93.75%的无效计算

#ifndef BIP39_CHECKSUM_CL
#define BIP39_CHECKSUM_CL

// 注意：所有依赖内核文件在Rust端合并，不需要#include
// #include "crypto/sha256.cl"

// BIP39校验位验证
// 根据BIP39规范，助记词的最后一个单词包含校验位
// 12词: 128位熵 + 4位校验 = 132位 (12*11)
// 15词: 160位熵 + 5位校验 = 165位 (15*11)
// 18词: 192位熵 + 6位校验 = 198位 (18*11)
// 21词: 224位熵 + 7位校验 = 231位 (21*11)
// 24词: 256位熵 + 8位校验 = 264位 (24*11)

// 根据助记词数量获取熵位数
uint get_entropy_bits(uint mnemonic_count) {
    switch (mnemonic_count) {
        case 12: return 128;
        case 15: return 160;
        case 18: return 192;
        case 21: return 224;
        case 24: return 256;
        default: return 0;
    }
}

// 根据助记词数量获取校验位数
uint get_checksum_bits(uint mnemonic_count) {
    switch (mnemonic_count) {
        case 12: return 4;
        case 15: return 5;
        case 18: return 6;
        case 21: return 7;
        case 24: return 8;
        default: return 0;
    }
}

// 从助记词索引数组中提取熵位
// 将助记词索引转换为位数组，然后提取熵位
void extract_entropy(const uint* mnemonic_indices, uint mnemonic_count, 
                     uchar* entropy_bytes, uint entropy_bits) {
    // 总位数 = mnemonic_count * 11
    uint total_bits = mnemonic_count * 11;
    
    // 清空输出
    uint byte_count = (entropy_bits + 7) / 8;
    for (uint i = 0; i < byte_count; i++) {
        entropy_bytes[i] = 0;
    }
    
    // 从助记词索引中提取位
    uint bit_pos = 0;
    for (uint i = 0; i < mnemonic_count && bit_pos < entropy_bits; i++) {
        uint index = mnemonic_indices[i];
        
        // 每个索引11位，从最高位开始
        for (int j = 10; j >= 0 && bit_pos < entropy_bits; j--) {
            uint bit = (index >> j) & 1;
            
            uint byte_idx = bit_pos / 8;
            uint bit_idx = 7 - (bit_pos % 8);  // 大端序
            
            if (bit) {
                entropy_bytes[byte_idx] |= (1 << bit_idx);
            }
            
            bit_pos++;
        }
    }
}

// 计算熵的SHA256哈希，并提取校验位
void compute_checksum_bits(const uchar* entropy_bytes, uint entropy_bits,
                           uchar* checksum_bits, uint checksum_bit_count) {
    // 计算SHA256
    uchar hash[32];
    sha256(entropy_bytes, (entropy_bits + 7) / 8, hash);
    
    // 从哈希中提取校验位（从最高位开始）
    for (uint i = 0; i < checksum_bit_count; i++) {
        uint bit_idx = i;
        uint byte_idx = bit_idx / 8;
        uint bit_offset = 7 - (bit_idx % 8);  // 大端序
        
        checksum_bits[i] = (hash[byte_idx] >> bit_offset) & 1;
    }
}

// 从助记词中提取校验位（最后一个单词的低几位）
void extract_checksum_from_mnemonic(const uint* mnemonic_indices, 
                                    uint mnemonic_count,
                                    uchar* checksum_bits, 
                                    uint checksum_bit_count) {
    // 最后一个单词的索引
    uint last_word_index = mnemonic_indices[mnemonic_count - 1];
    
    // 校验位在最后一个单词的最低位
    // 提取最低checksum_bit_count位
    for (uint i = 0; i < checksum_bit_count; i++) {
        checksum_bits[i] = (last_word_index >> i) & 1;
    }
}

// 验证BIP39校验位
// 返回: true = 有效, false = 无效
bool validate_bip39_checksum(const uint* mnemonic_indices, uint mnemonic_count) {
    // 获取熵位和校验位数
    uint entropy_bits = get_entropy_bits(mnemonic_count);
    uint checksum_bits_count = get_checksum_bits(mnemonic_count);
    
    if (entropy_bits == 0 || checksum_bits_count == 0) {
        return false;  // 无效的助记词数量
    }
    
    // 提取熵
    uchar entropy_bytes[32];  // 最大256位 = 32字节
    extract_entropy(mnemonic_indices, mnemonic_count, entropy_bytes, entropy_bits);
    
    // 计算期望的校验位
    uchar expected_checksum[8];  // 最大8位
    compute_checksum_bits(entropy_bytes, entropy_bits, expected_checksum, checksum_bits_count);
    
    // 从助记词中提取实际校验位
    uchar actual_checksum[8];
    extract_checksum_from_mnemonic(mnemonic_indices, mnemonic_count, 
                                   actual_checksum, checksum_bits_count);
    
    // 对比校验位
    for (uint i = 0; i < checksum_bits_count; i++) {
        if (expected_checksum[i] != actual_checksum[i]) {
            return false;
        }
    }
    
    return true;
}

// 优化的快速验证版本（使用位运算）
// 适用于在内核中快速过滤
bool validate_bip39_checksum_fast(const uint* mnemonic_indices, uint mnemonic_count) {
    // 获取熵位和校验位数
    uint entropy_bits = get_entropy_bits(mnemonic_count);
    uint checksum_bits_count = get_checksum_bits(mnemonic_count);
    
    if (entropy_bits == 0) {
        return false;
    }
    
    // 提取熵字节
    uchar entropy_bytes[32];
    uint byte_count = (entropy_bits + 7) / 8;
    
    uint bit_pos = 0;
    for (uint i = 0; i < byte_count; i++) {
        entropy_bytes[i] = 0;
    }
    
    for (uint i = 0; i < mnemonic_count && bit_pos < entropy_bits; i++) {
        uint index = mnemonic_indices[i];
        for (int j = 10; j >= 0 && bit_pos < entropy_bits; j--) {
            uint bit = (index >> j) & 1;
            uint byte_idx = bit_pos / 8;
            uint bit_idx = 7 - (bit_pos % 8);
            if (bit) {
                entropy_bytes[byte_idx] |= (1 << bit_idx);
            }
            bit_pos++;
        }
    }
    
    // SHA256哈希
    uchar hash[32];
    sha256(entropy_bytes, byte_count, hash);
    
    // 提取期望的校验位（从hash的第一个字节的高位）
    uint expected_checksum = 0;
    for (uint i = 0; i < checksum_bits_count; i++) {
        uint byte_idx = i / 8;
        uint bit_idx = 7 - (i % 8);
        uint bit = (hash[byte_idx] >> bit_idx) & 1;
        expected_checksum |= (bit << i);
    }
    
    // 提取实际的校验位（从最后一个单词的低位）
    uint actual_checksum = mnemonic_indices[mnemonic_count - 1] & ((1 << checksum_bits_count) - 1);
    
    return expected_checksum == actual_checksum;
}

#endif // BIP39_CHECKSUM_CL
