// BIP39 校验位验证 (OpenCL)
// 在PBKDF2之前验证助记词有效性，可减少93.75%的无效计算
// 参考: rust-profanity-ref/kernels/bip39/entropy.cl 的 mnemonic_to_entropy 函数

#ifndef BIP39_CHECKSUM_CL
#define BIP39_CHECKSUM_CL

// 注意：所有依赖内核文件在Rust端合并，不需要#include
// #include "crypto/sha256.cl"

// 验证BIP39校验位（支持12/15/18/21/24词）
// mnemonic_indices: 助记词索引数组
// mnemonic_count: 助记词数量（12/15/18/21/24）
// 返回: true = 校验通过, false = 校验失败
bool validate_bip39_checksum(const uint* mnemonic_indices, uint mnemonic_count) {
    // 根据助记词数量确定熵位数和校验位数
    uint entropy_bits;
    uint checksum_bits_count;
    
    switch (mnemonic_count) {
        case 12: entropy_bits = 128; checksum_bits_count = 4; break;
        case 15: entropy_bits = 160; checksum_bits_count = 5; break;
        case 18: entropy_bits = 192; checksum_bits_count = 6; break;
        case 21: entropy_bits = 224; checksum_bits_count = 7; break;
        case 24: entropy_bits = 256; checksum_bits_count = 8; break;
        default: return false;
    }
    
    // 总位数 = 熵位 + 校验位
    uint total_bits = entropy_bits + checksum_bits_count;
    
    // 从助记词索引重建位流
    // all_bits数组大小：24词时需要264位=33字节
    uchar all_bits[33];
    for (uint i = 0; i < 33; i++) {
        all_bits[i] = 0;
    }
    
    // 将每个助记词索引（11位）写入位流
    for (uint i = 0; i < mnemonic_count; i++) {
        uint word_idx = mnemonic_indices[i];
        int bit_offset = i * 11;
        
        // 提取11位，写入all_bits
        for (int j = 0; j < 11; j++) {
            int bit_pos = bit_offset + j;
            int byte_idx = bit_pos / 8;
            int bit_in_byte = 7 - (bit_pos % 8);  // 大端序
            
            // 如果该位为1，设置到all_bits中
            if ((word_idx >> (10 - j)) & 1) {
                all_bits[byte_idx] |= (1 << bit_in_byte);
            }
        }
    }
    
    // 提取熵字节（前entropy_bits位）
    uchar entropy[32];
    uint entropy_bytes = (entropy_bits + 7) / 8;
    for (uint i = 0; i < entropy_bytes; i++) {
        entropy[i] = all_bits[i];
    }
    
    // 提取实际校验位（位流的最后几位）
    // 校验位在all_bits中的位置：从entropy_bits开始
    uchar actual_checksum = 0;
    for (uint i = 0; i < checksum_bits_count; i++) {
        int bit_pos = entropy_bits + i;
        int byte_idx = bit_pos / 8;
        int bit_in_byte = 7 - (bit_pos % 8);
        
        if (all_bits[byte_idx] & (1 << bit_in_byte)) {
            actual_checksum |= (1 << (checksum_bits_count - 1 - i));
        }
    }
    
    // 计算熵的SHA256
    uchar hash[32];
    sha256(entropy, entropy_bytes, hash);
    
    // 从SHA256哈希中提取期望的校验位（取hash[0]的前checksum_bits_count位）
    uchar expected_checksum = hash[0] >> (8 - checksum_bits_count);
    
    // 对比校验位
    return actual_checksum == expected_checksum;
}

// 优化的快速验证版本（仅支持24词，使用位运算优化）
// 适用于在内核中快速过滤
bool validate_bip39_checksum_fast(const uint* mnemonic_indices, uint mnemonic_count) {
    // 仅支持24词
    if (mnemonic_count != 24) {
        // 对于其他长度，使用通用版本
        return validate_bip39_checksum(mnemonic_indices, mnemonic_count);
    }
    
    // 24词: 256位熵 + 8位校验 = 264位
    // 重建位流
    uchar all_bits[33];
    for (uint i = 0; i < 33; i++) {
        all_bits[i] = 0;
    }
    
    for (uint i = 0; i < 24; i++) {
        uint word_idx = mnemonic_indices[i];
        int bit_offset = i * 11;
        
        for (int j = 0; j < 11; j++) {
            int bit_pos = bit_offset + j;
            int byte_idx = bit_pos / 8;
            int bit_in_byte = 7 - (bit_pos % 8);
            
            if ((word_idx >> (10 - j)) & 1) {
                all_bits[byte_idx] |= (1 << bit_in_byte);
            }
        }
    }
    
    // 提取熵（前32字节）
    uchar entropy[32];
    for (uint i = 0; i < 32; i++) {
        entropy[i] = all_bits[i];
    }
    
    // 提取实际校验位（all_bits[32]）
    uchar actual_checksum = all_bits[32];
    
    // 计算SHA256
    uchar hash[32];
    sha256(entropy, 32, hash);
    
    // 期望校验位（hash[0]）
    uchar expected_checksum = hash[0];
    
    return actual_checksum == expected_checksum;
}

#endif // BIP39_CHECKSUM_CL
