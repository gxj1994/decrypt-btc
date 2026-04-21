// BTC Legacy 地址搜索主内核
// 完整实现GPU内的BIP39助记词到BTC地址的转换和匹配
// 流程: 助记词索引 → 助记词字符串 → PBKDF2 → 种子 → BIP32派生 → 私钥 → 公钥 → HASH160 → 地址
// 整合所有加密算法：SHA256, RIPEMD160, SHA512, PBKDF2, secp256k1, BIP32
// 集成BIP39校验位验证（减少93.75%无效计算）

// 注意：所有依赖内核文件在Rust端合并，不需要#include
// #include "crypto/sha256.cl"
// #include "crypto/ripemd160.cl"
// #include "crypto/sha512.cl"
// #include "crypto/pbkdf2.cl"
// #include "crypto/secp256k1.cl"
// #include "bip39/wordlist.cl"
// #include "bip39/checksum.cl"
// #include "bip39/mnemonic.cl"  // 包含BIP32派生

// 搜索参数（可通过编译选项配置）
#ifndef MNEMONIC_SIZE
#define MNEMONIC_SIZE 12  // 可配置: 12/15/18/21/24
#endif

// 注意：local_mnemonic_t 已在 mnemonic.cl 中定义

// 辅助函数：HASH160 = RIPEMD160(SHA256(data))
void hash160(const uchar* data, uint data_len, uchar output[20]) {
    uchar sha256_result[32];
    sha256(data, data_len, sha256_result);
    ripemd160(sha256_result, 32, output);
}

// 主内核函数
__kernel void btc_address_search(
    __global const uint* word_indices,      // 每个位置的候选词索引
    __constant const uchar* target_hash,    // 目标公钥哈希(20字节)
    __global const uchar* salt,             // 预计算的salt ("mnemonic" + passphrase)
    uint salt_len,                          // salt长度
    __global uint* result_buffer,           // 结果缓冲区
    __global uint* stats_counter            // 统计计数器
) {
    // 获取全局工作项ID
    uint global_id = get_global_id(0);
    
    // 步骤1: 根据global_id和候选词配置，计算当前工作项的助记词
    local_mnemonic_t mnemonic;
    
    uint remaining_id = global_id;
    uint word_pos_offset = 0; // word_indices数组中的当前位置
    
    for (uint i = 0; i < MNEMONIC_SIZE; i++) {
        // 读取当前位置的候选词数量
        uint candidates_count = word_indices[word_pos_offset];
        word_pos_offset++;
        
        // 计算当前工作项在这个位置应该选哪个候选词
        uint choice = remaining_id % candidates_count;
        remaining_id /= candidates_count;
        
        // 读取选中的候选词索引
        mnemonic.words[i] = (ushort)word_indices[word_pos_offset + choice];
        
        // 移动到下一个位置（跳过所有候选词）
        word_pos_offset += candidates_count;
    }
    
    // 填充剩余位为0
    for (uint i = MNEMONIC_SIZE; i < 24; i++) {
        mnemonic.words[i] = 0;
    }
    
    // 步骤2: BIP39校验位验证（重要优化！）
    // 在PBKDF2之前验证，可过滤93.75%的无效助记词
    uint mnemonic_indices[24];
    for (uint i = 0; i < MNEMONIC_SIZE; i++) {
        mnemonic_indices[i] = mnemonic.words[i];
    }
    // 填充剩余位为0
    for (uint i = MNEMONIC_SIZE; i < 24; i++) {
        mnemonic_indices[i] = 0;
    }
    
    // 验证BIP39校验位
    if (!validate_bip39_checksum_fast(mnemonic_indices, MNEMONIC_SIZE)) {
        // 校验失败，跳过这个助记词
        atomic_inc(stats_counter);
        return;
    }
    
    // 步骤3: 助记词 → 种子 (PBKDF2-HMAC-SHA512)
    seed_t seed;
    
    // 构建助记词字符串
    uchar mnemonic_str[256];
    uchar mnemonic_len = mnemonic_to_string(&mnemonic, mnemonic_str, 255);
    
    // 将__global的salt复制到__private数组（PBKDF2需要__private地址空间）
    uchar salt_local[256];
    for (uint i = 0; i < salt_len && i < 256; i++) {
        salt_local[i] = salt[i];
    }
    
    // 使用预计算的salt（CPU端已构建好 "mnemonic" + passphrase）
    // 调用PBKDF2
    pbkdf2_hmac_sha512(mnemonic_str, mnemonic_len, salt_local, salt_len, 2048, seed.bytes, 64);
    
    // 步骤4: BIP32派生私钥 (m/44'/0'/0'/0/0)
    uchar private_key[32];
    derive_path(&seed, DERIVATION_PATH, 5, private_key);
    
    // 步骤5: secp256k1 计算公钥
    uchar public_key_uncompressed[65];
    private_to_public(private_key, public_key_uncompressed);
    
    // 步骤6: HASH160(压缩公钥)
    // 比特币Legacy地址使用压缩公钥格式：0x02/0x03 + X坐标
    uchar compressed_key[33];
    compressed_key[0] = (public_key_uncompressed[64] & 1) ? 0x03 : 0x02;  // 根据Y坐标的奇偶性
    for (int i = 0; i < 32; i++) {
        compressed_key[1 + i] = public_key_uncompressed[1 + i];  // X坐标
    }
    
    uchar pubkey_hash[20];
    hash160(compressed_key, 33, pubkey_hash);
    
    // 步骤7: 对比目标哈希
    // 步骤7: 对比目标哈希
    bool match = true;
    for (int i = 0; i < 20; i++) {
        if (pubkey_hash[i] != target_hash[i]) {
            match = false;
            break;
        }
    }
    
    // 如果匹配，记录结果
    if (match) {
        // 使用原子操作写入结果
        uint result_idx = atomic_inc(&result_buffer[0]);
        
        // 存储找到的索引
        result_buffer[1 + result_idx * (MNEMONIC_SIZE + 2)] = global_id;
        
        // 存储助记词索引
        for (uint i = 0; i < MNEMONIC_SIZE; i++) {
            result_buffer[1 + result_idx * (MNEMONIC_SIZE + 2) + 1 + i] = mnemonic.words[i];
        }
    }
    
    // 更新统计计数器
    atomic_inc(stats_counter);
}
