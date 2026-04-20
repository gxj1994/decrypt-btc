// GPU调试内核 - 输出中间计算结果用于对比
// 这个内核会计算完整的地址生成流程，并将每一步的结果写入缓冲区
// 包含BIP32派生路径

#ifndef MNEMONIC_SIZE
#define MNEMONIC_SIZE 12
#endif

// HASH160函数定义（因为不加载search.cl）
void hash160(const uchar* data, uint data_len, uchar output[20]) {
    uchar sha256_result[32];
    sha256(data, data_len, sha256_result);
    ripemd160(sha256_result, 32, output);
}

// 调试内核
__kernel void debug_address_generation(
    __global const uint* word_indices,        // 助记词单词索引数组
    uint mnemonic_size,                       // 助记词长度（单词数量）
    __global const uchar* password,         // 密码
    uint password_len,                      // 密码长度
    __global uchar* output_seed,            // 输出：PBKDF2种子 (64字节)
    __global uchar* output_master_key,      // 输出：BIP32主密钥 (32字节)
    __global uchar* output_master_chain,    // 输出：BIP32主链码 (32字节)
    __global uchar* output_private_key,     // 输出：BIP32私钥 (32字节)
    __global uchar* output_public_key,      // 输出：公钥 (65字节)
    __global uchar* output_sha256,          // 输出：SHA256(公钥) (32字节)
    __global uchar* output_pubkey_hash,     // 输出：公钥哈希 (20字节)
    __global uchar* output_address          // 输出：完整地址 (25字节，含版本号和checksum)
) {
    uint global_id = get_global_id(0);
    
    // 步骤1: 根据单词索引构建助记词字符串
    uchar local_mnemonic[512];
    uchar mnemonic_len = 0;
    
    for (uint i = 0; i < mnemonic_size; i++) {
        // 添加空格分隔符（第一个单词前不加）
        if (i > 0) {
            if (mnemonic_len < 511) {
                local_mnemonic[mnemonic_len++] = ' ';
            }
        }
        
        // 复制单词
        uint word_idx = word_indices[i];
        uchar word_len = copy_word(word_idx, local_mnemonic + mnemonic_len, 511 - mnemonic_len);
        mnemonic_len += word_len;
    }
    
    // 填充剩余位为0
    for (uint i = mnemonic_size; i < 24; i++) {
        // 不需要，因为已经用mnemonic_len控制长度
    }
    
    // 步骤2: PBKDF2-HMAC-SHA512 计算种子
    seed_t seed;
    uchar salt[512];
    
    // 构建salt = "mnemonic" + password
    const uchar mnemonic_salt[] = "mnemonic";
    uint salt_len = 8;
    for (uint i = 0; i < 8; i++) {
        salt[i] = mnemonic_salt[i];
    }
    for (uint i = 0; i < password_len && i < 120; i++) {
        salt[8 + i] = password[i];
        salt_len++;
    }
    
    // 调用PBKDF2
    pbkdf2_hmac_sha512(local_mnemonic, mnemonic_len, salt, salt_len, 2048, seed.bytes, 64);
    
    // 输出种子
    for (int i = 0; i < 64; i++) {
        output_seed[i] = seed.bytes[i];
    }
        
    // 步骤3: BIP32主密钥生成
    uchar master_key[64];
    seed_to_master_key(&seed, master_key);
        
    // 输出主密钥和链码
    for (int i = 0; i < 32; i++) {
        output_master_key[i] = master_key[i];
        output_master_chain[i] = master_key[32 + i];
    }
        
    // 步顤4: BIP32派生私钥 (m/44'/0'/0'/0/0)
    uchar private_key[32];
    derive_path(&seed, DERIVATION_PATH, 5, private_key);
    
    // 输出私钥
    for (int i = 0; i < 32; i++) {
        output_private_key[i] = private_key[i];
    }
    
    // 步顤4: secp256k1计算公钥
    uchar public_key[65];
    // 先将private_key从__global复制到__private
    uchar private_key_local[32];
    for (int i = 0; i < 32; i++) {
        private_key_local[i] = private_key[i];
    }
    private_to_public(private_key_local, public_key);
        
    // 输出公钥（未压缩）
    for (int i = 0; i < 65; i++) {
        output_public_key[i] = public_key[i];
    }
        
    // 步骤5: HASH160(公钥)
    // 比特币Legacy地址使用压缩公钥格式：0x02/0x03 + X坐标
    uchar compressed_key[33];
    compressed_key[0] = (public_key[64] & 1) ? 0x03 : 0x02;  // 根据Y坐标的奇偶性
    for (int i = 0; i < 32; i++) {
        compressed_key[1 + i] = public_key[1 + i];  // X坐标
    }
        
    uchar sha256_result[32];
    sha256(compressed_key, 33, sha256_result);
        
    // 输出SHA256结果
    for (int i = 0; i < 32; i++) {
        output_sha256[i] = sha256_result[i];
    }
        
    // RIPEMD160
    uchar pubkey_hash[20];
    ripemd160(sha256_result, 32, pubkey_hash);
    
    // 输出公钥哈希
    for (int i = 0; i < 20; i++) {
        output_pubkey_hash[i] = pubkey_hash[i];
    }
    
    // 步骤6: 构建完整地址（版本号 + pubkey_hash + checksum）
    uchar address_temp[25];
    address_temp[0] = 0x00;
    for (int i = 0; i < 20; i++) {
        address_temp[1 + i] = pubkey_hash[i];
    }
    
    uchar hash1[32], hash2[32];
    sha256(address_temp, 21, hash1);
    sha256(hash1, 32, hash2);
    for (int i = 0; i < 4; i++) {
        address_temp[21 + i] = hash2[i];
    }
    
    for (int i = 0; i < 25; i++) {
        output_address[i] = address_temp[i];
    }
}
