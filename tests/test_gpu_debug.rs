// GPU分步调试测试 - 对比CPU和GPU的每一步计算

use decrypt_btc::address;
use decrypt_btc::mnemonic::Bip39Wordlist;
use ocl::{Buffer, MemFlags, ProQue};

/// 加载所有内核源文件
fn load_all_kernel_sources() -> String {
    let kernel_files = vec![
        "kernels/crypto/sha256.cl",
        "kernels/crypto/ripemd160.cl",
        "kernels/crypto/sha512.cl",
        "kernels/crypto/pbkdf2.cl",
        "kernels/crypto/secp256k1.cl",
        "kernels/bip39/wordlist.cl",
        "kernels/bip39/checksum.cl",
        "kernels/bip39/mnemonic.cl", // BIP32派生
        "kernels/debug.cl",
    ];

    let mut source = String::new();
    for file in &kernel_files {
        let content =
            std::fs::read_to_string(file).unwrap_or_else(|_| panic!("无法加载内核文件: {}", file));
        source.push_str(&content);
        source.push_str("\n\n");
    }
    source
}

/// GPU调试：输出每一步的中间结果
fn gpu_debug_compute(
    word_indices: &[u32], // 助记词单词索引数组
    passphrase: &str,
    _wordlist: &Bip39Wordlist,
) -> Result<GpuDebugOutput, Box<dyn std::error::Error>> {
    let source = load_all_kernel_sources();
    let mnemonic_size = word_indices.len() as u32;

    // CPU端预计算salt = "mnemonic" + passphrase
    let salt = if passphrase.is_empty() {
        b"mnemonic".to_vec()
    } else {
        let mut salt = Vec::new();
        salt.extend_from_slice(b"mnemonic");
        salt.extend_from_slice(passphrase.as_bytes());
        salt
    };
    let salt_len = salt.len() as u32;

    // 创建ProQue
    let proque = ProQue::builder().src(source).dims(1).build()?;

    // 创建缓冲区 - 使用单词索引而不是字符串
    let mnemonic_buffer = Buffer::<u32>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::READ_ONLY)
        .len(word_indices.len())
        .copy_host_slice(word_indices)
        .build()?;

    let salt_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::READ_ONLY)
        .len(salt.len())
        .copy_host_slice(&salt)
        .build()?;

    let seed_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(64)
        .build()?;

    let private_key_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(32)
        .build()?;

    let public_key_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(65)
        .build()?;

    let pubkey_hash_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(20)
        .build()?;

    let sha256_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(32)
        .build()?;

    let master_key_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(32)
        .build()?;

    let master_chain_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(32)
        .build()?;

    let address_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .flags(MemFlags::WRITE_ONLY)
        .len(25)
        .build()?;

    // 创建内核
    let kernel = proque
        .kernel_builder("debug_address_generation")
        .arg(&mnemonic_buffer)
        .arg(mnemonic_size)
        .arg(&salt_buffer)
        .arg(salt_len)
        .arg(&seed_buffer)
        .arg(&master_key_buffer)
        .arg(&master_chain_buffer)
        .arg(&private_key_buffer)
        .arg(&public_key_buffer)
        .arg(&sha256_buffer)
        .arg(&pubkey_hash_buffer)
        .arg(&address_buffer)
        .build()?;

    // 执行
    unsafe {
        kernel.enq()?;
    }

    // 读取结果
    let mut seed = vec![0u8; 64];
    seed_buffer.read(&mut seed).enq()?;

    let mut master_key = vec![0u8; 32];
    master_key_buffer.read(&mut master_key).enq()?;

    let mut master_chain = vec![0u8; 32];
    master_chain_buffer.read(&mut master_chain).enq()?;

    let mut private_key = vec![0u8; 32];
    private_key_buffer.read(&mut private_key).enq()?;

    let mut public_key = vec![0u8; 65];
    public_key_buffer.read(&mut public_key).enq()?;

    let mut sha256_result = vec![0u8; 32];
    sha256_buffer.read(&mut sha256_result).enq()?;

    let mut pubkey_hash = vec![0u8; 20];
    pubkey_hash_buffer.read(&mut pubkey_hash).enq()?;

    let mut address_bytes = vec![0u8; 25];
    address_buffer.read(&mut address_bytes).enq()?;

    Ok(GpuDebugOutput {
        seed,
        master_key,
        master_chain,
        private_key,
        public_key,
        sha256_result,
        pubkey_hash,
        _address_bytes: address_bytes,
    })
}

struct GpuDebugOutput {
    seed: Vec<u8>,
    master_key: Vec<u8>,
    master_chain: Vec<u8>,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    sha256_result: Vec<u8>,
    pubkey_hash: Vec<u8>,
    _address_bytes: Vec<u8>, // 保留用于未来调试
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_debug_step_by_step() {
        // 使用简单的固定助记词
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "";

        println!("\n=== GPU分步调试 ===");
        println!("助记词: {}", mnemonic);
        println!("密码: '{}'\n", passphrase);

        // 加载单词表
        let wordlist = Bip39Wordlist::load("data/english.txt").unwrap();

        // 将助记词转换为单词索引
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        let mut word_indices = Vec::new();
        for word in &words {
            let index = wordlist.get_index(word).expect("单词不在词表中");
            word_indices.push(index as u32);
        }

        println!("单词索引: {:?}", word_indices);

        // CPU端计算
        println!("--- CPU端计算 ---");

        // 打印助记词字节
        print!("助记词字节: ");
        for byte in &mnemonic.as_bytes()[..20] {
            print!("{:02x} ", byte);
        }
        println!("...");
        println!("助记词长度: {} 字节\n", mnemonic.len());

        let cpu_address =
            address::mnemonic_to_address(mnemonic, passphrase).expect("CPU地址计算失败");
        println!("CPU地址: {}", cpu_address);

        // 计算CPU的pubkey_hash（使用标准库生成的地址解码，而不是自己计算HASH160）
        let cpu_pubkey_hash = address::mnemonic_to_pubkey_hash(mnemonic, passphrase)
            .expect("CPU pubkey_hash计算失败");

        print!("CPU pubkey_hash: ");
        for byte in &cpu_pubkey_hash {
            print!("{:02x}", byte);
        }
        println!();

        // 为了调试，也从地址解码SHA256和RIPEMD160的结果
        // 注意：由于bitcoin::PublicKey的序列化API限制，我们直接从地址反推
        // 实际的SHA256和RIPEMD160计算在GPU内核中进行
        // 不需要对比SHA256，只对比最终的pubkey_hash

        print!("CPU pubkey_hash: ");
        for byte in &cpu_pubkey_hash {
            print!("{:02x}", byte);
        }
        println!();

        // 计算CPU种子（用于对比）
        use hmac::{Hmac, Mac};
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha512;

        type HmacSha512 = Hmac<Sha512>;

        let mut cpu_seed = vec![0u8; 64];
        pbkdf2_hmac::<Sha512>(
            mnemonic.as_bytes(),
            format!("mnemonic{}", passphrase).as_bytes(),
            2048,
            &mut cpu_seed,
        );
        print!("CPU seed: ");
        for byte in &cpu_seed[..8] {
            print!("{:02x}", byte);
        }
        println!("...");

        // 计算CPU的BIP32私钥
        let cpu_address_full =
            address::mnemonic_to_address(mnemonic, passphrase).expect("CPU地址计算失败");
        let cpu_pubkey_hash_full =
            address::base58check_decode(&cpu_address_full).expect("CPU地址解码失败");
        print!("CPU pubkey_hash (with BIP32): ");
        for byte in &cpu_pubkey_hash_full {
            print!("{:02x}", byte);
        }
        println!("...\n");

        // 额外调试：打印CPU的master key
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").unwrap();
        mac.update(&cpu_seed);
        let master_key_result = mac.finalize().into_bytes();

        print!("CPU master_key: ");
        for byte in &master_key_result[..8] {
            print!("{:02x}", byte);
        }
        println!("...");

        print!("CPU master_chain: ");
        for byte in &master_key_result[32..40] {
            print!("{:02x}", byte);
        }
        println!("...\n");

        // GPU端计算
        println!("--- GPU端计算 ---");
        match gpu_debug_compute(&word_indices, passphrase, &wordlist) {
            Ok(gpu_output) => {
                print!("GPU seed: ");
                for byte in &gpu_output.seed[..8] {
                    print!("{:02x}", byte);
                }
                println!("...");

                print!("GPU master_key: ");
                for byte in &gpu_output.master_key[..8] {
                    print!("{:02x}", byte);
                }
                println!("...");

                print!("GPU master_chain: ");
                for byte in &gpu_output.master_chain[..8] {
                    print!("{:02x}", byte);
                }
                println!("...");

                print!("GPU private_key: ");
                for byte in &gpu_output.private_key[..8] {
                    print!("{:02x}", byte);
                }
                println!("...");

                print!("GPU public_key (65 bytes): ");
                for byte in &gpu_output.public_key {
                    print!("{:02x}", byte);
                }
                println!();

                print!("GPU sha256 (32 bytes): ");
                for byte in &gpu_output.sha256_result {
                    print!("{:02x}", byte);
                }
                println!();

                print!("GPU pubkey_hash: ");
                for byte in &gpu_output.pubkey_hash {
                    print!("{:02x}", byte);
                }
                println!("...");

                // 对比关键步骤
                println!("\n--- 对比结果 ---");

                if cpu_seed == gpu_output.seed {
                    println!("✅ PBKDF2种子: 一致");
                } else {
                    println!("❌ PBKDF2种子: 不一致！");
                    println!("   CPU: {:02x?}", &cpu_seed[..16]);
                    println!("   GPU: {:02x?}", &gpu_output.seed[..16]);
                }

                if cpu_pubkey_hash.to_vec() == gpu_output.pubkey_hash {
                    println!("✅ pubkey_hash: 一致");
                } else {
                    println!("❌ pubkey_hash: 不一致！");
                    println!("   CPU: {:02x?}", cpu_pubkey_hash);
                    println!("   GPU: {:02x?}", gpu_output.pubkey_hash);
                }
            }
            Err(e) => {
                println!("❌ GPU计算失败: {}", e);
                panic!("GPU调试执行失败");
            }
        }
    }
}
