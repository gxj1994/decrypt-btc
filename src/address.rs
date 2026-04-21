// 比特币地址生成模块
// 使用bitcoin和bip39标准库确保地址生成的准确性

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::{Address, Network};
use secp256k1::Secp256k1;
use std::str::FromStr;

/// 从助记词生成BIP39种子
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let mnemonic_obj = Mnemonic::parse(mnemonic).expect("Invalid mnemonic");
    mnemonic_obj.to_seed(passphrase)
}

/// 从助记词生成Legacy地址 (1开头)
pub fn mnemonic_to_address(
    mnemonic: &str,
    passphrase: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Step 1: 解析助记词
    let mnemonic_obj = Mnemonic::parse(mnemonic)?;

    // Step 2: BIP39 seed (PBKDF2)
    let seed = mnemonic_obj.to_seed(passphrase);

    // Step 3: BIP32 master key
    let secp = Secp256k1::new();
    let master_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed)?;

    // Step 4: BIP32 derivation path m/44'/0'/0'/0/0
    let path = DerivationPath::from_str("m/44'/0'/0'/0/0")?;
    let derived_key = master_key.derive_priv(&secp, &path)?;

    // Step 5: 公钥
    let public_key = derived_key.to_priv().public_key(&secp);

    // Step 6: 生成Legacy地址 (P2PKH)
    let address = Address::p2pkh(&public_key, Network::Bitcoin);

    Ok(address.to_string())
}

/// 从助记词提取pubkey_hash（20字节）
pub fn mnemonic_to_pubkey_hash(
    mnemonic: &str,
    passphrase: &str,
) -> Result<[u8; 20], Box<dyn std::error::Error>> {
    // 生成地址
    let address_str = mnemonic_to_address(mnemonic, passphrase)?;

    // 解码地址获取pubkey_hash
    let decoded = base58check_decode(&address_str)?;

    // 转换为[u8; 20]
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&decoded);

    Ok(hash)
}

/// Base58Check解码
pub fn base58check_decode(address: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // 直接使用bs58库进行Base58Check解码
    // with_check会自动验证checksum并返回不含checksum的数据
    let decoded = bs58::decode(address).with_check(None).into_vec()?;

    // decoded结构: [version(1)] + [pubkey_hash(20)]
    // bs58 with_check已经验证并去掉了checksum
    if decoded.len() != 21 {
        return Err(format!("地址解码后长度应为21字节，实际为{}字节", decoded.len()).into());
    }

    // 返回pubkey_hash（去掉version字节）
    Ok(decoded[1..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_to_address_known_vector() {
        // BIP39测试向量
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "";

        let address = mnemonic_to_address(mnemonic, passphrase).expect("地址生成失败");

        println!("\n=== BIP39测试向量 ===");
        println!("助记词: {}", mnemonic);
        println!("派生路径: m/44'/0'/0'/0/0");
        println!("生成地址: {}", address);

        // 验证地址以1开头（Legacy格式）
        assert!(address.starts_with('1'), "地址应该以1开头（Legacy格式）");

        // 验证地址长度合理
        assert!(
            address.len() >= 26 && address.len() <= 35,
            "地址长度应该在26-35之间"
        );
    }

    #[test]
    fn test_mnemonic_to_address_random() {
        use bip39::Mnemonic;
        use rand::thread_rng;

        // 使用bip39库生成有效的助记词（包含正确的校验位）
        let mut rng = thread_rng();
        let mnemonic_obj = Mnemonic::generate_in_with(&mut rng, bip39::Language::English, 12)
            .expect("生成助记词失败");
        let mnemonic = mnemonic_obj.to_string();

        let address = mnemonic_to_address(&mnemonic, "").expect("地址生成失败");

        println!("\n=== 随机助记词测试 ===");
        println!("助记词: {}", mnemonic);
        println!("地址: {}", address);

        assert!(address.starts_with('1'));
    }
}
