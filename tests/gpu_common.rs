// GPU测试公共工具模块
// 用于准备GPU测试数据、验证GPU计算结果

use decrypt_btc::address::mnemonic_to_address;
use decrypt_btc::config::Config;
use std::collections::HashMap;

/// 测试场景配置
#[derive(Debug, Clone)]
pub struct GpuTestScenario {
    pub name: String,
    pub mnemonic_size: usize,
    pub passphrase: String,
    pub target_mnemonic: String,
    pub target_address: String,
    pub word_positions: HashMap<String, Vec<String>>,
    pub expected_found: bool, // GPU是否应该能找到
}

/// 创建简单测试配置（使用随机助记词）
///
/// # 参数
/// * `mnemonic_size` - 助记词长度（12/15/18/21/24），默认为12
pub fn create_simple_test_config(
    mnemonic_size: Option<usize>,
) -> Result<Config, Box<dyn std::error::Error>> {
    // 只在非测试环境下初始化logger
    let _ = env_logger::try_init();

    // 使用bip39库生成有效的助记词（包含正确的校验位）
    use bip39::Mnemonic;
    use rand::thread_rng;

    let size = mnemonic_size.unwrap_or(12);

    // 验证助记词长度
    if ![12, 15, 18, 21, 24].contains(&size) {
        return Err(format!("无效的助记词长度: {}，必须是 12/15/18/21/24", size).into());
    }

    let mut rng = thread_rng();
    let mnemonic_obj = Mnemonic::generate_in_with(&mut rng, bip39::Language::English, size)
        .expect("生成助记词失败");
    let mnemonic = mnemonic_obj.to_string();

    let passphrase = "";
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let mut word_positions = HashMap::new();

    for (i, word) in words.iter().enumerate() {
        let key = format!("position_{}", i + 1);
        word_positions.insert(key, vec![word.to_string()]);
    }

    let address = mnemonic_to_address(&mnemonic, passphrase)?;

    println!("[测试配置] 助记词长度: {} 位", size);
    println!("[测试配置] 助记词: {}", mnemonic);
    println!("[测试配置] 目标地址: {}", address);

    Ok(Config {
        mnemonic_size: size,
        passwords: vec![passphrase.to_string()],
        target_address: address,
        word_positions,
    })
}

/// 创建带干扰词的测试配置
/// 正确助记词在搜索空间中，用于测试GPU能否找到
pub fn create_test_config_with_candidates(
    correct_mnemonic: &str,
    passphrase: &str,
    wrong_positions: &[usize],   // 哪些位置添加干扰词
    wrong_words: &[Vec<String>], // 每个位置的干扰词
) -> Result<Config, Box<dyn std::error::Error>> {
    let correct_words: Vec<&str> = correct_mnemonic.split_whitespace().collect();
    let mnemonic_size = correct_words.len();

    assert_eq!(wrong_positions.len(), wrong_words.len());

    let mut word_positions = HashMap::new();

    for i in 0..mnemonic_size {
        let key = format!("position_{}", i + 1);

        if let Some(pos) = wrong_positions.iter().position(|&x| x == i) {
            // 这个位置包含正确词 + 干扰词
            let mut candidates = wrong_words[pos].clone();
            candidates.push(correct_words[i].to_string());
            word_positions.insert(key, candidates);
        } else {
            // 这个位置只有正确词
            word_positions.insert(key, vec![correct_words[i].to_string()]);
        }
    }

    let address = mnemonic_to_address(correct_mnemonic, passphrase)?;

    Ok(Config {
        mnemonic_size,
        passwords: vec![passphrase.to_string()],
        target_address: address,
        word_positions,
    })
}

/// 计算搜索空间大小
pub fn calculate_search_space(config: &Config) -> u64 {
    let mut space: u64 = 1;
    for i in 0..config.mnemonic_size {
        let key = format!("position_{}", i + 1);
        if let Some(candidates) = config.word_positions.get(&key) {
            space *= candidates.len() as u64;
        }
    }
    space
}

/// 验证GPU搜索结果
pub fn verify_gpu_result(
    found_mnemonic: &str,
    found_password: &str,
    expected_mnemonic: &str,
    expected_password: &str,
) -> bool {
    found_mnemonic == expected_mnemonic && found_password == expected_password
}

/// 打印GPU测试场景信息
pub fn print_gpu_test_scenario(scenario: &GpuTestScenario) {
    println!("\n{}", "=".repeat(80));
    println!("GPU测试场景: {}", scenario.name);
    println!("{}", "-".repeat(80));
    println!("助记词长度: {} 位", scenario.mnemonic_size);
    println!("密码: '{}'", scenario.passphrase);
    println!("目标助记词: {}", scenario.target_mnemonic);
    println!("目标地址: {}", scenario.target_address);

    let search_space = {
        let config = Config {
            mnemonic_size: scenario.mnemonic_size,
            passwords: vec![scenario.passphrase.clone()],
            target_address: scenario.target_address.clone(),
            word_positions: scenario.word_positions.clone(),
        };
        calculate_search_space(&config)
    };

    println!("搜索空间: {} 组合", search_space);
    println!(
        "预期结果: {}",
        if scenario.expected_found {
            "GPU应该找到"
        } else {
            "GPU不应该找到"
        }
    );
    println!("{}", "=".repeat(80));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_simple_config() {
        let config = create_simple_test_config(None).unwrap();
        assert_eq!(config.mnemonic_size, 12);
        assert_eq!(config.passwords, vec![""]);
        assert!(!config.target_address.is_empty());
        assert!(config.target_address.starts_with('1')); // Legacy地址
    }

    #[test]
    fn test_calculate_search_space() {
        let config = create_simple_test_config(None).unwrap();
        let space = calculate_search_space(&config);
        assert_eq!(space, 1); // 每个位置只有1个词
    }
}
