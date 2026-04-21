// GPU测试公共工具模块
// 用于准备GPU测试数据、验证GPU计算结果、运行测试

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
    create_test_config_with_password(mnemonic_size, "")
}

/// 创建带密码的测试配置
///
/// # 参数
/// * `mnemonic_size` - 助记词长度（12/15/18/21/24），默认为12
/// * `password` - 密码（passphrase）
pub fn create_test_config_with_password(
    mnemonic_size: Option<usize>,
    password: &str,
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

    // 计算目标地址
    let address = mnemonic_to_address(&mnemonic, password)?;

    // 构建word_positions
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let mut word_positions = HashMap::new();
    for (i, word) in words.iter().enumerate() {
        let key = format!("position_{}", i + 1);
        word_positions.insert(key, vec![word.to_string()]);
    }

    println!("[测试配置] 助记词长度: {} 位", size);
    println!("[测试配置] 助记词: {}", mnemonic);
    println!("[测试配置] 目标地址: {}", address);

    Ok(Config {
        mnemonic_size: size,
        passwords: vec![password.to_string()],
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

/// 添加干扰词到配置
///
/// # 参数
/// * `base_config` - 基础配置
/// * `positions` - 要添加干扰词的位置（0-based索引）
/// * `noise_counts` - 每个位置添加的干扰词数量
pub fn add_noise_words(
    base_config: &Config,
    positions: &[usize],
    noise_counts: &[usize],
) -> Result<Config, Box<dyn std::error::Error>> {
    use rand::thread_rng;
    
    let mut new_config = base_config.clone();
    let mut rng = thread_rng();
    
    // 加载单词表
    let wordlist = decrypt_btc::mnemonic::Bip39Wordlist::load("data/english.txt")?;
    
    for (idx, &pos) in positions.iter().enumerate() {
        let key = format!("position_{}", pos + 1);
        if let Some(original_words) = new_config.word_positions.get_mut(&key) {
            // 为每个原始词添加干扰词
            let noise_count = noise_counts[idx];
            let mut new_candidates = original_words.clone();
            
            for _ in 0..noise_count {
                // 随机选择一个不同的单词
                loop {
                    let random_idx = rand::Rng::gen_range(&mut rng, 0..2048);
                    if let Some(word) = wordlist.get_word(random_idx) {
                        // 确保不与现有候选词重复
                        if !new_candidates.contains(&word.to_string()) {
                            new_candidates.push(word.to_string());
                            break;
                        }
                    }
                }
            }
            
            new_config.word_positions.insert(key, new_candidates);
        }
    }
    
    Ok(new_config)
}

/// 构建完整助记词（从config中取每个位置的第一个词）
pub fn build_full_mnemonic(config: &Config) -> String {
    let mut mnemonic_parts = Vec::new();
    for i in 1..=config.mnemonic_size {
        let key = format!("position_{}", i);
        if let Some(words) = config.word_positions.get(&key) {
            mnemonic_parts.push(words[0].clone());
        }
    }
    mnemonic_parts.join(" ")
}

/// 运行GPU搜索测试
///
/// # 参数
/// * `config` - 测试配置
/// * `test_name` - 测试名称
/// * `should_find` - 是否应该找到匹配
pub fn run_gpu_search_test(config: &Config, test_name: &str, should_find: bool) {
    let full_mnemonic = build_full_mnemonic(config);
    
    println!("\n[测试配置]");
    println!("助记词长度: {} 位", config.mnemonic_size);
    println!("助记词: {}", full_mnemonic);
    println!("密码: '{}'", if !config.passwords.is_empty() { &config.passwords[0] } else { "" });
    println!("目标地址: {}", config.target_address);
    
    // CPU端验证
    println!("\n[CPU端计算]");
    let cpu_address = if !config.passwords.is_empty() {
        mnemonic_to_address(&full_mnemonic, &config.passwords[0])
            .expect("CPU地址计算失败")
    } else {
        mnemonic_to_address(&full_mnemonic, "")
            .expect("CPU地址计算失败")
    };
    println!("CPU地址: {}", cpu_address);
    
    // GPU端搜索
    println!("\n[GPU端计算]");
    let mut searcher = decrypt_btc::opencl::gpu_searcher::GpuSearcher::new(config)
        .expect("GPU搜索器初始化失败");
    let results = searcher.search(config).expect("GPU搜索失败");
    
    println!("[GPU结果] 找到 {} 个匹配", results.len());
    
    if should_find {
        assert!(!results.is_empty(), "GPU应该找到匹配");
        if !results.is_empty() {
            println!("[GPU结果] 第一个匹配: {}", results[0].mnemonic);
            assert_eq!(
                results[0].mnemonic, full_mnemonic,
                "GPU找到的助记词应该与目标一致"
            );
            println!("✅ GPU测试通过: {}", test_name);
        }
    } else {
        assert!(results.is_empty(), "GPU不应该找到匹配");
        println!("✅ GPU测试通过（预期无匹配）: {}", test_name);
    }
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
