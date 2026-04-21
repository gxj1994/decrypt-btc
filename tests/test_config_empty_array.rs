// 测试空数组配置逻辑

use decrypt_btc::config::Config;
use decrypt_btc::mnemonic::{Bip39Wordlist, CandidateGenerator};
use std::collections::HashMap;

#[test]
fn test_empty_array_means_all_2048_words() {
    // 创建配置，word0为空数组
    let mut word_positions = HashMap::new();
    word_positions.insert("word0".to_string(), vec![]); // 空数组应该使用2048个单词
    word_positions.insert("word1".to_string(), vec!["abandon".to_string(), "ability".to_string()]); // 2个候选词
    
    // 补齐12个位置
    for i in 2..12 {
        word_positions.insert(format!("word{}", i), vec!["abandon".to_string()]);
    }
    
    let config = Config {
        mnemonic_size: 12,
        passwords: vec![],
        target_address: "1KddEkd2fiWuibkSmK1ASBpjpTDjmAZTKs".to_string(),
        word_positions,
    };
    
    // 构建候选词
    let wordlist = Bip39Wordlist::load("data/english.txt").unwrap();
    let generator = CandidateGenerator::new(wordlist);
    let candidates = generator.build_candidates(&config).unwrap();
    
    // 验证word0应该有2048个候选词
    assert_eq!(candidates[0].len(), 2048, "空数组应该使用全部2048个单词");
    
    // 验证word1应该有2个候选词
    assert_eq!(candidates[1].len(), 2, "应该使用配置的2个候选词");
    
    // 验证其他位置应该有1个候选词
    for i in 2..12 {
        assert_eq!(candidates[i].len(), 1, "位置 {} 应该有1个候选词", i);
    }
    
    // 计算搜索空间
    let search_space = CandidateGenerator::calculate_search_space(&candidates);
    assert_eq!(search_space, 2048 * 2, "搜索空间应该是 2048 * 2 = 4096");
    
    println!("✅ 空数组配置测试通过");
    println!("搜索空间: {} = 2048 * 2", search_space);
}

#[test]
fn test_config_key_format_word0_to_word11() {
    // 验证配置使用word0-word11格式（0-based）
    let mut word_positions = HashMap::new();
    
    // 使用正确的键名格式
    for i in 0..12 {
        word_positions.insert(format!("word{}", i), vec!["abandon".to_string()]);
    }
    
    let config = Config {
        mnemonic_size: 12,
        passwords: vec![],
        target_address: "1KddEkd2fiWuibkSmK1ASBpjpTDjmAZTKs".to_string(),
        word_positions,
    };
    
    // 构建候选词（如果配置正确，这步不会报错）
    let wordlist = Bip39Wordlist::load("data/english.txt").unwrap();
    let generator = CandidateGenerator::new(wordlist);
    let candidates = generator.build_candidates(&config).unwrap();
    
    // 验证所有位置都有1个候选词
    assert_eq!(candidates.len(), 12);
    for i in 0..12 {
        assert_eq!(candidates[i].len(), 1, "位置 {} 应该有1个候选词", i);
    }
    
    println!("✅ 配置键名格式测试通过");
}
