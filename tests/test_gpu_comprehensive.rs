// GPU全面场景测试 - 测试各种助记词长度、密码、干扰词组合
mod gpu_common;

use gpu_common::*;
use rand::thread_rng;

/// 测试场景1: 12位助记词，无密码
#[test]
fn test_mnemonic_12_no_password() {
    println!("\n=== 测试: 12位助记词（无密码） ===");
    
    let config = create_simple_test_config(Some(12)).unwrap();
    run_gpu_search_test(&config, "12位助记词-无密码", true);
}

/// 测试场景2: 15位助记词，无密码
#[test]
fn test_mnemonic_15_no_password() {
    println!("\n=== 测试: 15位助记词（无密码） ===");
    
    let config = create_simple_test_config(Some(15)).unwrap();
    run_gpu_search_test(&config, "15位助记词-无密码", true);
}

/// 测试场景3: 18位助记词，无密码
#[test]
fn test_mnemonic_18_no_password() {
    println!("\n=== 测试: 18位助记词（无密码） ===");
    
    let config = create_simple_test_config(Some(18)).unwrap();
    run_gpu_search_test(&config, "18位助记词-无密码", true);
}

/// 测试场景4: 24位助记词，无密码
#[test]
fn test_mnemonic_24_no_password() {
    println!("\n=== 测试: 24位助记词（无密码） ===");
    
    let config = create_simple_test_config(Some(24)).unwrap();
    run_gpu_search_test(&config, "24位助记词-无密码", true);
}

/// 测试场景5: 12位助记词，带密码
#[test]
fn test_mnemonic_12_with_password() {
    println!("\n=== 测试: 12位助记词（带密码） ===");
    
    let config = create_test_config_with_password(Some(12), "my_secret_password").unwrap();
    run_gpu_search_test(&config, "12位助记词-带密码", true);
}

/// 测试场景6: 15位助记词，带密码
#[test]
fn test_mnemonic_15_with_password() {
    println!("\n=== 测试: 15位助记词（带密码） ===");
    
    let config = create_test_config_with_password(Some(15), "test_passphrase_123").unwrap();
    run_gpu_search_test(&config, "15位助记词-带密码", true);
}

/// 测试场景7: 18位助记词，带密码
#[test]
fn test_mnemonic_18_with_password() {
    println!("\n=== 测试: 18位助记词（带密码） ===");
    
    let config = create_test_config_with_password(Some(18), "longer_password_string").unwrap();
    run_gpu_search_test(&config, "18位助记词-带密码", true);
}

/// 测试场景8: 24位助记词，带密码
#[test]
fn test_mnemonic_24_with_password() {
    println!("\n=== 测试: 24位助记词（带密码） ===");
    
    let config = create_test_config_with_password(Some(24), "very_long_password_for_24_words").unwrap();
    run_gpu_search_test(&config, "24位助记词-带密码", true);
}

/// 测试场景9: 12位助记词，1个位置掺杂1个干扰词（2种组合）
#[test]
fn test_12_mnemonic_1_noise_word() {
    println!("\n=== 测试: 12位助记词（1个干扰词） ===");
    
    let config = create_simple_test_config(Some(12)).unwrap();
    let config_with_noise = add_noise_words(&config, &[2], &[1]).unwrap();
    
    println!("搜索空间: 2种组合（位置2有2个候选词）");
    run_gpu_search_test(&config_with_noise, "12位-1个干扰词", true);
}

/// 测试场景10: 12位助记词，2个位置各掺杂1个干扰词（4种组合）
#[test]
fn test_12_mnemonic_2_noise_words() {
    println!("\n=== 测试: 12位助记词（2个干扰词） ===");
    
    let config = create_simple_test_config(Some(12)).unwrap();
    let config_with_noise = add_noise_words(&config, &[3, 7], &[1, 1]).unwrap();
    
    println!("搜索空间: 4种组合（2^2）");
    run_gpu_search_test(&config_with_noise, "12位-2个干扰词", true);
}

/// 测试场景11: 15位助记词，2个位置各掺杂2个干扰词（9种组合）
#[test]
fn test_15_mnemonic_2_positions_3_candidates() {
    println!("\n=== 测试: 15位助记词（2个位置，每位置3个候选） ===");
    
    let config = create_simple_test_config(Some(15)).unwrap();
    let config_with_noise = add_noise_words(&config, &[4, 10], &[2, 2]).unwrap();
    
    println!("搜索空间: 9种组合（3^2）");
    run_gpu_search_test(&config_with_noise, "15位-2位置3候选", true);
}

/// 测试场景12: 18位助记词，3个位置各掺杂1个干扰词（8种组合）
#[test]
fn test_18_mnemonic_3_noise_words() {
    println!("\n=== 测试: 18位助记词（3个干扰词） ===");
    
    let config = create_simple_test_config(Some(18)).unwrap();
    let config_with_noise = add_noise_words(&config, &[2, 8, 15], &[1, 1, 1]).unwrap();
    
    println!("搜索空间: 8种组合（2^3）");
    run_gpu_search_test(&config_with_noise, "18位-3个干扰词", true);
}

/// 测试场景13: 24位助记词，2个位置各掺杂1个干扰词（4种组合）
#[test]
fn test_24_mnemonic_2_noise_words() {
    println!("\n=== 测试: 24位助记词（2个干扰词） ===");
    
    let config = create_simple_test_config(Some(24)).unwrap();
    let config_with_noise = add_noise_words(&config, &[5, 20], &[1, 1]).unwrap();
    
    println!("搜索空间: 4种组合（2^2）");
    run_gpu_search_test(&config_with_noise, "24位-2个干扰词", true);
}

/// 测试场景14: 完全随机的2-3个位置替换（12位助记词）
#[test]
fn test_12_mnemonic_random_replacement() {
    println!("\n=== 测试: 12位助记词（随机2-3个位置替换） ===");
    
    let config = create_simple_test_config(Some(12)).unwrap();
    
    // 随机选择2-3个位置
    let mut rng = thread_rng();
    let num_positions = if rand::Rng::gen_range(&mut rng, 0..2) == 0 { 2 } else { 3 };
    
    let mut positions = Vec::new();
    let mut noise_counts = Vec::new();
    for _ in 0..num_positions {
        let pos = rand::Rng::gen_range(&mut rng, 0..12);
        positions.push(pos);
        noise_counts.push(1); // 每个位置加1个干扰词
    }
    
    let config_with_noise = add_noise_words(&config, &positions, &noise_counts).unwrap();
    
    println!("搜索空间: {}种组合", calculate_search_space(&config_with_noise));
    run_gpu_search_test(&config_with_noise, "12位-随机替换", true);
}

/// 测试场景15: 大搜索空间测试（12位，4个位置各2个候选 = 16种组合）
#[test]
fn test_large_search_space_16_combinations() {
    println!("\n=== 测试: 大搜索空间（16种组合） ===");
    
    let config = create_simple_test_config(Some(12)).unwrap();
    let config_with_noise = add_noise_words(&config, &[0, 3, 6, 9], &[1, 1, 1, 1]).unwrap();
    
    println!("搜索空间: 16种组合（2^4）");
    run_gpu_search_test(&config_with_noise, "大搜索空间-16组合", true);
}

/// 测试场景16: 中等搜索空间测试（12位，3个位置各3个候选 = 27种组合）
#[test]
fn test_medium_search_space_27_combinations() {
    println!("\n=== 测试: 中等搜索空间（27种组合） ===");
    
    let config = create_simple_test_config(Some(12)).unwrap();
    let config_with_noise = add_noise_words(&config, &[1, 5, 10], &[2, 2, 2]).unwrap();
    
    println!("搜索空间: 27种组合（3^3）");
    run_gpu_search_test(&config_with_noise, "中等搜索空间-27组合", true);
}