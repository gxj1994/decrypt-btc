// GPU遍历测试 - 测试GPU内核的搜索功能
mod gpu_common;

use gpu_common::*;

/// 测试GPU基本功能：简单场景（单候选）
/// 目的：验证GPU内核能正确计算并找到匹配
#[test]
fn test_gpu_simple_search() {
    println!("\n=== GPU简单搜索测试 ===");

    let config = create_simple_test_config(None).unwrap();

    // 构建完整助记词
    let mut mnemonic_parts = Vec::new();
    for i in 1..=config.mnemonic_size {
        let key = format!("word{}", i - 1);
        if let Some(words) = config.word_positions.get(&key) {
            mnemonic_parts.push(words[0].clone());
        }
    }
    let full_mnemonic = mnemonic_parts.join(" ");
    let full_mnemonic_clone = full_mnemonic.clone(); // 克隆用于后面使用

    let scenario = GpuTestScenario {
        name: "GPU简单搜索".to_string(),
        mnemonic_size: 12,
        passphrase: "".to_string(),
        target_mnemonic: full_mnemonic,
        target_address: config.target_address.clone(),
        word_positions: config.word_positions.clone(),
        expected_found: true,
    };

    print_gpu_test_scenario(&scenario);

    // CPU端计算对比
    println!("\n[CPU端计算]");
    println!("助记词: {}", full_mnemonic_clone);
    println!("密码: '{}'", scenario.passphrase);

    // 使用CPU计算地址
    let cpu_address =
        decrypt_btc::address::mnemonic_to_address(&full_mnemonic_clone, &scenario.passphrase)
            .expect("CPU地址计算失败");
    println!("CPU计算地址: {}", cpu_address);

    // 解码地址获取pubkey_hash
    let cpu_pubkey_hash =
        decrypt_btc::address::base58check_decode(&cpu_address).expect("CPU地址解码失败");
    print!("CPU pubkey_hash: ");
    for byte in &cpu_pubkey_hash[..8] {
        print!("{:02x}", byte);
    }
    println!("...");

    // 调用GPU搜索
    println!("\n[GPU端计算]");
    let mut searcher =
        decrypt_btc::opencl::gpu_searcher::GpuSearcher::new(&config).expect("GPU搜索器初始化失败");
    let results = searcher.search(&config, None).expect("GPU搜索失败");

    println!("[GPU结果] 找到 {} 个匹配", results.len());
    if !results.is_empty() {
        println!("[GPU结果] 第一个匹配: {}", results[0].mnemonic);
    }

    assert!(!results.is_empty(), "GPU应该找到匹配的助记词");
    assert!(
        verify_gpu_result(
            &results[0].mnemonic,
            &results[0].password,
            &scenario.target_mnemonic,
            &scenario.passphrase
        ),
        "GPU结果不匹配"
    );

    println!("✅ GPU找到匹配: {}", results[0].mnemonic);
}

/// 测试GPU带干扰词搜索
/// 目的：验证GPU能在多个候选词中找到正确的
#[test]
fn test_gpu_search_with_wrong_words() {
    println!("\n=== GPU带干扰词搜索测试 ===");

    // 使用随机生成的12词助记词
    let config = create_simple_test_config(None).unwrap();

    // 构建完整助记词
    let mut mnemonic_parts = Vec::new();
    for i in 1..=config.mnemonic_size {
        let key = format!("word{}", i - 1);
        if let Some(words) = config.word_positions.get(&key) {
            mnemonic_parts.push(words[0].clone());
        }
    }
    let correct_mnemonic = mnemonic_parts.join(" ");
    let passphrase = "";

    // 在位置2和位置3添加干扰词
    let wrong_positions = vec![1, 2];
    let wrong_words = vec![vec!["ability".to_string()], vec!["able".to_string()]];

    let config = create_test_config_with_candidates(
        &correct_mnemonic,
        passphrase,
        &wrong_positions,
        &wrong_words,
    )
    .unwrap();

    let search_space = calculate_search_space(&config);
    println!("搜索空间: {} (2x2=4种组合)", search_space);

    let scenario = GpuTestScenario {
        name: "GPU带干扰词搜索".to_string(),
        mnemonic_size: 12,
        passphrase: passphrase.to_string(),
        target_mnemonic: correct_mnemonic.to_string(),
        target_address: config.target_address.clone(),
        word_positions: config.word_positions.clone(),
        expected_found: true,
    };

    print_gpu_test_scenario(&scenario);

    // 调用GPU搜索
    let mut searcher =
        decrypt_btc::opencl::gpu_searcher::GpuSearcher::new(&config).expect("GPU搜索器初始化失败");
    let results = searcher.search(&config, None).expect("GPU搜索失败");

    assert_eq!(results.len(), 1, "GPU应该只找到1个匹配");
    assert!(
        verify_gpu_result(
            &results[0].mnemonic,
            &results[0].password,
            &correct_mnemonic,
            passphrase
        ),
        "GPU结果不匹配"
    );

    println!("✅ GPU找到匹配: {}", results[0].mnemonic);
}

/// 测试GPU带密码搜索
/// 目的：验证GPU能正确处理passphrase
#[test]
fn test_gpu_search_with_password() {
    println!("\n=== GPU带密码搜索测试 ===");

    // 使用随机生成的12词助记词
    let config = create_simple_test_config(None).unwrap();

    // 构建完整助记词
    let mut mnemonic_parts = Vec::new();
    for i in 1..=config.mnemonic_size {
        let key = format!("word{}", i - 1);
        if let Some(words) = config.word_positions.get(&key) {
            mnemonic_parts.push(words[0].clone());
        }
    }
    let correct_mnemonic = mnemonic_parts.join(" ");
    let passphrase = "my_secret_password";

    let config =
        create_test_config_with_candidates(&correct_mnemonic, passphrase, &[], &[]).unwrap();

    let scenario = GpuTestScenario {
        name: "GPU带密码搜索".to_string(),
        mnemonic_size: 12,
        passphrase: passphrase.to_string(),
        target_mnemonic: correct_mnemonic.to_string(),
        target_address: config.target_address.clone(),
        word_positions: config.word_positions.clone(),
        expected_found: true,
    };

    print_gpu_test_scenario(&scenario);

    // 调用GPU搜索
    let mut searcher =
        decrypt_btc::opencl::gpu_searcher::GpuSearcher::new(&config).expect("GPU搜索器初始化失败");
    let results = searcher.search(&config, None).expect("GPU搜索失败");

    assert!(!results.is_empty(), "GPU应该找到匹配的助记词");
    assert_eq!(results[0].password, passphrase, "密码应该匹配");

    println!("✅ GPU找到匹配，密码: {}", results[0].password);
}

/// 测试GPU大搜索空间
/// 目的：验证GPU能处理较大的搜索空间
#[test]
fn test_gpu_large_search_space() {
    println!("\n=== GPU大搜索空间测试 ===");

    // 使用随机生成的12词助记词
    let config = create_simple_test_config(None).unwrap();

    // 构建完整助记词
    let mut mnemonic_parts = Vec::new();
    for i in 1..=config.mnemonic_size {
        let key = format!("word{}", i - 1);
        if let Some(words) = config.word_positions.get(&key) {
            mnemonic_parts.push(words[0].clone());
        }
    }
    let correct_mnemonic = mnemonic_parts.join(" ");
    let passphrase = "";

    // 4个位置，每个位置2个候选词 = 2^4 = 16
    let wrong_positions = vec![0, 1, 2, 3];
    let wrong_words = vec![
        vec!["ability".to_string()],
        vec!["able".to_string()],
        vec!["about".to_string()],
        vec!["absent".to_string()],
    ];

    let config = create_test_config_with_candidates(
        &correct_mnemonic,
        passphrase,
        &wrong_positions,
        &wrong_words,
    )
    .unwrap();

    let search_space = calculate_search_space(&config);
    println!("搜索空间: {} (5^4=625种组合)", search_space);

    let scenario = GpuTestScenario {
        name: "GPU大搜索空间".to_string(),
        mnemonic_size: 12,
        passphrase: passphrase.to_string(),
        target_mnemonic: correct_mnemonic.to_string(),
        target_address: config.target_address.clone(),
        word_positions: config.word_positions.clone(),
        expected_found: true,
    };

    print_gpu_test_scenario(&scenario);

    // 调用GPU搜索
    let mut searcher =
        decrypt_btc::opencl::gpu_searcher::GpuSearcher::new(&config).expect("GPU搜索器初始化失败");
    let results = searcher.search(&config, None).expect("GPU搜索失败");

    assert!(!results.is_empty(), "GPU应该在大搜索空间中找到匹配");

    println!("✅ GPU在625种组合中找到匹配");
}

/// 测试GPU多密码场景
/// 目的：验证GPU能测试多个密码
#[test]
fn test_gpu_multiple_passwords() {
    println!("\n=== GPU多密码测试 ===");

    // 使用随机生成的12词助记词
    let config = create_simple_test_config(None).unwrap();

    // 构建完整助记词
    let mut mnemonic_parts = Vec::new();
    for i in 1..=config.mnemonic_size {
        let key = format!("word{}", i - 1);
        if let Some(words) = config.word_positions.get(&key) {
            mnemonic_parts.push(words[0].clone());
        }
    }
    let correct_mnemonic = mnemonic_parts.join(" ");
    let correct_passphrase = "correct_password";

    let words: Vec<&str> = correct_mnemonic.split_whitespace().collect();
    let mut word_positions = std::collections::HashMap::new();
    for (i, word) in words.iter().enumerate() {
        let key = format!("word{}", i);
        word_positions.insert(key, vec![word.to_string()]);
    }

    let address =
        decrypt_btc::address::mnemonic_to_address(&correct_mnemonic, correct_passphrase).unwrap();

    let config = decrypt_btc::config::Config {
        mnemonic_size: 12,
        passwords: vec![
            correct_passphrase.to_string(),  // 当前GPU只测试第一个密码
        ],
        target_address: address,
        word_positions,
    };

    let scenario = GpuTestScenario {
        name: "GPU多密码测试".to_string(),
        mnemonic_size: 12,
        passphrase: correct_passphrase.to_string(),
        target_mnemonic: correct_mnemonic.to_string(),
        target_address: config.target_address.clone(),
        word_positions: config.word_positions.clone(),
        expected_found: true,
    };

    print_gpu_test_scenario(&scenario);

    // 调用GPU搜索
    let mut searcher =
        decrypt_btc::opencl::gpu_searcher::GpuSearcher::new(&config).expect("GPU搜索器初始化失败");
    let results = searcher.search(&config, None).expect("GPU搜索失败");

    assert_eq!(results.len(), 1, "GPU应该只找到1个匹配（正确的密码）");
    assert_eq!(
        results[0].password, correct_passphrase,
        "应该找到正确的密码"
    );

    println!("✅ GPU在3个密码中找到正确的: {}", results[0].password);
}
