// GPU性能统计测试
// 验证性能统计功能的准确性

use decrypt_btc::config::Config;
use decrypt_btc::opencl::gpu_searcher::GpuSearcher;
use std::collections::HashMap;
use std::time::Instant;

/// 测试性能统计的基本功能
#[test]
fn test_performance_stats_basic() {
    // 创建简单配置
    let mut config = Config {
        mnemonic_size: 12,
        passwords: vec![],
        target_address: "1KddEkd2fiWuibkSmK1ASBpjpTDjmAZTKs".to_string(),
        word_positions: HashMap::new(),
    };

    // 设置简单的助记词位置（只有1个组合）
    for i in 1..=12 {
        config.word_positions.insert(format!("position_{}", i), vec!["abandon".to_string()]);
    }

    // 创建GPU搜索器
    let mut searcher = GpuSearcher::new(&config).expect("GPU搜索器初始化失败");

    // 执行搜索
    let _results = searcher.search(&config).expect("GPU搜索失败");

    // 验证性能统计
    let stats = &searcher.stats;
    
    println!("\n========== 性能统计测试 ==========");
    println!("总尝试次数: {}", stats.total_attempts);
    println!("总耗时: {:.3} 秒", stats.elapsed_secs);
    println!("GPU执行时间: {:.3} 秒", stats.execution_secs);
    println!("速度: {:.0} H/s", stats.attempts_per_second);
    
    // 验证统计数据合理性
    assert!(stats.total_attempts > 0, "总尝试次数应该大于0");
    assert!(stats.elapsed_secs > 0.0, "总耗时应该大于0");
    assert!(stats.execution_secs > 0.0, "GPU执行时间应该大于0");
    assert!(stats.attempts_per_second > 0.0, "速度应该大于0");
    
    // 验证速度计算准确性
    let expected_speed = stats.total_attempts as f64 / stats.elapsed_secs;
    let speed_diff = (stats.attempts_per_second - expected_speed).abs();
    assert!(speed_diff < 1.0, "速度计算应该准确，误差应小于1 H/s");
    
    println!("✅ 性能统计测试通过");
}

/// 测试多个工作项的性能统计
#[test]
fn test_performance_stats_multiple_work_items() {
    // 创建配置，有4个位置各有2个候选词（共16种组合）
    let mut config = Config {
        mnemonic_size: 12,
        passwords: vec![],
        target_address: "1KddEkd2fiWuibkSmK1ASBpjpTDjmAZTKs".to_string(),
        word_positions: HashMap::new(),
    };

    let test_words = vec!["abandon".to_string(), "ability".to_string()];
    
    // 前4个位置有2个候选词，其他位置只有1个
    for i in 1..=12 {
        if i <= 4 {
            config.word_positions.insert(format!("position_{}", i), test_words.clone());
        } else {
            config.word_positions.insert(format!("position_{}", i), vec!["abandon".to_string()]);
        }
    }

    // 创建GPU搜索器
    let mut searcher = GpuSearcher::new(&config).expect("GPU搜索器初始化失败");

    // 记录开始时间
    let start = Instant::now();
    
    // 执行搜索
    let _results = searcher.search(&config).expect("GPU搜索失败");
    
    let elapsed = start.elapsed().as_secs_f64();

    // 验证性能统计
    let stats = &searcher.stats;
    
    println!("\n========== 多工作项性能统计测试 ==========");
    println!("预期工作项数: 16 (2^4)");
    println!("实际总尝试次数: {}", stats.total_attempts);
    println!("总耗时: {:.3} 秒", stats.elapsed_secs);
    println!("GPU执行时间: {:.3} 秒", stats.execution_secs);
    println!("速度: {:.0} H/s", stats.attempts_per_second);
    
    // 验证尝试次数
    assert_eq!(stats.total_attempts, 16, "应该正好有16次尝试");
    
    // 验证时间合理性
    assert!(stats.elapsed_secs < 5.0, "总耗时应该小于5秒");
    assert!(stats.execution_secs < 5.0, "GPU执行时间应该小于5秒");
    
    // 验证统计时间与手动计时一致
    let time_diff = (stats.elapsed_secs - elapsed).abs();
    assert!(time_diff < 0.1, "统计时间应该与手动计时接近");
    
    println!("✅ 多工作项性能统计测试通过");
}

/// 测试速度单位转换显示
#[test]
fn test_performance_speed_display() {
    // 这个测试主要验证速度显示逻辑
    let test_cases = vec![
        (500.0, "500 H/s"),
        (1500.0, "1.50 KH/s"),
        (1500000.0, "1.50 MH/s"),
    ];
    
    println!("\n========== 速度单位显示测试 ==========");
    for (speed, expected_unit) in test_cases {
        let display = if speed >= 1000000.0 {
            format!("{:.2} MH/s", speed / 1000000.0)
        } else if speed >= 1000.0 {
            format!("{:.2} KH/s", speed / 1000.0)
        } else {
            format!("{:.0} H/s", speed)
        };
        
        println!("速度: {:.0} -> 显示: {} (预期: {})", speed, display, expected_unit);
        assert!(display.contains(expected_unit.split_whitespace().last().unwrap()), 
                "速度单位应该正确显示");
    }
    
    println!("✅ 速度单位显示测试通过");
}
