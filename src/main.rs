use clap::Parser;
use log::info;

use decrypt_btc::address::mnemonic_to_address;
use decrypt_btc::config::Config;
use decrypt_btc::mnemonic::{indices_to_mnemonic, Bip39Wordlist, CandidateGenerator};
use decrypt_btc::opencl::gpu_searcher::GpuSearcher;

#[derive(Parser, Debug)]
#[command(name = "decrypt-btc")]
#[command(author = "Your Name")]
#[command(version = "0.1.0")]
#[command(about = "BTC mnemonic brute-force tool with GPU acceleration", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/example.yaml")]
    config: String,

    /// Use GPU search
    #[arg(short, long)]
    gpu: bool,

    /// GPU batch size
    #[arg(long, default_value = "10000")]
    batch_size: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger
    env_logger::init();

    // Parse command line arguments
    let args = Args::parse();

    info!("Loading configuration from: {}", args.config);

    // Load configuration
    let config = Config::load(&args.config)?;

    info!("Configuration loaded successfully");
    info!("Mnemonic size: {}", config.mnemonic_size);
    info!("Target address: {}", config.target_address);
    info!("Password count: {}", config.passwords.len());

    // Load BIP39 wordlist
    let wordlist = Bip39Wordlist::load("data/english.txt")?;
    info!("BIP39 wordlist loaded: {} words", wordlist.words().len());

    // Build candidate indices
    let generator = CandidateGenerator::new(wordlist);
    let candidates = generator.build_candidates(&config)?;

    let search_space = CandidateGenerator::calculate_search_space(&candidates);
    info!(
        "Total search space: {:.2e} combinations",
        search_space as f64
    );

    if args.gpu {
        // GPU search mode
        info!("\n[Mode] GPU accelerated search");
        run_gpu_search(&config, &candidates, args.batch_size)?;
    } else if cfg!(debug_assertions) {
        // CPU verification test (development)
        info!("\n[Mode] CPU verification test");
        run_cpu_verification_test(&generator, &config)?;
    } else {
        info!("\nReady for GPU search. Use --gpu flag to enable.");
    }

    Ok(())
}

/// CPU验证测试（for development）
fn run_cpu_verification_test(
    generator: &CandidateGenerator,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // 构建候选词
    let candidates = generator.build_candidates(config)?;
    let search_space = CandidateGenerator::calculate_search_space(&candidates);
    
    info!("CPU测试：搜索空间 = {:.2e} 组合", search_space as f64);
    
    // 如果搜索空间太大，只测试前几个组合
    let max_test_count = 10;
    if search_space > max_test_count as u64 {
        info!("搜索空间过大，只测试前 {} 个组合", max_test_count);
    }
    
    // 生成要测试的索引组合
    let mut test_count = 0;
    let mut indices = vec![0usize; config.mnemonic_size];
    
    loop {
        if test_count >= max_test_count {
            break;
        }
        
        // 将indices转换为助记词
        let mnemonic_indices: Vec<u16> = indices.iter().map(|&i| i as u16).collect();
        let mnemonic = indices_to_mnemonic(&mnemonic_indices, generator.wordlist())?;
        
        info!("\n测试 [{}/{}]: {}", test_count + 1, max_test_count.min(search_space as usize), mnemonic);
        
        // 测试所有密码
        let passwords = if config.passwords.is_empty() {
            vec!["".to_string()]
        } else {
            config.passwords.clone()
        };
        
        for password in &passwords {
            let address = mnemonic_to_address(&mnemonic, password)?;
            info!("  Password: '{}' -> Address: {}", password, address);
            
            if address == config.target_address {
                info!("\n*** MATCH FOUND! ***");
                info!("Mnemonic: {}", mnemonic);
                info!("Password: {}", password);
                return Ok(());
            }
        }
        
        // 生成下一个索引组合
        test_count += 1;
        let mut pos = config.mnemonic_size - 1;
        while pos < config.mnemonic_size {
            indices[pos] += 1;
            if indices[pos] < candidates[pos].len() {
                break;
            }
            indices[pos] = 0;
            if pos == 0 {
                // 已经遍历完所有组合
                info!("\n已遍历完所有 {} 个组合", test_count);
                return Ok(());
            }
            pos -= 1;
        }
    }
    
    info!("\nCPU测试完成，未找到匹配");
    Ok(())
}

/// GPU搜索模式
fn run_gpu_search(
    config: &Config,
    candidates: &[Vec<u16>],
    _batch_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;
    
    info!("\n初始化GPU搜索器...");
    let init_start = Instant::now();

    // 创建GPU搜索器
    let mut searcher = GpuSearcher::new(config)?;
    let init_elapsed = init_start.elapsed().as_secs_f64();
    info!("GPU搜索器初始化完成，耗时: {:.3}秒", init_elapsed);

    // 执行GPU搜索（传入预生成的candidates，避免重复构建）
    info!("\n开始GPU搜索...");
    let results = searcher.search(config, Some(candidates))?;

    // 输出性能统计
    let stats = &searcher.stats;
    info!("\n{}", "=".repeat(60));
    info!("GPU搜索性能报告");
    info!("{}", "=".repeat(60));
    info!("初始化时间: {:.3} 秒", init_elapsed);
    info!("GPU执行时间: {:.3} 秒", stats.execution_secs);
    info!("总耗时: {:.3} 秒", stats.elapsed_secs);
    info!("总尝试次数: {} 次", stats.total_attempts);
    info!("搜索速度: {:.0} H/s", stats.attempts_per_second);
    
    if stats.attempts_per_second > 1000.0 && stats.attempts_per_second < 1000000.0 {
        info!("搜索速度: {:.2} KH/s", stats.attempts_per_second / 1000.0);
    } else if stats.attempts_per_second >= 1000000.0 {
        info!("搜索速度: {:.2} MH/s", stats.attempts_per_second / 1000000.0);
    }
    
    if stats.total_attempts > 0 && stats.execution_secs > 0.0 {
        let avg_time_per_attempt = stats.execution_secs * 1_000_000_000.0 / stats.total_attempts as f64;
        info!("平均每次尝试: {:.0} 纳秒", avg_time_per_attempt);
    }
    info!("{}", "=".repeat(60));

    // 输出结果
    if results.is_empty() {
        info!("\n未找到匹配的助记词");
    } else {
        info!("\n✅ 找到 {} 个匹配的助记词！", results.len());
        for (i, result) in results.iter().enumerate() {
            info!("\n匹配 #{}", i + 1);
            info!("  工作项索引: {}", result.work_item_index);
            info!("  助记词: {}", result.mnemonic);
            info!("  密码: {}", result.password);
        }
    }

    Ok(())
}
