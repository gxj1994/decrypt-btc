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

    // TODO: Initialize OpenCL and run GPU search

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

/// CPU verification test (for development)
fn run_cpu_verification_test(
    generator: &CandidateGenerator,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    // Test with a small subset if search space is too large
    let test_candidates = if config.mnemonic_size == 12 {
        // Use only first few candidates for each position
        let mut small = Vec::new();
        for position in generator.wordlist().all_indices().iter().take(4) {
            small.push(vec![*position]);
        }
        // Fill remaining positions
        for _ in small.len()..12 {
            small.push(vec![0]);
        }
        small
    } else {
        return Ok(());
    };

    info!("CPU test: generating addresses for small candidate set");

    // Test first combination
    let first_mnemonic = indices_to_mnemonic(
        &test_candidates.iter().map(|v| v[0]).collect::<Vec<_>>(),
        generator.wordlist(),
    )?;

    info!("Test mnemonic: {}", first_mnemonic);

    for password in &config.passwords {
        let address = mnemonic_to_address(&first_mnemonic, password)?;
        info!("  Password: '{}' -> Address: {}", password, address);

        if address == config.target_address {
            info!("*** MATCH FOUND! ***");
            info!("Mnemonic: {}", first_mnemonic);
            info!("Password: {}", password);
        }
    }

    if config.passwords.is_empty() {
        let address = mnemonic_to_address(&first_mnemonic, "")?;
        info!("  No password -> Address: {}", address);

        if address == config.target_address {
            info!("*** MATCH FOUND! ***");
            info!("Mnemonic: {}", first_mnemonic);
        }
    }

    Ok(())
}

/// GPU搜索模式
fn run_gpu_search(
    config: &Config,
    candidates: &[Vec<u16>],
    _batch_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("\n初始化GPU搜索器...");

    // 创建GPU搜索器
    let mut searcher = GpuSearcher::new(config)?;

    // 执行GPU搜索
    info!("\n开始GPU搜索...");
    let results = searcher.search(config)?;

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
