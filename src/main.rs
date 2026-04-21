use clap::Parser;
use log::{debug, info};

use decrypt_btc::config::Config;
use decrypt_btc::mnemonic::{Bip39Wordlist, CandidateGenerator};
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

    /// GPU batch size
    #[arg(long, default_value = "10000")]
    batch_size: usize,

    /// Maximum search space limit (default: 5,000,000)
    /// If calculated search space exceeds this, the program will warn and exit
    #[arg(long, default_value = "5000000")]
    max_search_space: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger with default info level
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

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

    // 检查搜索空间是否超过限制
    if search_space > args.max_search_space {
        log::error!("❌ 搜索空间过大！");
        log::error!("   计算得到的搜索空间: {:.2e}", search_space as f64);
        log::error!(
            "   允许的最大搜索空间: {:.2e}",
            args.max_search_space as f64
        );
        log::error!(
            "   超出倍数: {:.1}x",
            search_space as f64 / args.max_search_space as f64
        );
        log::error!("");
        log::error!("请缩小候选词范围，或使用 --max-search-space 参数调整限制");
        log::error!("示例: decrypt-btc --gpu --max-search-space 10000000");
        return Err("搜索空间超过限制，程序退出".into());
    }

    if search_space > 1_000_000 {
        log::warn!("⚠️  搜索空间较大: {:.2e} 组合", search_space as f64);
        log::warn!("   预计需要较长时间，请耐心等待");
    }

    // 自动检测GPU并执行搜索
    debug!("\n[Mode] GPU accelerated search");
    run_gpu_search(&config, &candidates, args.batch_size)?;

    Ok(())
}

/// GPU搜索模式
fn run_gpu_search(
    config: &Config,
    candidates: &[Vec<u16>],
    _batch_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;

    info!("初始化GPU搜索器...");
    let init_start = Instant::now();

    // 创建GPU搜索器
    let mut searcher = GpuSearcher::new(config)?;
    let init_elapsed = init_start.elapsed().as_secs_f64();
    info!("GPU搜索器初始化完成，耗时: {:.3}秒", init_elapsed);

    // 执行GPU搜索（传入预生成的candidates，避免重复构建）
    info!("开始GPU搜索...");
    let results = searcher.search(config, Some(candidates))?;

    // 输出性能统计
    let stats = &searcher.stats;
    info!("{}", "=".repeat(60));
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
        info!(
            "搜索速度: {:.2} MH/s",
            stats.attempts_per_second / 1000000.0
        );
    }

    if stats.total_attempts > 0 && stats.execution_secs > 0.0 {
        let avg_time_per_attempt =
            stats.execution_secs * 1_000_000_000.0 / stats.total_attempts as f64;
        info!("平均每次尝试: {:.0} 纳秒", avg_time_per_attempt);
    }
    info!("{}", "=".repeat(60));

    // 输出结果
    if results.is_empty() {
        info!("❌未找到匹配的助记词");
    } else {
        info!("✅ 找到 {} 个匹配的助记词！", results.len());
        for (i, result) in results.iter().enumerate() {
            info!("  匹配 #{}", i + 1);
            debug!("  工作项索引: {}", result.work_item_index);
            info!("  助记词: {}", result.mnemonic);
            info!("  密码: {}", result.password);
        }
    }

    Ok(())
}
