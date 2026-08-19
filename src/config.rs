//! Configuration module for loading and validating BTC decrypt settings

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// BTC 地址类型（由 target_address 格式自动检测，无需在配置中指定）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Taproot (P2TR, bc1p 开头, witness v1, bech32m)
    Taproot,
    /// Legacy (P2PKH, 1 开头, Base58Check)
    Legacy,
    /// Nested SegWit (P2SH, 3 开头, Base58Check)
    NestedSegWit,
    /// Native SegWit (P2WPKH, bc1q 开头, witness v0, bech32)
    NativeSegWit,
}

impl AddressType {
    /// 类型名称（用于日志输出）
    pub fn as_str(&self) -> &'static str {
        match self {
            AddressType::Taproot => "Taproot",
            AddressType::Legacy => "Legacy",
            AddressType::NestedSegWit => "Nested SegWit",
            AddressType::NativeSegWit => "Native SegWit",
        }
    }

    /// 类型编号（与 GPU 内核 ADDRESS_TYPE 宏一致）
    /// 0=Taproot, 1=Legacy, 2=Nested SegWit, 3=Native SegWit
    pub fn as_u8(&self) -> u8 {
        match self {
            AddressType::Taproot => 0,
            AddressType::Legacy => 1,
            AddressType::NestedSegWit => 2,
            AddressType::NativeSegWit => 3,
        }
    }
}

impl std::fmt::Display for AddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration structure loaded from YAML file
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Mnemonic length (12/15/18/21/24)
    pub mnemonic_size: usize,

    /// Optional passphrases
    #[serde(default)]
    pub passwords: Vec<String>,

    /// Target BTC address（支持 4 种类型，加载时自动检测：
    /// Taproot bc1p... / Legacy 1... / Nested SegWit 3... / Native SegWit bc1q...）
    pub target_address: String,

    /// Candidate word lists for each position
    /// Key format: "word0", "word1", ..., "word11"
    /// Empty Vec means use all 2048 BIP39 words
    #[serde(default)]
    pub word_positions: HashMap<String, Vec<String>>,
}

/// Configuration errors
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse YAML: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("Invalid mnemonic size: {0}. Must be 12, 15, 18, 21, or 24")]
    InvalidMnemonicSize(usize),

    #[error("Invalid target address: {0}. Must be a valid Bitcoin mainnet address (Taproot / Legacy / Nested SegWit / Native SegWit)")]
    InvalidAddress(String),

    #[error("Missing word position configuration for word{0}")]
    MissingWordPosition(usize),

    #[error("Configuration validation failed: {0}")]
    ValidationError(String),
}

impl Config {
    /// Load configuration from YAML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        // Read file contents
        let content = fs::read_to_string(&path)?;

        // Parse YAML
        let config: Config = serde_yaml::from_str(&content)?;

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Validate configuration
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate mnemonic size
        if ![12, 15, 18, 21, 24].contains(&self.mnemonic_size) {
            return Err(ConfigError::InvalidMnemonicSize(self.mnemonic_size));
        }

        // Validate target address: 自动检测类型并严格校验格式
        // （Base58Check/bech32/bech32m checksum + witness 版本 + 主网网络）
        let address_type = detect_address_type(&self.target_address)?;
        log::info!("Detected target address type: {}", address_type);

        // Validate word positions
        for i in 0..self.mnemonic_size {
            let key = format!("word{}", i);
            if !self.word_positions.contains_key(&key) {
                return Err(ConfigError::MissingWordPosition(i));
            }
        }

        // Calculate search space
        let search_space = self.calculate_search_space();
        log::info!(
            "Total search space: {:.2e} combinations",
            search_space as f64
        );

        // Warning if search space is too large
        if search_space > 1_000_000_000_000_000 {
            log::warn!("Search space is very large. Consider narrowing down candidate words.");
        }

        Ok(())
    }

    /// Calculate total search space (product of all position candidate counts)
    pub fn calculate_search_space(&self) -> u64 {
        let mut total: u64 = 1;

        for i in 0..self.mnemonic_size {
            let key = format!("word{}", i);
            let count = if let Some(words) = self.word_positions.get(&key) {
                if words.is_empty() {
                    2048 // All BIP39 words
                } else {
                    words.len() as u64
                }
            } else {
                2048
            };

            total = total.saturating_mul(count);
        }

        total
    }

    /// Get candidate words for a specific position
    /// Returns None if using all 2048 words
    pub fn get_candidates_for_position(&self, position: usize) -> Option<&Vec<String>> {
        let key = format!("word{}", position);
        self.word_positions.get(&key).and_then(
            |words| {
                if words.is_empty() {
                    None
                } else {
                    Some(words)
                }
            },
        )
    }

    /// 自动检测目标地址的地址类型
    pub fn address_type(&self) -> Result<AddressType, ConfigError> {
        detect_address_type(&self.target_address)
    }

    /// Check if a position uses all 2048 words
    pub fn is_full_search_for_position(&self, position: usize) -> bool {
        let key = format!("word{}", position);
        match self.word_positions.get(&key) {
            Some(words) => words.is_empty(),
            None => true,
        }
    }
}

/// 根据地址自身格式自动检测 BTC 地址类型（严格校验 checksum 与网络）
///
/// 检测规则（无需配置，按地址格式识别）：
/// - bc1p... → Taproot（bech32m, witness v1）
/// - 1...    → Legacy（Base58Check, P2PKH）
/// - 3...    → Nested SegWit（Base58Check, P2SH）
/// - bc1q... → Native SegWit（bech32, witness v0）
///
/// 使用 bitcoin 库解析，Base58Check/bech32/bech32m checksum、
/// witness 版本、主网网络全部验证，任一不通过即返回错误。
pub fn detect_address_type(address: &str) -> Result<AddressType, ConfigError> {
    use bitcoin::address::{Payload, WitnessVersion};
    use bitcoin::{Address, Network};
    use std::str::FromStr;

    // 严格解析：Base58Check / bech32 / bech32m checksum 全验证
    let addr =
        Address::from_str(address).map_err(|_| ConfigError::InvalidAddress(address.to_string()))?;

    // 仅接受比特币主网地址
    let addr = addr
        .require_network(Network::Bitcoin)
        .map_err(|_| ConfigError::InvalidAddress(address.to_string()))?;

    match addr.payload {
        Payload::PubkeyHash(_) => Ok(AddressType::Legacy),
        Payload::ScriptHash(_) => Ok(AddressType::NestedSegWit),
        Payload::WitnessProgram(ref wp) => match wp.version() {
            WitnessVersion::V0 => Ok(AddressType::NativeSegWit),
            WitnessVersion::V1 => Ok(AddressType::Taproot),
            _ => Err(ConfigError::InvalidAddress(address.to_string())),
        },
        // Payload 为 non_exhaustive，未来新增变体时兜底拒绝
        _ => Err(ConfigError::InvalidAddress(address.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let mut word_positions = HashMap::new();
        for i in 0..12 {
            word_positions.insert(format!("word{}", i), vec![]);
        }

        let config = Config {
            mnemonic_size: 12,
            passwords: vec![],
            target_address: "1KddEkd2fiWuibkSmK1ASBpjpTDjmAZTKs".to_string(),
            word_positions,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_mnemonic_size() {
        let mut word_positions = HashMap::new();
        for i in 0..10 {
            word_positions.insert(format!("word{}", i), vec![]);
        }

        let config = Config {
            mnemonic_size: 10, // Invalid
            passwords: vec![],
            target_address: "1KddEkd2fiWuibkSmK1ASBpjpTDjmAZTKs".to_string(),
            word_positions,
        };

        assert!(config.validate().is_err());
    }

    /// 构造一个 mnemonic_size=12、word 位置齐全的合法 Config（仅 target_address 可变）
    fn make_config(address: &str) -> Config {
        let mut word_positions = HashMap::new();
        for i in 0..12 {
            word_positions.insert(format!("word{}", i), vec![]);
        }
        Config {
            mnemonic_size: 12,
            passwords: vec![],
            target_address: address.to_string(),
            word_positions,
        }
    }

    #[test]
    fn test_detect_address_type_all_four_types() {
        // Taproot（bech32m, witness v1）
        assert_eq!(
            detect_address_type("bc1pnlgec4pd8ekmhsqdzese7jfqsnae9f6cu99m4f0cz877e3lt4v3sv2s4h7")
                .unwrap(),
            AddressType::Taproot
        );
        // Legacy（Base58Check, P2PKH）
        assert_eq!(
            detect_address_type("1KddEkd2fiWuibkSmK1ASBpjpTDjmAZTKs").unwrap(),
            AddressType::Legacy
        );
        // Nested SegWit（Base58Check, P2SH）
        assert_eq!(
            detect_address_type("3BSruDfveoFrFG5LSfW77CJcN61ARoMHZj").unwrap(),
            AddressType::NestedSegWit
        );
        // Native SegWit（bech32, witness v0）
        assert_eq!(
            detect_address_type("bc1q5tgrcty99d7d7muxl6kk3xkmkm32c30kn3cyza").unwrap(),
            AddressType::NativeSegWit
        );
    }

    #[test]
    fn test_validate_accepts_all_four_address_types() {
        // 4 种类型地址分别构造 Config，validate 均应通过，且类型检测一致
        let cases = [
            (
                "bc1pnlgec4pd8ekmhsqdzese7jfqsnae9f6cu99m4f0cz877e3lt4v3sv2s4h7",
                AddressType::Taproot,
            ),
            ("1KddEkd2fiWuibkSmK1ASBpjpTDjmAZTKs", AddressType::Legacy),
            (
                "3BSruDfveoFrFG5LSfW77CJcN61ARoMHZj",
                AddressType::NestedSegWit,
            ),
            (
                "bc1q5tgrcty99d7d7muxl6kk3xkmkm32c30kn3cyza",
                AddressType::NativeSegWit,
            ),
        ];

        for (addr, expected) in cases {
            let config = make_config(addr);
            assert!(
                config.validate().is_ok(),
                "{} 地址校验应通过: {}",
                expected,
                addr
            );
            assert_eq!(
                config.address_type().unwrap(),
                expected,
                "{} 地址类型检测应一致",
                addr
            );
        }
    }

    #[test]
    fn test_validate_rejects_bad_checksum_addresses() {
        // 各类型 checksum 错误地址应被拒绝
        let bad_addresses = [
            "1KddEkd2fiWuibkSmK1ASBpjpTDjmAZTKt", // Legacy 末字符改动，checksum 错
            "bc1q5tgrcty99d7d7muxl6kk3xkmkm32c30kn3cyzz", // Native SegWit checksum 错
            "bc1pnlgec4pd8ekmhsqdzese7jfqsnae9f6cu99m4f0cz877e3lt4v3sv2s4hz", // Taproot checksum 错
        ];

        for bad in bad_addresses {
            assert!(
                detect_address_type(bad).is_err(),
                "坏 checksum 地址应检测失败: {}",
                bad
            );
            let config = make_config(bad);
            assert!(
                config.validate().is_err(),
                "坏 checksum 地址应校验失败: {}",
                bad
            );
        }
    }

    #[test]
    fn test_validate_rejects_testnet_address() {
        // 格式合法的 testnet 地址（非主网）应被拒绝
        let testnet = "mfcHP2WMCVLsVZA8yrovmhMgxNFW9r98xw";
        assert!(
            detect_address_type(testnet).is_err(),
            "testnet 地址应检测失败"
        );
        let config = make_config(testnet);
        assert!(config.validate().is_err(), "testnet 地址应校验失败");
    }

    #[test]
    fn test_detect_rejects_malformed_strings() {
        // 完全非法的字符串
        let bad = ["", "not-an-address", "1Cmo", "bc1q", "bc1p"];
        for s in bad {
            assert!(
                detect_address_type(s).is_err(),
                "非法字符串应检测失败: {:?}",
                s
            );
        }
    }
}
