//! Configuration module for loading and validating BTC decrypt settings

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Configuration structure loaded from YAML file
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Mnemonic length (12/15/18/21/24)
    pub mnemonic_size: usize,

    /// Optional passphrases
    #[serde(default)]
    pub passwords: Vec<String>,

    /// Target BTC address (Legacy format, starts with '1')
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

    #[error("Invalid target address: {0}. Must be a valid Legacy address starting with '1'")]
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

        // Validate target address format
        if !self.target_address.starts_with('1') {
            return Err(ConfigError::InvalidAddress(self.target_address.clone()));
        }
        if self.target_address.len() < 26 || self.target_address.len() > 35 {
            return Err(ConfigError::InvalidAddress(self.target_address.clone()));
        }

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

    /// Check if a position uses all 2048 words
    pub fn is_full_search_for_position(&self, position: usize) -> bool {
        let key = format!("word{}", position);
        match self.word_positions.get(&key) {
            Some(words) => words.is_empty(),
            None => true,
        }
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
}
