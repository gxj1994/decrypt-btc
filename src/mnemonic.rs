//! Mnemonic module for BIP39 wordlist management and candidate generation

use crate::config::Config;
use std::fs;
use std::path::Path;

/// BIP39 Wordlist (2048 English words)
pub struct Bip39Wordlist {
    words: Vec<String>,
}

impl Bip39Wordlist {
    /// Load wordlist from file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let words: Vec<String> = content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.trim().to_string())
            .collect();

        if words.len() != 2048 {
            return Err(format!("Expected 2048 words, got {}", words.len()).into());
        }

        Ok(Self { words })
    }

    /// Get word by index
    pub fn get_word(&self, index: usize) -> Option<&str> {
        self.words.get(index).map(|s| s.as_str())
    }

    /// Get index by word
    pub fn get_index(&self, word: &str) -> Option<usize> {
        self.words.iter().position(|w| w == word)
    }

    /// Get all words
    pub fn words(&self) -> &[String] {
        &self.words
    }

    /// Get all word indices (0..2047)
    pub fn all_indices(&self) -> Vec<u16> {
        (0..2048).collect()
    }
}

/// Candidate word indices for each position
pub type CandidateIndices = Vec<Vec<u16>>;

/// Generate candidate mnemonic combinations
pub struct CandidateGenerator {
    wordlist: Bip39Wordlist,
}

impl CandidateGenerator {
    pub fn new(wordlist: Bip39Wordlist) -> Self {
        Self { wordlist }
    }

    /// Build candidate indices from configuration
    pub fn build_candidates(
        &self,
        config: &Config,
    ) -> Result<CandidateIndices, Box<dyn std::error::Error>> {
        let mut candidates = Vec::with_capacity(config.mnemonic_size);

        for i in 0..config.mnemonic_size {
            if let Some(words) = config.get_candidates_for_position(i) {
                // Use configured candidates
                let mut indices = Vec::new();
                for word in words {
                    if let Some(index) = self.wordlist.get_index(word) {
                        indices.push(index as u16);
                    } else {
                        return Err(format!("Word '{}' not found in BIP39 wordlist", word).into());
                    }
                }
                candidates.push(indices);
            } else {
                // Use all 2048 words
                candidates.push((0..2048).map(|i| i as u16).collect());
            }
        }

        Ok(candidates)
    }

    /// Calculate total search space
    pub fn calculate_search_space(candidates: &CandidateIndices) -> u64 {
        let mut total: u64 = 1;
        for position in candidates {
            total = total.saturating_mul(position.len() as u64);
        }
        total
    }

    /// Get wordlist reference
    pub fn wordlist(&self) -> &Bip39Wordlist {
        &self.wordlist
    }
}

/// Convert indices to mnemonic string
pub fn indices_to_mnemonic(
    indices: &[u16],
    wordlist: &Bip39Wordlist,
) -> Result<String, Box<dyn std::error::Error>> {
    let words: Vec<&str> = indices
        .iter()
        .map(|&idx| {
            wordlist
                .get_word(idx as usize)
                .ok_or_else(|| format!("Invalid word index: {}", idx))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(words.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_load() {
        // This test will fail if english.txt doesn't exist
        let result = Bip39Wordlist::load("data/english.txt");
        assert!(result.is_ok());

        let wordlist = result.unwrap();
        assert_eq!(wordlist.words().len(), 2048);
        assert_eq!(wordlist.get_word(0), Some("abandon"));
    }
}
