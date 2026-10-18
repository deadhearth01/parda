use std::path::Path;
use crate::util::result::Result;


/// Sub-word tokenization (aka encoding)
pub trait Tokenizer {
    fn encode(&self, input: &str) -> Result<Vec<u32>>;

    /// Ids of the sequence start / end special tokens (parda patch: models built on
    /// non-DeBERTa encoders such as ModernBERT/Ettin do not use 1 and 2).
    fn special_ids(&self) -> (i64, i64) {
        (1, 2)
    }
}


/// Implement `Tokenizer` as a wrapper around Hugging Face tokenizers
pub struct HFTokenizer {
    inner: tokenizers::Tokenizer,
}


impl HFTokenizer {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self {
            inner: tokenizers::Tokenizer::from_file(path)?
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: tokenizers::Tokenizer::from_bytes(bytes)?
        })
    }
}

impl Tokenizer for HFTokenizer {
    fn encode(&self, input: &str) -> Result<Vec<u32>> {
        let encoding = self.inner.encode(input, false)?;
        Ok(encoding.get_ids().to_vec())
    }

    fn special_ids(&self) -> (i64, i64) {
        let find = |names: &[&str], default: i64| {
            names.iter().find_map(|n| self.inner.token_to_id(n)).map(i64::from).unwrap_or(default)
        };
        (find(&["[CLS]", "<s>"], 1), find(&["[SEP]", "</s>"], 2))
    }
}