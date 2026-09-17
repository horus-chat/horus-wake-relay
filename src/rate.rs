use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct RateLimited;

pub struct RateLimiter {
    window: Duration,
    max: u32,
    hits: HashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    pub fn new(window: Duration, max: u32) -> Self {
        Self {
            window,
            max,
            hits: HashMap::new(),
        }
    }

    pub fn check(&mut self, key: &str) -> Result<(), RateLimited> {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let entry = self.hits.entry(key.to_string()).or_default();
        entry.retain(|t| *t > cutoff);
        if entry.len() as u32 >= self.max {
            return Err(RateLimited);
        }
        entry.push(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_then_blocks() {
        let mut r = RateLimiter::new(Duration::from_secs(60), 2);
        assert!(r.check("a").is_ok());
        assert!(r.check("a").is_ok());
        assert!(r.check("a").is_err());
        assert!(r.check("b").is_ok());
    }
}
