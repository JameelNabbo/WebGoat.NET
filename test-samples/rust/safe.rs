// Safe Rust code - should produce minimal/no findings
// This file demonstrates secure patterns.

use std::fs;
use std::path::Path;
use std::io;

/// Properly handles errors with Result
fn read_config(path: &str) -> Result<String, io::Error> {
    let canonical = Path::new(path).canonicalize()?;
    if !canonical.starts_with("/etc/app/") {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Access denied"));
    }
    fs::read_to_string(canonical)
}

/// Uses environment variables properly
fn get_port() -> u16 {
    std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .unwrap_or(8080)
}

/// Proper error handling with match
fn safe_parse(input: &str) -> Option<i32> {
    match input.parse::<i32>() {
        Ok(val) => Some(val),
        Err(_) => None,
    }
}

/// Safe array access with .get()
fn safe_index(data: &[i32], idx: usize) -> Option<&i32> {
    data.get(idx)
}

/// Uses checked arithmetic
fn safe_add(a: u32, b: u32) -> Option<u32> {
    a.checked_add(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_parse() {
        assert_eq!(safe_parse("42"), Some(42));
        assert_eq!(safe_parse("abc"), None);
    }

    #[test]
    fn test_unwrap_in_test() {
        // unwrap in tests is fine
        let result: Result<i32, &str> = Ok(42);
        assert_eq!(result.unwrap(), 42);
    }
}

fn main() {
    println!("Safe code example");
}
