use std::{ env, path::PathBuf, sync::Arc };
use nanoid::nanoid;
use parking_lot::RwLock;

fn get_dir(test_env: bool) -> Result<PathBuf, std::io::Error> {
    let dir = if test_env {
        env::current_dir()?
    } else {
        let mut d = env::current_exe()?;
        d.pop();
        d
    };
    Ok(dir)
}

pub fn config_dir(test_env: bool) -> Result<PathBuf, std::io::Error> {
    let mut dir = get_dir(test_env)?;
    dir.push("configs");
    Ok(dir)
}

pub fn log_dir(test_env: bool) -> Result<PathBuf, std::io::Error> {
    let mut dir = get_dir(test_env)?;
    dir.push("logs");
    Ok(dir)
}

pub fn ref_to_digit(v: &str) -> Result<u8, String> {
    if !v.starts_with(':') {
        return Err("doesn't begin with :".to_string());
    }
    let n = v
        .replace(':', "")
        .parse::<u8>()
        .map_err(|e| e.to_string())?;
    Ok(n)
}

pub fn generate_id() -> String {
    nanoid!(9)
}

// This is only used for serialize
pub fn is_locked_zero_or_less(num: &Arc<RwLock<i64>>) -> bool {
    let r = num.read();
    *r <= 0
}
// This is only used for serialize
pub fn is_locked_string_empty(s: &Arc<RwLock<String>>) -> bool {
    let r = s.read();
    r.is_empty()
}