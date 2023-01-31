use std::{ env, path::PathBuf };

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

/*
pub fn log_dir() -> Result<PathBuf, std::io::Error> {
    let mut dir = get_dir()?;
    dir.push("logs");
    Ok(dir)
}
*/

pub fn ref_to_digit(v: String) -> Result<u8, String> {
    if !v.starts_with(':') {
        return Err("doesn't begin with :".to_string());
    }
    let n = v
        .replace(':', "")
        .parse::<u8>()
        .map_err(|e| e.to_string())?;
    Ok(n)
}