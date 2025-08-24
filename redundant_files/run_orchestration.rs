use std::{process::{Command, Stdio}, thread, time::Duration};

fn main() -> anyhow::Result<()> {
    // Read desired counts from env or defaults
    let threshold: u16 = std::env::var("THRESHOLD").ok().and_then(|v| v.parse().ok()).unwrap_or(3);
    let total: u16 = std::env::var("TOTAL").ok().and_then(|v| v.parse().ok()).unwrap_or(threshold);

    // Start TTP
    let _ttp = Command::new("cargo")
        .args(["run", "--bin", "ttp"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    // Wait a moment for TTP to bind
    thread::sleep(Duration::from_millis(300));

    // Start `total` issuers, each will self-bind to 127.0.0.1:9200+(id-1)
    for _i in 0..total {
        let _child = Command::new("cargo")
            .args(["run", "--bin", "issuer"]) // issuer decides own port after getting id
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;
        thread::sleep(Duration::from_millis(100));
    }

    // Optionally run user after a short delay
    if std::env::var("RUN_USER").unwrap_or_default() == "1" {
        thread::sleep(Duration::from_millis(500));
        let mut user = Command::new("cargo")
            .args(["run", "--bin", "user"])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;
        let _ = user.wait();
    }

    // Keep the launcher alive (or exit if LAUNCHER_EXIT=1)
    if std::env::var("LAUNCHER_EXIT").unwrap_or_default() == "1" {
        Ok(())
    } else {
        loop { thread::sleep(Duration::from_secs(5)); }
    }
}
