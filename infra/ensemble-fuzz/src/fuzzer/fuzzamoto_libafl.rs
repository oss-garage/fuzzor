use std::path::{Path, PathBuf};
use std::process::Stdio;

use async_trait::async_trait;
use fuzzor_infra::FuzzerStats;

use super::Fuzzer;

/// FuzzamotoLibAflFuzzer is an implementation of [`Fuzzer`] for fuzzamoto's libafl based fuzzer.
///
/// A single instance occupies all available cores.
pub struct FuzzamotoLibAflFuzzer {
    share_dir: PathBuf,
    seeds: PathBuf,
    /// Name of the sanitizer build, e.g. `fuzzamoto_libafl_asan`.
    build: String,
    out_dir: PathBuf,
    log_file: PathBuf,
    pid: Option<u32>,
}

impl FuzzamotoLibAflFuzzer {
    pub fn new(share_dir: PathBuf, seeds: PathBuf, workspace: &Path) -> Self {
        let build = share_dir
            .parent()
            .and_then(|dir| dir.file_name())
            .expect("share dir has no parent")
            .to_string_lossy()
            .to_string();
        let workspace = workspace.join(&build);

        Self {
            share_dir,
            seeds,
            build,
            out_dir: workspace.join("out"),
            log_file: workspace.join("fuzzer.log"),
            pid: None,
        }
    }

    fn binary(&self) -> PathBuf {
        self.share_dir
            .parent()
            .expect("share dir has no parent")
            .join("fuzzamoto-libafl")
    }

    /// Collect `out/cpu_*/<name>` for all cores.
    fn core_dirs(&self, name: &str) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(&self.out_dir) else {
            return Vec::new();
        };

        entries
            .flatten()
            .map(|entry| entry.path().join(name))
            .filter(|path| path.is_dir())
            .collect()
    }

    fn last_stats_line(&self) -> Option<String> {
        use std::io::{Read, Seek, SeekFrom};

        const TAIL: u64 = 64 * 1024;

        let mut file = std::fs::File::open(&self.log_file).ok()?;
        let len = file.metadata().ok()?.len();
        file.seek(SeekFrom::Start(len.saturating_sub(TAIL))).ok()?;

        // The stats lines start with an emoji, so an arbitrary offset regularly lands inside a
        // multi-byte sequence. Reading as bytes keeps a stats read from failing over that.
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).ok()?;
        let tail = String::from_utf8_lossy(&bytes);

        tail.lines()
            .rev()
            .find(|line| line.contains("exec/sec:"))
            .map(String::from)
    }
}

/// Nyx resolves paths against its own working directory, so it needs absolute ones.
fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Cores the process is allowed to run on, as `--cores` expects them (e.g. "24-31").
///
/// `--cores all` resolves to the ids 0..num_cpus, which are the wrong ones under a cpu set.
fn allowed_cores() -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
                .map(|cores| cores.trim().to_string())
        })
        .unwrap_or(String::from("all"))
}

fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.split(name).nth(1)?.split_whitespace().next()
}

/// Parse numbers that libafl prettifies with a magnitude suffix (e.g. "1.2k").
fn parse_pretty(value: &str) -> Option<f64> {
    let (number, factor) = match value.chars().last()? {
        'k' | 'K' => (&value[..value.len() - 1], 1_000.0),
        'm' | 'M' => (&value[..value.len() - 1], 1_000_000.0),
        _ => (value, 1.0),
    };

    number.parse::<f64>().ok().map(|n| n * factor)
}

#[async_trait]
impl Fuzzer for FuzzamotoLibAflFuzzer {
    fn get_name(&self) -> &str {
        "fuzzamoto-libafl"
    }

    fn get_instance_name(&self) -> String {
        self.build.clone()
    }

    async fn get_stats(&self) -> FuzzerStats {
        let mut stats = FuzzerStats::default();

        let Some(line) = self.last_stats_line() else {
            return stats;
        };

        stats.execs_per_sec = field(&line, "exec/sec:")
            .and_then(parse_pretty)
            .unwrap_or(0.0);
        // Hangs are ignored, so every bug is a crash.
        stats.saved_crashes = field(&line, "bugs:").and_then(parse_pretty).unwrap_or(0.0) as u64;
        stats.stability = field(&line, "stability:")
            .and_then(|s| s.strip_suffix('%'))
            .and_then(parse_pretty);

        stats
    }

    async fn has_started_fuzzing(&self) -> bool {
        // Stats are reported while the vms are still booting, so wait for an actual execution.
        self.last_stats_line()
            .and_then(|line| field(&line, "execs:").and_then(parse_pretty))
            .is_some_and(|execs| execs > 0.0)
    }

    fn get_push_corpus(&self) -> Option<PathBuf> {
        // The clients share their inputs, so the queue of one of them is enough.
        let mut queues = self.core_dirs("queue");
        queues.sort();
        queues.into_iter().next()
    }

    fn get_pull_corpus(&self) -> Option<PathBuf> {
        None // libafl shares new inputs between its own clients
    }

    fn get_solutions(&self) -> Vec<PathBuf> {
        self.core_dirs("crashes")
    }

    fn start(&mut self) -> tokio::process::Child {
        let _ = std::fs::create_dir_all(&self.out_dir);

        let mut command = tokio::process::Command::new(self.binary());
        command
            .args(["--input", absolute(&self.seeds).to_str().unwrap()])
            .args(["--output", absolute(&self.out_dir).to_str().unwrap()])
            .args(["--share", absolute(&self.share_dir).to_str().unwrap()])
            .args(["--log", absolute(&self.log_file).to_str().unwrap()])
            .args(["--timeout", "3000"])
            .args(["--cores", &allowed_cores()])
            .process_group(0)
            .stdout(Stdio::null())
            .kill_on_drop(true);

        // Startup failures only show up on stderr.
        match std::fs::File::create(self.log_file.with_extension("stderr")) {
            Ok(file) => command.stderr(Stdio::from(file)),
            Err(_) => command.stderr(Stdio::null()),
        };

        let child = command
            .spawn()
            .expect("Could not start fuzzamoto-libafl instance");
        self.pid = child.id();
        child
    }
}

impl Drop for FuzzamotoLibAflFuzzer {
    fn drop(&mut self) {
        // Killing the main process leaves its clients running, so kill the whole group.
        if let Some(pid) = self.pid {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", "--", &format!("-{}", pid)])
                .status();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = "1234.5s 📊 time: 0h-1m-2s (x8) execs: 12345 cov: 100/200 corpus: 42 exec/sec: 1.2k stability: 99.50% bugs: 3 (2d /1h)";

    #[test]
    fn parse_stats_line() {
        assert_eq!(
            field(LINE, "exec/sec:").and_then(parse_pretty),
            Some(1200.0)
        );
        assert_eq!(field(LINE, "bugs:").and_then(parse_pretty), Some(3.0));
        assert_eq!(field(LINE, "execs:").and_then(parse_pretty), Some(12345.0));
        assert_eq!(
            field(LINE, "stability:")
                .and_then(|s| s.strip_suffix('%'))
                .and_then(parse_pretty),
            Some(99.5)
        );
    }
}
