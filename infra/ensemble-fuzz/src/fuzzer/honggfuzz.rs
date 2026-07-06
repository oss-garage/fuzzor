use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;

use async_trait::async_trait;
use fuzzor_infra::FuzzerStats;

use super::Fuzzer;

pub struct HonggFuzzer {
    binary: PathBuf,
    corpus: PathBuf,
    solutions: PathBuf,
    stats_file: PathBuf,
    num_threads: u64,
}

impl HonggFuzzer {
    pub fn new(binary: PathBuf, workspace: PathBuf, num_threads: u64) -> Self {
        Self {
            binary,
            corpus: workspace.join("corpus"),
            solutions: workspace.join("solutions"),
            stats_file: workspace.join("honggfuzz.stats"),
            num_threads,
        }
    }
}

/// Parse a line from the honggfuzz stats file:
///
/// `# unix_time, last_cov_update, total_exec, exec_per_sec, crashes, unique_crashes, hangs, edge_cov, block_cov, corpus_count`
///
/// Returns `None` for comment lines as well as malformed or partially written
/// lines (the stats file is parsed while honggfuzz is appending to it).
fn parse_stats_line(line: &str) -> Option<FuzzerStats> {
    if line.starts_with('#') {
        return None;
    }

    let fields = line
        .split(',')
        .map(|num_str| num_str.trim().parse::<u64>())
        .collect::<Result<Vec<u64>, _>>()
        .ok()?;

    Some(FuzzerStats {
        execs_per_sec: *fields.get(3)? as f64,
        saved_crashes: *fields.get(5)?,
        // saved_hangs: *fields.get(6)?, // honggfuzz does not save timeouts to disk :(
        corpus_count: *fields.get(9)?,
        ..FuzzerStats::default()
    })
}

#[async_trait]
impl Fuzzer for HonggFuzzer {
    fn get_name(&self) -> &str {
        "honggfuzz"
    }

    fn get_instance_name(&self) -> String {
        self.get_name().to_string()
    }

    async fn get_stats(&self) -> FuzzerStats {
        let Ok(contents) = std::fs::read_to_string(&self.stats_file) else {
            return FuzzerStats::default();
        };

        contents
            .lines()
            .rev()
            .find_map(parse_stats_line)
            .unwrap_or_default()
    }

    async fn has_started_fuzzing(&self) -> bool {
        std::fs::read_to_string(&self.stats_file)
            .map(|contents| {
                contents
                    .lines()
                    .any(|line| parse_stats_line(line).is_some())
            })
            .unwrap_or(false)
    }

    fn get_push_corpus(&self) -> Option<PathBuf> {
        Some(self.corpus.clone())
    }
    fn get_pull_corpus(&self) -> Option<PathBuf> {
        None
    }

    fn get_solutions(&self) -> Vec<PathBuf> {
        vec![self.solutions.clone()]
    }

    fn start(&mut self) -> tokio::process::Child {
        let _ = std::fs::create_dir_all(&self.corpus);
        let _ = std::fs::create_dir_all(&self.solutions);

        let _ = std::fs::remove_file(&self.stats_file);

        let num_threads_str = self.num_threads.to_string();
        let args = vec![
            "--timeout",
            "10",
            "--verbose",
            "--quiet",
            "--statsfile",
            self.stats_file.to_str().unwrap(),
            "--input",
            self.corpus.to_str().unwrap(),
            "--crashdir",
            self.solutions.to_str().unwrap(),
            "--threads",
            num_threads_str.as_str(),
            "--",
            self.binary.to_str().unwrap(),
        ];

        let host_env: HashMap<String, String> = std::env::vars().collect();
        tokio::process::Command::new("honggfuzz")
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .envs(host_env)
            .kill_on_drop(true)
            .spawn()
            .expect("Could not start honggfuzz instance")
    }
}
