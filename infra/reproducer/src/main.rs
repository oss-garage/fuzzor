mod reproducer;

use std::path::PathBuf;

use clap::Parser;
use tokio::fs;

use fuzzor_infra::{get_harness_binary, FuzzEngine, ProjectConfig, Sanitizer};

use reproducer::{
    FuzzamotoReproducer, LibFuzzerReproducer, NativeGoReproducer, Reproducer, SemSanReproducer,
};
use std::error::Error;

async fn reproduce<E: Error, R: Reproducer<E>>(reproducer: R, output_dir: &PathBuf) {
    let result = reproducer.reproduce().await;

    match result {
        Ok(solution) => {
            let output_file = match std::fs::File::create(output_dir.join(solution.name())) {
                Ok(file) => file,
                Err(err) => {
                    log::error!("Failed to create output file: {}", err);
                    return;
                }
            };

            if let Err(err) = serde_yaml::to_writer(output_file, &solution) {
                log::error!("Failed to write solution to {:?}: {}", output_dir, err);
            }
        }
        Err(err) => {
            log::error!("Failed to reproduce solution: {}", err);
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub struct Options {
    #[arg(
        long = "output-dir",
        help = "Path to output directory where reproduced solutions are written to",
        required = true
    )]
    pub output_dir: PathBuf,
    #[arg(help = "Path to the project config", required = true)]
    pub config: PathBuf,
    #[arg(
        help = "Files or directories containing the solutions to reproduce",
        required = true
    )]
    pub solutions: Vec<PathBuf>,
    #[arg(
        help = "Name of the harness to reproduce solutions for",
        required = true
    )]
    pub harness: String,
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    env_logger::init();

    let opts = Options::parse();

    let config = fs::read_to_string(&opts.config).await?;
    let config: ProjectConfig = serde_yaml::from_str(&config).unwrap();

    let _ = tokio::fs::create_dir_all(&opts.output_dir).await;

    if let Some(native_go_bin) = get_harness_binary(
        &FuzzEngine::NativeGo,
        &Sanitizer::None,
        &opts.harness,
        &config,
    ) {
        // Reproduce Go testcases that have been written to testdata/fuzz/<harness>/<testcase>.
        reproduce(NativeGoReproducer::new(native_go_bin), &opts.output_dir).await;

        return Ok(());
    }

    if config.name == "fuzzamoto" {
        // Special case for fuzzamoto reproduction
        let fuzzamoto_dir = get_harness_binary(
            &FuzzEngine::AflPlusPlusNyx,
            &Sanitizer::None, // actually ASan
            &opts.harness,
            &config,
        )
        .expect("Could not find fuzzamoto harness");

        for file in opts.solutions.iter() {
            if file.is_file() {
                reproduce(
                    FuzzamotoReproducer::new(fuzzamoto_dir.clone(), file.clone()),
                    &opts.output_dir,
                )
                .await;
            } else if file.is_dir() {
                let mut dir_entries = fs::read_dir(file).await?;
                while let Some(entry) = dir_entries.next_entry().await? {
                    reproduce(
                        FuzzamotoReproducer::new(fuzzamoto_dir.clone(), entry.path()),
                        &opts.output_dir,
                    )
                    .await;
                }
            }
        }

        return Ok(());
    }

    let sanitizers = vec![
        Sanitizer::None,
        Sanitizer::Undefined,
        Sanitizer::Address,
        Sanitizer::Memory,
        Sanitizer::Thread,
    ];
    let libfuzzer_harnesses: Vec<(PathBuf, Sanitizer)> = sanitizers
        .iter()
        .filter(|sanitizer| config.has_sanitizer(sanitizer))
        .map(|sanitizer| {
            (
                get_harness_binary(&FuzzEngine::LibFuzzer, sanitizer, &opts.harness, &config)
                    .unwrap(),
                sanitizer.clone(),
            )
        })
        .collect();

    let semsan_pairs: Vec<(PathBuf, PathBuf)> = if let Some(sanitizers) = &config.sanitizers {
        sanitizers
            .iter()
            .filter(|s| matches!(s, Sanitizer::SemSan(_)))
            .map(|s| {
                (
                    get_harness_binary(
                        &FuzzEngine::AflPlusPlus,
                        &Sanitizer::None,
                        &opts.harness,
                        &config,
                    )
                    .unwrap(),
                    get_harness_binary(&FuzzEngine::AflPlusPlus, s, &opts.harness, &config)
                        .unwrap(),
                )
            })
            .collect()
    } else {
        Vec::new()
    };

    for dir_or_file in opts.solutions.iter() {
        if dir_or_file.is_file() {
            log::info!("Reproducing test case: {:?}", dir_or_file);

            for (bin, sanitizer) in libfuzzer_harnesses.iter() {
                reproduce(
                    LibFuzzerReproducer::new(bin.clone(), sanitizer.clone(), dir_or_file.clone()),
                    &opts.output_dir,
                )
                .await;
            }

            if config.has_engine(&FuzzEngine::AflPlusPlus) && config.has_engine(&FuzzEngine::SemSan)
            {
                for (primary, secondary) in semsan_pairs.iter() {
                    reproduce(
                        SemSanReproducer::new(
                            primary.clone(),
                            secondary.clone(),
                            dir_or_file.clone(),
                        ),
                        &opts.output_dir,
                    )
                    .await;
                }
            }

            continue;
        }

        if dir_or_file.is_dir() {
            log::info!("Reproducing all test cases from dir: {:?}", dir_or_file);

            let mut dir_entries = fs::read_dir(dir_or_file).await?;
            while let Some(entry) = dir_entries.next_entry().await? {
                if !entry.path().is_file() {
                    continue;
                }

                for (bin, sanitizer) in libfuzzer_harnesses.iter() {
                    reproduce(
                        LibFuzzerReproducer::new(bin.clone(), sanitizer.clone(), entry.path()),
                        &opts.output_dir,
                    )
                    .await;
                }

                if config.has_engine(&FuzzEngine::AflPlusPlus)
                    && config.has_engine(&FuzzEngine::SemSan)
                {
                    for (primary, secondary) in semsan_pairs.iter() {
                        reproduce(
                            SemSanReproducer::new(primary.clone(), secondary.clone(), entry.path()),
                            &opts.output_dir,
                        )
                        .await;
                    }
                }
            }
        }
    }

    Ok(())
}
