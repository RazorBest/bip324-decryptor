use std::path::{Path, PathBuf};

use time::macros::format_description;
use tracing::level_filters::LevelFilter;
use tracing_appender::rolling::{Builder, Rotation};
use tracing_subscriber::Layer;
use tracing_subscriber::fmt::{self, format::FmtSpan, time::UtcTime};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::Registry;

type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync>;

fn get_file_layer_log(log_template: &Path, log_level: tracing::Level) -> impl Layer<Registry> {
    let directory = log_template.parent().expect("Log path must have parent");
    let prefix = log_template
        .file_prefix()
        .expect("Log path must have file name")
        .to_str()
        .unwrap();
    let suffix = log_template.extension();

    let mut builder = Builder::new()
        .rotation(Rotation::DAILY)
        .max_log_files(14)
        .filename_prefix(prefix);
    if let Some(suffix) = suffix {
        builder = builder.filename_suffix(suffix.to_str().unwrap());
    }
    let file_appender = builder.build(directory).unwrap();

    let timer = UtcTime::new(format_description!(
        "[year repr:last_two]-[month]-[day]T\
        [hour]:[minute]:[second].[subsecond digits:2]Z"
    ));

    fmt::layer()
        .with_writer(file_appender)
        .with_target(false)
        .with_timer(timer)
        .with_span_events(FmtSpan::CLOSE)
        .with_file(true)
        .with_line_number(true)
        // No colors
        .with_ansi(false)
        .with_filter(LevelFilter::from_level(log_level))
}

fn get_stdout_layer_log(log_level: tracing::Level) -> impl Layer<Registry> {
    let timer = UtcTime::new(format_description!(
        "[year repr:last_two]-[month]-[day]T\
        [hour]:[minute]:[second].[subsecond digits:2]Z"
    ));

    fmt::layer()
        .with_writer(std::io::stdout)
        .with_target(false)
        .with_timer(timer)
        .with_filter(LevelFilter::from_level(log_level))
}

pub fn setup_log(
    log_template: &Option<PathBuf>,
    log_level: tracing::Level,
    stdout_log_level: tracing::Level,
) {
    let registry = tracing_subscriber::registry();

    let mut layers: Vec<BoxedLayer> = vec![];
    if let Some(log_template) = log_template {
        let file_layer = get_file_layer_log(log_template, log_level);
        layers.push(file_layer.boxed());
    }

    let stdout_layer = get_stdout_layer_log(stdout_log_level);
    layers.push(stdout_layer.boxed());

    registry.with(layers).init();
}
