use indicatif::{ProgressBar, ProgressStyle};

pub fn create_progress_bar(length: u64, template: &str) -> ProgressBar {
    let pb = ProgressBar::new(length);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(template)
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("#>-"),
    );
    pb
}

pub fn create_standard_progress_bar(length: u64, operation: &str) -> ProgressBar {
    create_progress_bar(
        length,
        &format!("{{spinner:.green}} {operation} [{{elapsed_precise}}] [{{bar:40.cyan/blue}}] {{pos}}/{{len}} {{msg}}")
    )
}

pub fn create_byte_progress_bar(length: u64, operation: &str) -> ProgressBar {
    create_progress_bar(
        length,
        &format!("{{spinner:.green}} {operation} [{{elapsed_precise}}] [{{bar:40.yellow/red}}] {{bytes}}/{{total_bytes}} ({{bytes_per_sec}}, {{eta}})")
    )
}
