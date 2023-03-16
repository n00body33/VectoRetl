use std::{collections::HashSet, process::Command};

use anyhow::Result;

use crate::app::CommandExt as _;

pub fn current_branch() -> Result<String> {
    let output = capture_output(&["rev-parse", "--abbrev-ref", "HEAD"])?;
    Ok(output.trim_end().to_string())
}

pub fn checkout_or_create_branch(branch_name: &str) -> Result<()> {
    if branch_exists(branch_name)? {
        checkout_branch(branch_name)?;
    } else {
        create_branch(branch_name)?;
    }
    Ok(())
}

pub fn merge_branch(branch_name: &str) -> Result<()> {
    let _output = capture_output(&["merge", "--ff", branch_name])?;
    Ok(())
}

pub fn tag_version(version: &str) -> Result<()> {
    let _output = capture_output(&["tag", "--annotate", version, "--message", version])?;
    Ok(())
}

pub fn push_branch(branch_name: &str) -> Result<()> {
    let _output = capture_output(&["push", "origin", branch_name])?;
    Ok(())
}

pub fn changed_files() -> Result<Vec<String>> {
    let mut files = HashSet::new();

    // Committed e.g.:
    // A   relative/path/to/file.added
    // M   relative/path/to/file.modified
    let output = capture_output(&["diff", "--name-status", "origin/master..."])?;
    for line in output.lines() {
        if !is_warning_line(line) {
            if let Some((_, path)) = line.split_once('\t') {
                files.insert(path.to_string());
            }
        }
    }

    // Tracked
    let output = capture_output(&["diff", "--name-only", "HEAD"])?;
    for line in output.lines() {
        if !is_warning_line(line) {
            files.insert(line.to_string());
        }
    }

    // Untracked
    let output = capture_output(&["ls-files", "--others", "--exclude-standard"])?;
    for line in output.lines() {
        files.insert(line.to_string());
    }

    let mut sorted = Vec::from_iter(files);
    sorted.sort();

    Ok(sorted)
}

pub fn list_files() -> Result<Vec<String>> {
    Ok(capture_output(&["ls-files"])?
        .lines()
        .map(str::to_owned)
        .collect())
}

/// Get a list of files that have been modified, as a vector of strings
pub fn get_modified_files() -> Result<Vec<String>> {
    let args = vec![
        "ls-files",
        "--full-name",
        "--modified",
        "--others",
        "--exclude-standard",
    ];
    Ok(capture_output(&args)?.lines().map(str::to_owned).collect())
}

pub fn set_config_values(config_values: &[(&str, &str)]) -> Result<String> {
    let mut args = vec!["config"];

    for (key, value) in config_values {
        args.push(key);
        args.push(value);
    }

    capture_output(&args)
}

/// Checks if the current directory's repo is clean
pub fn check_git_repository_clean() -> Result<bool> {
    Ok(Command::new("git")
        .args(["diff-index", "--quiet", "HEAD"])
        .stdout(std::process::Stdio::null())
        .status()
        .map(|status| status.success())?)
}

/// Commits changes from the current repo
pub fn commit(commit_message: &str) -> Result<String> {
    Command::new("git")
        .args(["-am", commit_message])
        .capture_output()
}

/// Pushes changes from the current repo
pub fn push() -> Result<String> {
    Command::new("git").arg("push").capture_output()
}

pub fn clone(repo_url: &str) -> Result<String> {
    Command::new("git")
        .args(["clone", repo_url])
        .capture_output()
}

pub fn branch_exists(branch_name: &str) -> Result<bool> {
    let output = capture_output(&["rev-parse", "--verify", branch_name])?;
    Ok(!output.is_empty())
}

pub fn checkout_branch(branch_name: &str) -> Result<()> {
    let _output = capture_output(&["checkout", branch_name])?;
    Ok(())
}

pub fn create_branch(branch_name: &str) -> Result<()> {
    let _output = capture_output(&["checkout", "-b", branch_name])?;
    Ok(())
}

fn capture_output(args: &[&str]) -> Result<String> {
    Command::new("git").in_repo().args(args).capture_output()
}

fn is_warning_line(line: &str) -> bool {
    line.starts_with("warning: ") || line.contains("original line endings")
}
