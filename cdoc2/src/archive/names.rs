use std::collections::HashSet;

use super::{FileEntry, FileNameError};

const FORBIDDEN_CHARS: [char; 8] = ['<', '>', ':', '\\', '/', '|', '?', '*'];
const RESERVED_NAMES: [&str; 28] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "COM¹", "COM²", "COM³", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9", "LPT¹", "LPT²", "LPT³",
];
const RIGHT_TO_LEFT_OVERRIDE: char = '\u{202E}';
const NONCHARACTERS: [char; 2] = ['\u{FFFE}', '\u{FFFF}'];
const MAX_NAME_LEN: usize = 1000;

pub(crate) fn check_file_names(files: &[FileEntry]) -> Result<(), FileNameError> {
    let mut names = HashSet::new();
    for file in files {
        check_file_name(file.name, &mut names)?;
    }
    Ok(())
}

pub(super) fn check_file_name(name: &str, seen: &mut HashSet<String>) -> Result<(), FileNameError> {
    if !is_valid_file_name(name) {
        return Err(FileNameError::Unsafe(name.to_owned()));
    }
    if !seen.insert(name.to_owned()) {
        return Err(FileNameError::Duplicate(name.to_owned()));
    }
    Ok(())
}

// https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
// https://open-eid.github.io/CDOC2/2.0/02_protocol_and_cryptography_spec/ch03_container_format/#unencrypted-payload
fn is_valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name.starts_with([' ', '-'])
        && !name.ends_with([' ', '.'])
        && !is_reserved_name(name)
        && !name.chars().any(|c| {
            FORBIDDEN_CHARS.contains(&c)
                || c.is_control()
                || c == RIGHT_TO_LEFT_OVERRIDE
                || NONCHARACTERS.contains(&c)
        })
}

fn is_reserved_name(name: &str) -> bool {
    let stem = name
        .split_once('.')
        .map_or(name, |(stem, _)| stem)
        .trim_end_matches(' ');
    RESERVED_NAMES
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}
