//! Interpretation of raw `strace -ff -qq -yy` output.
//!
//! These helpers answer one question before any behavior is derived: what did
//! strace actually report? Keeping that separate from behavior derivation makes
//! the "did this syscall really happen?" decision testable on its own.

const UNFINISHED_MARKER: &str = "<unfinished ...>";
const RESUMED_MARKER: &str = " resumed>";
const RESULT_MARKER: &str = ") = ";

/// Splices interrupted syscalls back into single lines.
///
/// strace reports a syscall that is interrupted mid-flight as two lines: an
/// entry line ending in `<unfinished ...>`, and a later `<... name resumed>`
/// line that carries the real result. Neither half can be interpreted on its
/// own, so the halves are rejoined before anything is parsed out of them.
///
/// An entry half that never reports a result is dropped, and so is a resumed
/// half with no recorded entry. Runprint must not record behavior that the
/// kernel never confirmed.
pub fn reassemble_trace_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending: Option<String> = None;

    for line in text.lines() {
        let line = line.trim_end();

        if line.is_empty() {
            continue;
        }

        // Signal deliveries and exit notices carry no syscall result.
        if line.starts_with("---") || line.starts_with("+++") {
            continue;
        }

        if let Some(head) = line.strip_suffix(UNFINISHED_MARKER) {
            pending = Some(head.trim_end().to_string());
            continue;
        }

        if let Some(tail) = resumed_tail(line) {
            if let Some(head) = pending.take() {
                lines.push(format!("{head}{tail}"));
            }

            continue;
        }

        lines.push(line.to_string());
    }

    lines
}

fn resumed_tail(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("<... ")?;
    let end = rest.find(RESUMED_MARKER)?;

    Some(&rest[end + RESUMED_MARKER.len()..])
}

/// The text strace printed after the syscall's closing `) = `.
///
/// Anchoring on the result region matters: a quoted path may itself contain
/// text that looks like a failed result.
pub fn syscall_result(line: &str) -> Option<&str> {
    let position = line.rfind(RESULT_MARKER)?;

    Some(line[position + RESULT_MARKER.len()..].trim())
}

/// A syscall counts as successful only when strace printed a non-negative
/// result for it. Failures (`-1 ERRNO`), restarts (`? ERESTARTSYS`) and lines
/// carrying no result at all are all rejected.
pub fn syscall_succeeded(line: &str) -> bool {
    match syscall_result(line) {
        Some(result) => !result.starts_with('-') && !result.starts_with('?'),
        None => false,
    }
}

/// Syscalls whose reported result proves the operation reached the kernel.
pub fn observable_syscall(line: &str) -> bool {
    syscall_succeeded(line) || connect_in_progress(line)
}

/// A non-blocking `connect()` reports `-1 EINPROGRESS`, and a later attempt on
/// the same socket reports `-1 EALREADY`, while the connection is genuinely
/// initiated toward the printed destination. Treating those as "did not
/// happen" would hide the destinations of every event-loop based client.
///
/// This is deliberately limited to those two errno values. `ECONNREFUSED`,
/// `EACCES`, `ENETUNREACH` and friends mean no connection was initiated.
fn connect_in_progress(line: &str) -> bool {
    if !line.starts_with("connect(") {
        return false;
    }

    let Some(result) = syscall_result(line) else {
        return false;
    };

    let Some(errno) = result.strip_prefix("-1 ") else {
        return false;
    };

    matches!(
        errno.split_whitespace().next(),
        Some("EINPROGRESS") | Some("EALREADY")
    )
}

/// The printed argument region between the first quoted path and the result.
///
/// Excluding the result keeps `-yy` descriptor annotations such as
/// `3</project/O_WRONLY>` from being read as access flags.
pub fn file_open_flags(line: &str) -> &str {
    let Some(path_end) = quoted_end(line, 0) else {
        return "";
    };

    let start = path_end + 1;
    let end = line.rfind(") =").unwrap_or(line.len());

    if start >= end {
        return "";
    }

    &line[start..end]
}

/// Whole-token flag lookup inside a printed argument region.
///
/// Substring matching would find `O_RDWR` inside unrelated text, so the region
/// is split on every character that cannot appear in a flag name.
pub fn flags_have_token(flags: &str, wanted: &str) -> bool {
    flags
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|token| token == wanted)
}

pub fn angle_path(value: &str) -> Option<String> {
    let start = value.find('<')? + 1;
    let rest = &value[start..];
    let end = rest.find('>')?;
    Some(rest[..end].to_string())
}

pub fn first_quoted_string(line: &str) -> Option<String> {
    nth_quoted_string(line, 0)
}

pub fn nth_quoted_string(line: &str, wanted: usize) -> Option<String> {
    let mut in_quote = false;
    let mut escaped = false;
    let mut start = 0usize;
    let mut index = 0usize;

    for (pos, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        if ch == '\\' && in_quote {
            escaped = true;
            continue;
        }

        if ch == '"' {
            if !in_quote {
                start = pos + 1;
                in_quote = true;
            } else {
                if index == wanted {
                    return Some(decode_strace_string(&line[start..pos]));
                }

                index += 1;
                in_quote = false;
            }
        }
    }

    None
}

fn decode_strace_string(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] != b'\\' {
            out.push(bytes[index]);
            index += 1;
            continue;
        }

        let escape_start = index;
        index += 1;

        if index >= bytes.len() {
            out.push(b'\\');
            break;
        }

        match bytes[index] {
            b'\\' => {
                out.push(b'\\');
                index += 1;
            }
            b'"' => {
                out.push(b'"');
                index += 1;
            }
            b'\'' => {
                out.push(b'\'');
                index += 1;
            }
            b'a' => {
                out.push(0x07);
                index += 1;
            }
            b'b' => {
                out.push(0x08);
                index += 1;
            }
            b'f' => {
                out.push(0x0c);
                index += 1;
            }
            b'n' => {
                out.push(b'\n');
                index += 1;
            }
            b'r' => {
                out.push(b'\r');
                index += 1;
            }
            b't' => {
                out.push(b'\t');
                index += 1;
            }
            b'v' => {
                out.push(0x0b);
                index += 1;
            }
            b'x' => {
                if index + 2 < bytes.len() {
                    if let (Some(high), Some(low)) =
                        (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
                    {
                        out.push((high << 4) | low);
                        index += 3;
                        continue;
                    }
                }

                out.extend_from_slice(&bytes[escape_start..=index]);
                index += 1;
            }
            b'0'..=b'7' => {
                let mut value = 0u16;
                let mut digits = 0usize;

                while index < bytes.len() && digits < 3 && matches!(bytes[index], b'0'..=b'7') {
                    value = value * 8 + u16::from(bytes[index] - b'0');
                    index += 1;
                    digits += 1;
                }

                if value <= u16::from(u8::MAX) {
                    out.push(value as u8);
                } else {
                    out.extend_from_slice(&bytes[escape_start..index]);
                }
            }
            other => {
                // Preserve unknown escapes instead of inventing semantics.
                out.push(b'\\');
                out.push(other);
                index += 1;
            }
        }
    }

    match String::from_utf8(out) {
        Ok(decoded) => decoded,
        Err(_) => raw.to_string(),
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn quoted_end(line: &str, wanted: usize) -> Option<usize> {
    let mut in_quote = false;
    let mut escaped = false;
    let mut index = 0usize;

    for (pos, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        if ch == '\\' && in_quote {
            escaped = true;
            continue;
        }

        if ch == '"' {
            if !in_quote {
                in_quote = true;
            } else {
                if index == wanted {
                    return Some(pos);
                }

                index += 1;
                in_quote = false;
            }
        }
    }

    None
}

pub fn extract_strace_quoted_field(line: &str, field: &str) -> Option<String> {
    let start = line.find(field)? + field.len();
    let rest = &line[start..];

    // Preserve current scope: pathname Unix sockets are quoted directly.
    // Abstract namespace sockets have a different strace representation
    // and are handled by extract_strace_abstract_unix_address.
    if !rest.starts_with('"') {
        return None;
    }

    first_quoted_string(rest)
}

pub fn extract_strace_abstract_unix_address(line: &str) -> Option<String> {
    let field = "sun_path=@";
    let start = line.find(field)? + field.len();
    let rest = &line[start..];

    if !rest.starts_with('"') {
        return None;
    }

    let name = first_quoted_string(rest)?;

    Some(format!("@{name}"))
}

pub fn extract_between(line: &str, start: &str, end: &str) -> Option<String> {
    let start_pos = line.find(start)? + start.len();
    let rest = &line[start_pos..];
    let end_pos = rest.find(end)?;
    Some(rest[..end_pos].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_strace_c_escapes() {
        let line = r#"openat(AT_FDCWD, "quote\"name\\tail\040space\012line", O_RDONLY) = 3"#;

        assert_eq!(
            nth_quoted_string(line, 0).as_deref(),
            Some("quote\"name\\tail space\nline")
        );
    }

    #[test]
    fn decodes_strace_octal_utf8() {
        let line = r#"openat(AT_FDCWD, "caf\303\251.txt", O_RDONLY) = 3"#;

        assert_eq!(nth_quoted_string(line, 0).as_deref(), Some("café.txt"));
    }

    #[test]
    fn preserves_unknown_strace_escape() {
        let line = r#"openat(AT_FDCWD, "odd\qname.txt", O_RDONLY) = 3"#;

        assert_eq!(
            nth_quoted_string(line, 0).as_deref(),
            Some(r"odd\qname.txt")
        );
    }

    #[test]
    fn parses_two_rename_paths() {
        let line = r#"rename("old.txt", "new.txt") = 0"#;

        assert_eq!(nth_quoted_string(line, 0).as_deref(), Some("old.txt"));
        assert_eq!(nth_quoted_string(line, 1).as_deref(), Some("new.txt"));
    }

    #[test]
    fn interrupted_syscall_takes_its_result_from_the_resumed_line() {
        let text = "openat(AT_FDCWD</p>, \"x\", O_RDONLY <unfinished ...>\n<... openat resumed>) = 3</p/x>\n";

        let lines = reassemble_trace_lines(text);

        assert_eq!(lines.len(), 1);
        assert!(syscall_succeeded(&lines[0]));
        assert_eq!(syscall_result(&lines[0]), Some("3</p/x>"));
        assert_eq!(nth_quoted_string(&lines[0], 0).as_deref(), Some("x"));
        assert!(flags_have_token(file_open_flags(&lines[0]), "O_RDONLY"));
    }

    #[test]
    fn interrupted_syscall_that_failed_is_not_observable() {
        let text = "openat(AT_FDCWD</p>, \"x\", O_WRONLY|O_CREAT <unfinished ...>\n<... openat resumed>) = -1 EACCES (Permission denied)\n";

        let lines = reassemble_trace_lines(text);

        assert_eq!(lines.len(), 1);
        assert!(!observable_syscall(&lines[0]));
    }

    #[test]
    fn unresumed_syscall_entry_is_dropped() {
        let text = "openat(AT_FDCWD</p>, \"never.txt\", O_RDONLY <unfinished ...>\n";

        assert!(reassemble_trace_lines(text).is_empty());
    }

    #[test]
    fn resumed_line_without_an_entry_is_dropped() {
        let text = "<... openat resumed>) = 3</p/x>\n";

        assert!(reassemble_trace_lines(text).is_empty());
    }

    #[test]
    fn signal_and_exit_notices_are_dropped() {
        let text =
            "--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---\n+++ exited with 0 +++\n";

        assert!(reassemble_trace_lines(text).is_empty());
    }

    #[test]
    fn signal_between_halves_does_not_break_the_splice() {
        let text = "connect(3, {sa_family=AF_UNIX}, 12 <unfinished ...>\n--- SIGWINCH {si_signo=SIGWINCH} ---\n<... connect resumed>) = 0\n";

        let lines = reassemble_trace_lines(text);

        assert_eq!(lines.len(), 1);
        assert!(observable_syscall(&lines[0]));
    }

    #[test]
    fn failed_syscall_is_not_observable() {
        let line =
            r#"openat(AT_FDCWD, "missing", O_RDONLY) = -1 ENOENT (No such file or directory)"#;

        assert!(!observable_syscall(line));
    }

    #[test]
    fn restarted_syscall_is_not_observable() {
        let line = "connect(3, {sa_family=AF_INET}, 16) = ? ERESTARTSYS (To be restarted)";

        assert!(!observable_syscall(line));
    }

    #[test]
    fn quoted_path_containing_failure_text_stays_observable() {
        let line = r#"openat(AT_FDCWD</p>, "report = -1 draft.txt", O_RDONLY) = 3"#;

        assert!(observable_syscall(line));
        assert_eq!(syscall_result(line), Some("3"));
    }

    #[test]
    fn nonblocking_connect_is_observable() {
        let line = "connect(3<TCP:[127.0.0.1:1]>, {sa_family=AF_INET}, 16) = -1 EINPROGRESS (Operation now in progress)";

        assert!(observable_syscall(line));
    }

    #[test]
    fn repeated_nonblocking_connect_is_observable() {
        let line = "connect(3<TCP:[127.0.0.1:1]>, {sa_family=AF_INET}, 16) = -1 EALREADY (Operation already in progress)";

        assert!(observable_syscall(line));
    }

    #[test]
    fn refused_connect_is_not_observable() {
        let line = "connect(3<TCP:[127.0.0.1:1]>, {sa_family=AF_INET}, 16) = -1 ECONNREFUSED (Connection refused)";

        assert!(!observable_syscall(line));
    }

    #[test]
    fn denied_connect_is_not_observable() {
        let line = "connect(3<TCP:[127.0.0.1:1]>, {sa_family=AF_INET}, 16) = -1 EACCES (Permission denied)";

        assert!(!observable_syscall(line));
    }

    #[test]
    fn in_progress_errno_only_applies_to_connect() {
        let line =
            r#"openat(AT_FDCWD, "x", O_RDONLY) = -1 EINPROGRESS (Operation now in progress)"#;

        assert!(!observable_syscall(line));
    }

    #[test]
    fn flag_tokens_are_matched_whole() {
        let openat2 = ", {flags=O_WRONLY|O_CREAT, mode=0644, resolve=0}, 24";

        assert!(flags_have_token(openat2, "O_CREAT"));
        assert!(flags_have_token(openat2, "O_WRONLY"));
        assert!(!flags_have_token(openat2, "O_RDWR"));
        assert!(!flags_have_token(", XO_CREATX", "O_CREAT"));
        assert!(!flags_have_token("", "O_PATH"));
    }

    #[test]
    fn open_flags_exclude_the_result_annotation() {
        let line = r#"openat(AT_FDCWD</p>, "x", O_RDONLY) = 3</p/O_WRONLY>"#;

        assert!(flags_have_token(file_open_flags(line), "O_RDONLY"));
        assert!(!flags_have_token(file_open_flags(line), "O_WRONLY"));
    }

    #[test]
    fn abstract_unix_address_is_prefixed() {
        let line =
            r#"connect(4<UNIX-STREAM:[84234]>, {sa_family=AF_UNIX, sun_path=@"abstract"}, 20) = 0"#;

        assert_eq!(
            extract_strace_abstract_unix_address(line).as_deref(),
            Some("@abstract")
        );
    }

    #[test]
    fn abstract_field_is_not_read_as_a_pathname_socket() {
        let line =
            r#"connect(4<UNIX-STREAM:[84234]>, {sa_family=AF_UNIX, sun_path=@"abstract"}, 20) = 0"#;

        assert_eq!(extract_strace_quoted_field(line, "sun_path="), None);
    }

    #[test]
    fn extracts_ipv6_literal_between_markers() {
        let line = r#"connect(3, {sa_family=AF_INET6, sin6_port=htons(443), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr)}, 28) = 0"#;

        assert_eq!(
            extract_between(line, "sin6_port=htons(", ")").as_deref(),
            Some("443")
        );
        assert_eq!(
            extract_between(line, "inet_pton(AF_INET6, \"", "\"").as_deref(),
            Some("2001:db8::1")
        );
    }
}
