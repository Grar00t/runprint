use super::*;

fn context() -> NormalizeContext {
    NormalizeContext::new(PathBuf::from("/project"), None, PathBuf::from("/tmp"))
}

#[test]
fn resolves_relative_path_from_cwd() {
    assert_eq!(
        resolve_path(Path::new("/project/subdir"), "output.txt"),
        PathBuf::from("/project/subdir/output.txt")
    );
}

#[test]
fn resolves_openat_fdcwd() {
    let line = r#"openat(AT_FDCWD, "output.txt", O_WRONLY|O_CREAT, 0666) = 3"#;

    assert_eq!(
        resolve_openat(line, Path::new("/project/subdir"), "output.txt").unwrap(),
        PathBuf::from("/project/subdir/output.txt")
    );
}

#[test]
fn resolves_openat_directory_fd() {
    let line = r#"openat(3</project/assets>, "config.json", O_RDONLY) = 4"#;

    assert_eq!(
        resolve_openat(line, Path::new("/ignored"), "config.json").unwrap(),
        PathBuf::from("/project/assets/config.json")
    );
}

#[test]
fn parses_linkat_symlink_follow_semantics() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"linkat(AT_FDCWD</project>, "source-link", AT_FDCWD</project>, "out", AT_SYMLINK_FOLLOW) = 0"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert!(lock.behaviors.contains(&Behavior::HardlinkCreate {
        from: "$PROJECT/source-link".into(),
        to: "$PROJECT/out".into(),
        follow_symlink: true,
        empty_path: false,
    }));
}

#[test]
fn parses_linkat_empty_path_semantics() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"linkat(3</project/source.txt>, "", AT_FDCWD</project>, "out.txt", AT_EMPTY_PATH) = 0"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert!(lock.behaviors.contains(&Behavior::HardlinkCreate {
        from: "$PROJECT/source.txt".into(),
        to: "$PROJECT/out.txt".into(),
        follow_symlink: false,
        empty_path: true,
    }));
}

#[test]
fn linkat_path_named_flag_does_not_impersonate_flag() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"linkat(AT_FDCWD</project>, "AT_SYMLINK_FOLLOW", AT_FDCWD</project>, "out", 0) = 0"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert!(lock.behaviors.contains(&Behavior::HardlinkCreate {
        from: "$PROJECT/AT_SYMLINK_FOLLOW".into(),
        to: "$PROJECT/out".into(),
        follow_symlink: false,
        empty_path: false,
    }));
}

#[test]
fn parses_abstract_unix_socket_address() {
    let behavior = parse_connect(
        r#"connect(4<UNIX-STREAM:[84234]>, {sa_family=AF_UNIX, sun_path=@"runprint-abstract"}, 20) = 0"#,
    )
    .unwrap();

    assert_eq!(
        behavior,
        Behavior::UnixAbstractConnect {
            address: "@runprint-abstract".to_string(),
        }
    );
}

#[test]
fn decodes_unix_socket_path_escapes() {
    let behavior = parse_connect(
        r#"connect(4<UNIX-STREAM:[71608]>, {sa_family=AF_UNIX, sun_path="sock\\name"}, 12) = 0"#,
    )
    .unwrap();

    assert_eq!(
        behavior,
        Behavior::UnixConnect {
            path: "sock\\name".to_string(),
        }
    );
}

#[test]
fn decodes_unix_socket_escaped_quote() {
    let behavior = parse_connect(
        r#"connect(4<UNIX-STREAM:[71608]>, {sa_family=AF_UNIX, sun_path="sock\"name"}, 12) = 0"#,
    )
    .unwrap();

    assert_eq!(
        behavior,
        Behavior::UnixConnect {
            path: "sock\"name".to_string(),
        }
    );
}

#[test]
fn parses_renameat2_exchange() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"renameat2(AT_FDCWD</project>, "b.txt", AT_FDCWD</project>, "a.txt", RENAME_EXCHANGE) = 0"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert_eq!(lock.behaviors.len(), 1);

    assert!(lock.behaviors.contains(&Behavior::RenameExchange {
        left: "$PROJECT/a.txt".to_string(),
        right: "$PROJECT/b.txt".to_string(),
    }));
}

#[test]
fn renameat2_path_named_exchange_is_not_exchange_without_flag() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"renameat2(AT_FDCWD</project>, "RENAME_EXCHANGE", AT_FDCWD</project>, "b.txt", 0) = 0"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert_eq!(lock.behaviors.len(), 1);

    assert!(lock.behaviors.contains(&Behavior::FileRename {
        from: "$PROJECT/RENAME_EXCHANGE".to_string(),
        to: "$PROJECT/b.txt".to_string(),
    }));

    assert!(!lock
        .behaviors
        .iter()
        .any(|behavior| matches!(behavior, Behavior::RenameExchange { .. })));
}

#[test]
fn parses_rdwr_as_read_and_write() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"openat(AT_FDCWD</project>, "data.txt", O_RDWR) = 3</project/data.txt>"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert_eq!(lock.behaviors.len(), 2);
    assert!(lock.behaviors.contains(&Behavior::FileRead {
        path: "$PROJECT/data.txt".to_string(),
    }));
    assert!(lock.behaviors.contains(&Behavior::FileWrite {
        path: "$PROJECT/data.txt".to_string(),
    }));
}

#[test]
fn creat_is_write_only() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"creat("created.txt", 0644) = 3</project/created.txt>"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert_eq!(lock.behaviors.len(), 1);
    assert!(lock.behaviors.contains(&Behavior::FileWrite {
        path: "$PROJECT/created.txt".to_string(),
    }));
}

#[test]
fn path_named_rdwr_does_not_impersonate_access_flag() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"openat(AT_FDCWD</project>, "O_RDWR", O_RDONLY) = 3</project/O_RDWR>"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert_eq!(lock.behaviors.len(), 1);
    assert!(lock.behaviors.contains(&Behavior::FileRead {
        path: "$PROJECT/O_RDWR".to_string(),
    }));
    assert!(!lock.behaviors.contains(&Behavior::FileWrite {
        path: "$PROJECT/O_RDWR".to_string(),
    }));
}

#[test]
fn read_only_create_records_read_and_write() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"openat(AT_FDCWD</project>, "cache.db", O_RDONLY|O_CREAT, 0644) = 3</project/cache.db>"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert_eq!(lock.behaviors.len(), 2);
    assert!(lock.behaviors.contains(&Behavior::FileRead {
        path: "$PROJECT/cache.db".to_string(),
    }));
    assert!(lock.behaviors.contains(&Behavior::FileWrite {
        path: "$PROJECT/cache.db".to_string(),
    }));
}

#[test]
fn read_only_truncate_records_read_and_write() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"openat(AT_FDCWD</project>, "data.bin", O_RDONLY|O_TRUNC) = 3</project/data.bin>"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert_eq!(lock.behaviors.len(), 2);
    assert!(lock.behaviors.contains(&Behavior::FileRead {
        path: "$PROJECT/data.bin".to_string(),
    }));
    assert!(lock.behaviors.contains(&Behavior::FileWrite {
        path: "$PROJECT/data.bin".to_string(),
    }));
}

#[test]
fn write_only_append_is_not_recorded_as_read() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"openat(AT_FDCWD</project>, "out.log", O_WRONLY|O_APPEND) = 3</project/out.log>"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert_eq!(lock.behaviors.len(), 1);
    assert!(lock.behaviors.contains(&Behavior::FileWrite {
        path: "$PROJECT/out.log".to_string(),
    }));
}

#[test]
fn resolution_only_open_records_nothing() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"openat(AT_FDCWD</project>, "sub", O_RDONLY|O_PATH|O_DIRECTORY) = 3</project/sub>"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert!(lock.behaviors.is_empty());
}

#[test]
fn parses_openat2_fdcwd_read() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"openat2(AT_FDCWD</project>, "read.txt", {flags=O_RDONLY, resolve=0}, 24) = 3</project/read.txt>"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert!(lock.behaviors.contains(&Behavior::FileRead {
        path: "$PROJECT/read.txt".to_string(),
    }));
}

#[test]
fn parses_openat2_directory_fd_write() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"openat2(3</project/sub>, "write.txt", {flags=O_WRONLY|O_CREAT|O_TRUNC, mode=0644, resolve=0}, 24) = 4</project/sub/write.txt>"#,
        Path::new("/ignored"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert!(lock.behaviors.contains(&Behavior::FileWrite {
        path: "$PROJECT/sub/write.txt".to_string(),
    }));
}

#[test]
fn parses_execveat_directory_fd() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"execveat(3</opt/app>, "tool", ["tool"], 0x0, 0) = 0"#,
        Path::new("/ignored"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert!(lock.behaviors.contains(&Behavior::Exec {
        path: "/opt/app/tool".to_string(),
    }));
}

#[test]
fn parses_execveat_empty_path_from_fd() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"execveat(3</project/target>, "", ["target"], 0x0, AT_EMPTY_PATH) = 0"#,
        Path::new("/ignored"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert!(lock.behaviors.contains(&Behavior::Exec {
        path: "$PROJECT/target".to_string(),
    }));
}

#[test]
fn parses_execveat_fdcwd() {
    let context = context();

    let mut lock = BehaviorLock::new();

    parse_behavior_line(
        r#"execveat(AT_FDCWD, "bin/tool", ["tool"], 0x0, 0) = 0"#,
        Path::new("/project"),
        &mut lock,
        true,
        &context,
    )
    .unwrap();

    assert!(lock.behaviors.contains(&Behavior::Exec {
        path: "$PROJECT/bin/tool".to_string(),
    }));
}

#[test]
fn nonblocking_connect_destination_is_recorded() {
    let context = context();

    let mut lock = BehaviorLock::new();

    let line = r#"connect(3<TCP:[127.0.0.1:39112]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16) = -1 EINPROGRESS (Operation now in progress)"#;

    assert!(observable_syscall(line));

    parse_behavior_line(line, Path::new("/project"), &mut lock, true, &context).unwrap();

    assert!(lock.behaviors.contains(&Behavior::NetworkConnect {
        address: "203.0.113.10:443".to_string(),
    }));
}

/// An interrupted syscall must only be recorded once its resumed line proves
/// the operation actually happened.
#[test]
fn interrupted_open_that_failed_records_nothing() {
    let context = context();

    let mut lock = BehaviorLock::new();

    let text = "openat(AT_FDCWD</project>, \"x\", O_WRONLY|O_CREAT <unfinished ...>\n<... openat resumed>) = -1 EACCES (Permission denied)\n";

    for line in reassemble_trace_lines(text) {
        if !observable_syscall(&line) {
            continue;
        }

        parse_behavior_line(&line, Path::new("/project"), &mut lock, true, &context).unwrap();
    }

    assert!(lock.behaviors.is_empty());
}

#[test]
fn interrupted_open_that_succeeded_is_recorded() {
    let context = context();

    let mut lock = BehaviorLock::new();

    let text = "openat(AT_FDCWD</project>, \"late.txt\", O_RDONLY <unfinished ...>\n<... openat resumed>) = 3</project/late.txt>\n";

    for line in reassemble_trace_lines(text) {
        if !observable_syscall(&line) {
            continue;
        }

        parse_behavior_line(&line, Path::new("/project"), &mut lock, true, &context).unwrap();
    }

    assert!(lock.behaviors.contains(&Behavior::FileRead {
        path: "$PROJECT/late.txt".to_string(),
    }));
}
