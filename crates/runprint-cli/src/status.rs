use std::process::ExitStatus;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

pub fn shell_exit_code(status: &ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    #[cfg(unix)]
    if let Some(signal) = status.signal() {
        return 128 + signal;
    }

    128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;

    #[cfg(unix)]
    #[test]
    fn preserves_normal_exit_code() {
        let status = ExitStatus::from_raw(7 << 8);

        assert_eq!(shell_exit_code(&status), 7);
    }

    #[cfg(unix)]
    #[test]
    fn maps_signal_to_shell_exit_code() {
        let status = ExitStatus::from_raw(15);

        assert_eq!(shell_exit_code(&status), 143);
    }
}
