//! Process group management and descendant reaping.

use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

/// A managed child process spawned in an isolated process group.
#[derive(Debug)]
pub struct ProcessHandle {
    /// Process identifier of the spawned leader.
    pub pid: u32,
    /// Process group identifier of the isolated group.
    pub pgid: u32,
    child: Child,
}

impl ProcessHandle {
    /// Spawns a child process in a newly created process group (PGID == PID).
    pub fn spawn(mut command: Command) -> std::io::Result<Self> {
        command.process_group(0);
        let child = command.spawn()?;
        let pid = child.id();
        let pgid = pid;
        Ok(Self { pid, pgid, child })
    }

    /// Checks if the child process has already exited without blocking.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Waits synchronously for the child process to exit.
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.wait()
    }

    /// Gracefully terminates the entire process group and reaps the child process.
    pub fn terminate(&mut self, grace_period: Duration) -> std::io::Result<ExitStatus> {
        terminate_and_reap_child(&mut self.child, self.pgid, grace_period)
    }
}

/// Enables subreaper status on Linux so orphaned descendants are reparented
/// to the current supervisor process and can be reaped without leaking.
pub fn enable_child_subreaper() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
    }
}

/// Terminates all processes in the given process group by sending `SIGTERM`,
/// waiting for the grace period, escalating to `SIGKILL` if necessary,
/// and reaping all orphaned descendant processes.
pub fn terminate_process_group(pgid: u32, grace_period: Duration) -> std::io::Result<()> {
    if pgid <= 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to signal invalid process group (pgid <= 1)",
        ));
    }

    enable_child_subreaper();

    let pid_t = pgid as libc::pid_t;

    // Send SIGTERM to the entire process group
    unsafe {
        libc::kill(-pid_t, libc::SIGTERM);
    }

    // Reap any immediate exits
    reap_process_group(pid_t);

    let start = Instant::now();
    let poll_interval = Duration::from_millis(5);

    while start.elapsed() < grace_period {
        reap_process_group(pid_t);
        let res = unsafe { libc::kill(-pid_t, 0) };
        if res == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
        }
        std::thread::sleep(poll_interval);
    }

    // Escalate to SIGKILL for any lingering processes in the group
    unsafe {
        libc::kill(-pid_t, libc::SIGKILL);
    }

    let kill_deadline = Instant::now() + Duration::from_millis(200);
    while Instant::now() < kill_deadline {
        reap_process_group(pid_t);
        let res = unsafe { libc::kill(-pid_t, 0) };
        if res == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
        }
        std::thread::sleep(poll_interval);
    }

    Ok(())
}

fn reap_process_group(pid_t: libc::pid_t) {
    let mut status: libc::c_int = 0;
    loop {
        let ret = unsafe { libc::waitpid(-pid_t, &mut status, libc::WNOHANG) };
        if ret <= 0 {
            break;
        }
    }
}

use std::os::unix::process::ExitStatusExt;

/// Terminates a process group and reaps the child handle so it does not become a zombie.
pub fn terminate_and_reap_child(
    child: &mut Child,
    pgid: u32,
    grace_period: Duration,
) -> std::io::Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }

    let _ = terminate_process_group(pgid, grace_period);

    // If already reaped by waitpid during process group termination, handle ECHILD
    match child.wait() {
        Ok(status) => Ok(status),
        Err(err) if err.raw_os_error() == Some(libc::ECHILD) => {
            // Process was terminated and reaped by the process group reaper
            #[cfg(unix)]
            {
                // Signal 9 (SIGKILL) termination status
                Ok(ExitStatus::from_raw(libc::SIGKILL))
            }
            #[cfg(not(unix))]
            {
                Ok(ExitStatus::default())
            }
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_and_terminate_process_group_kills_descendants() {
        let mut cmd = Command::new("sh");
        // Spawns a background grandchild sleep and waits
        cmd.arg("-c").arg("sleep 60 & sleep 60");

        let mut handle = ProcessHandle::spawn(cmd).expect("spawn child");
        assert_eq!(handle.pid, handle.pgid);

        std::thread::sleep(Duration::from_millis(50));

        let status = handle
            .terminate(Duration::from_millis(50))
            .expect("terminate child");
        assert!(!status.success());

        // Verify that the process group no longer exists
        let res = unsafe { libc::kill(-(handle.pgid as libc::pid_t), 0) };
        assert_eq!(res, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    fn clean_process_exit_without_termination() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("exit 0");

        let mut handle = ProcessHandle::spawn(cmd).expect("spawn child");
        let status = handle.wait().expect("wait child");
        assert!(status.success());
    }
}
