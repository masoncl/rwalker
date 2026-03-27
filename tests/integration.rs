use std::process::Command;

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Build the release binary path relative to the project root.
fn rwalker_bin() -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("release");
    path.push("rwalker");
    path
}

/// Run rwalker with the given args, return (stdout, stderr).
/// Panics if the process fails to start.
fn run_rwalker(args: &[&str]) -> (String, String) {
    let output = Command::new(rwalker_bin())
        .args(args)
        .output()
        .expect("failed to execute rwalker");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert!(
        output.status.success(),
        "rwalker exited with {}\nstderr: {}",
        output.status,
        stderr
    );

    (stdout, stderr)
}

#[test]
#[ignore]
fn test_default_dstate_walk() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    let (stdout, _stderr) = run_rwalker(&[]);

    // Default mode should produce some output — at minimum the
    // aggregation lines or task lines.  On a busy system there will
    // be running/D-state tasks.  We just verify it doesn't crash
    // and produces parseable output.
    // Any task line starts with "comm "
    // Any aggregation line ends with hit counts
    assert!(
        stdout.contains("comm ") || stdout.contains(" hits ") || stdout.is_empty(),
        "unexpected output format:\n{}",
        &stdout[..stdout.len().min(500)]
    );
}

#[test]
#[ignore]
fn test_profile_oncpu() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    let (stdout, _stderr) = run_rwalker(&["-p", "1"]);

    assert!(
        stdout.contains(">>>") && stdout.contains('%'),
        "expected profiling output with >>> percentage lines:\n{}",
        &stdout[..stdout.len().min(500)]
    );
}

#[test]
#[ignore]
fn test_profile_oncpu_user() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    let (stdout, _stderr) = run_rwalker(&["-p", "1", "-u"]);

    assert!(
        stdout.contains(">>>") && stdout.contains('%'),
        "expected profiling output:\n{}",
        &stdout[..stdout.len().min(500)]
    );
}

#[test]
#[ignore]
fn test_profile_oncpu_dwarf() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    let (stdout, stderr) = run_rwalker(&["-p", "1", "--dwarf"]);

    assert!(
        stderr.contains("dwarf: reducing sampling frequency"),
        "expected dwarf frequency message on stderr:\n{}",
        stderr
    );
    assert!(
        stdout.contains(">>>") && stdout.contains('%'),
        "expected profiling output:\n{}",
        &stdout[..stdout.len().min(500)]
    );
}

#[test]
#[ignore]
fn test_profile_oncpu_quick() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    let (stdout, _stderr) = run_rwalker(&["-p", "1", "-q"]);

    assert!(
        stdout.contains(">>>") && stdout.contains('%'),
        "expected profiling output:\n{}",
        &stdout[..stdout.len().min(500)]
    );
}

#[test]
#[ignore]
fn test_profile_oncpu_sw_perf() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    let (stdout, _stderr) = run_rwalker(&["-p", "1", "--sw-perf"]);

    assert!(
        stdout.contains(">>>") && stdout.contains('%'),
        "expected profiling output:\n{}",
        &stdout[..stdout.len().min(500)]
    );
}

#[test]
#[ignore]
fn test_offcpu() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    let (stdout, _stderr) = run_rwalker(&["--offcpu", "1"]);

    assert!(
        stdout.contains(">>>") && stdout.contains('%'),
        "expected offcpu profiling output:\n{}",
        &stdout[..stdout.len().min(500)]
    );
    // Off-CPU output shows time in ms
    assert!(
        stdout.contains("ms)"),
        "expected off-cpu timing in ms:\n{}",
        &stdout[..stdout.len().min(500)]
    );
}

#[test]
#[ignore]
fn test_offcpu_user() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    let (stdout, _stderr) = run_rwalker(&["--offcpu", "1", "-u"]);

    assert!(
        stdout.contains(">>>") && stdout.contains("ms)"),
        "expected offcpu profiling output with timing:\n{}",
        &stdout[..stdout.len().min(500)]
    );
}

#[test]
#[ignore]
fn test_offcpu_dwarf() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    let (stdout, stderr) = run_rwalker(&["--offcpu", "1", "--dwarf"]);

    assert!(
        stderr.contains("dwarf: reducing sampling frequency"),
        "expected dwarf frequency message on stderr:\n{}",
        stderr
    );
    // May have output or may have heavy drops — just verify no crash
    // and that any output present is well-formed
    if !stdout.is_empty() {
        assert!(
            stdout.contains(">>>"),
            "non-empty output should contain >>> lines:\n{}",
            &stdout[..stdout.len().min(500)]
        );
    }
}

#[test]
#[ignore]
fn test_trace_sched_switch() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    let (stdout, _stderr) = run_rwalker(&["--trace", "sched_switch:1"]);

    assert!(
        stdout.contains(">>>") && stdout.contains('%'),
        "expected tracepoint profiling output:\n{}",
        &stdout[..stdout.len().min(500)]
    );
    // sched_switch tracepoint should show __traceiter_sched_switch in stacks
    assert!(
        stdout.contains("sched_switch") || stdout.contains("schedule"),
        "expected sched_switch-related symbols in output:\n{}",
        &stdout[..stdout.len().min(500)]
    );
}

#[test]
#[ignore]
fn test_trace_dwarf() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    let (stdout, stderr) = run_rwalker(&["--trace", "sched_switch:1", "--dwarf"]);

    assert!(
        stderr.contains("dwarf: reducing sampling frequency"),
        "expected dwarf frequency message on stderr:\n{}",
        stderr
    );
    if !stdout.is_empty() {
        assert!(
            stdout.contains(">>>"),
            "non-empty output should contain >>> lines:\n{}",
            &stdout[..stdout.len().min(500)]
        );
    }
}

#[test]
#[ignore]
fn test_kfunc() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    let (stdout, _stderr) = run_rwalker(&["--kfunc", "__x64_sys_read:1"]);

    // kfunc may or may not produce output depending on system activity
    if !stdout.is_empty() {
        assert!(
            stdout.contains(">>>"),
            "non-empty output should contain >>> lines:\n{}",
            &stdout[..stdout.len().min(500)]
        );
    }
}
