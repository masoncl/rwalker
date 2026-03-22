use std::env;
use std::fs;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/rwalker.bpf.c";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("rwalker.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .build_and_generate(&out)
        .unwrap();

    // The generated bindings may contain duplicate enum discriminants (e.g.
    // BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED and BPF_MAP_TYPE_CGROUP_STORAGE
    // both = 19), which is valid C but not valid Rust. Remove the deprecated
    // alias to fix the build.
    let contents = fs::read_to_string(&out).unwrap();
    let fixed = contents
        .lines()
        .filter(|line| !line.contains("BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&out, fixed).unwrap();

    println!("cargo:rerun-if-changed={SRC}");
}
