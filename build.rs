use std::fs;
use std::path::{Path, PathBuf};

// LZ4 block codec only. xxhash.c serves lz4frame.c (not built) and is
// referenced by neither lz4.c nor lz4hc.c.
const LZ4_SOURCES: &[&str] =
    &["native/lz4/src/lz4_ffi.c", "native/lz4/vendor/lib/lz4.c", "native/lz4/vendor/lib/lz4hc.c"];

fn main() {
    println!("cargo:rustc-check-cfg=cfg(otadump_lz4)");
    println!("cargo:rustc-check-cfg=cfg(otadump_zucchini)");
    println!("cargo:rerun-if-changed=src/protos/chromeos_update_engine/update_metadata.proto");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu")
    {
        build_lz4();
        println!("cargo:rustc-cfg=otadump_lz4");
    }

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("unable to find vendored protoc");
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    config
        .compile_protos(
            &["src/protos/chromeos_update_engine/update_metadata.proto"],
            &[] as &[&str],
        )
        .expect("error compiling protobuf files");
}

fn build_lz4() {
    let root = Path::new("native/lz4");
    track_directory(root);

    cc::Build::new()
        .std("c99")
        .opt_level(3)
        .define("NDEBUG", None)
        .warnings(true)
        .warnings_into_errors(true)
        .flag("-fvisibility=hidden")
        // C code never throws: drop unwind tables.
        .flag("-fno-asynchronous-unwind-tables")
        .flag("-fno-unwind-tables")
        .include(root.join("src"))
        .include(root.join("vendor/lib"))
        .files(LZ4_SOURCES)
        .compile("otadump_lz4");
}

fn track_directory(root: &Path) {
    let mut tracked = Vec::new();
    collect_files(root, &mut tracked);
    tracked.sort();
    for path in tracked {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn collect_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("unable to read native source entry: {error}"));
    for entry in entries {
        let path = entry.expect("unable to read native source entry").path();
        if path.is_dir() {
            collect_files(&path, files);
        } else {
            files.push(path);
        }
    }
}
