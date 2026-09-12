use std::fs;
use std::path::{Path, PathBuf};

// Upstream Zucchini apply-only closure.
const ZUCCHINI_SOURCES: &[&str] = &[
    "native/zucchini/src/zucchini_ffi.cc",
    "native/zucchini/vendor/zucchini/abs32_utils.cc",
    "native/zucchini/vendor/zucchini/address_translator.cc",
    "native/zucchini/vendor/zucchini/arm_utils.cc",
    "native/zucchini/vendor/zucchini/buffer_source.cc",
    "native/zucchini/vendor/zucchini/crc32.cc",
    "native/zucchini/vendor/zucchini/disassembler.cc",
    "native/zucchini/vendor/zucchini/disassembler_dex.cc",
    "native/zucchini/vendor/zucchini/disassembler_elf.cc",
    "native/zucchini/vendor/zucchini/disassembler_no_op.cc",
    "native/zucchini/vendor/zucchini/element_detection.cc",
    "native/zucchini/vendor/zucchini/equivalence_map.cc",
    "native/zucchini/vendor/zucchini/patch_reader.cc",
    "native/zucchini/vendor/zucchini/rel32_finder.cc",
    "native/zucchini/vendor/zucchini/rel32_utils.cc",
    "native/zucchini/vendor/zucchini/reloc_elf.cc",
    "native/zucchini/vendor/zucchini/target_pool.cc",
    "native/zucchini/vendor/zucchini/zucchini_apply.cc",
    // Minimal libchrome runtime: the only upstream TUs still referenced after
    // the dead debug/metrics/activity-tracking closure was removed, plus a shim
    // replacing logging.cc + base/debug/*.
    "native/zucchini/vendor/libchrome/base/callback_internal.cc",
    "native/zucchini/vendor/libchrome/base/strings/stringprintf.cc",
    "native/zucchini/src/libchrome_shim.cc",
];

// LZ4 block codec only. xxhash.c serves lz4frame.c (not built) and is
// referenced by neither lz4.c nor lz4hc.c.
const LZ4_SOURCES: &[&str] = &[
    "native/lz4/src/lz4_ffi.c",
    "native/lz4/vendor/lib/lz4.c",
    "native/lz4/vendor/lib/lz4hc.c",
];

fn main() {
    println!("cargo:rustc-check-cfg=cfg(otadump_lz4)");
    println!("cargo:rustc-check-cfg=cfg(otadump_zucchini)");
    println!("cargo:rustc-check-cfg=cfg(otadump_native_zucchini)");
    println!("cargo:rerun-if-changed=src/protos/chromeos_update_engine/update_metadata.proto");
    println!("cargo:rerun-if-env-changed=OTADUMP_NATIVE_ZUCCHINI");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu")
    {
        build_lz4();
        println!("cargo:rustc-cfg=otadump_lz4");
    }

    // Zucchini is implemented in pure Rust (`src/zucchini_pure`). The vendored
    // C++/libchrome implementation is retained only for differential testing,
    // enabled explicitly with `OTADUMP_NATIVE_ZUCCHINI=1` (exact value only).
    println!("cargo:rustc-cfg=otadump_zucchini");
    if std::env::var("OTADUMP_NATIVE_ZUCCHINI").as_deref() == Ok("1") {
        build_zucchini();
        println!("cargo:rustc-cfg=otadump_native_zucchini");
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

fn build_zucchini() {
    let root = Path::new("native/zucchini");
    track_directory(root);

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .cpp_link_stdlib(None)
        .std("c++17")
        .opt_level(2)
        .define("NDEBUG", None)
        .define("OFFICIAL_BUILD", None)
        .define("__ANDROID_HOST__", None)
        .define("DONT_EMBED_BUILD_METADATA", None)
        .flag("-ffunction-sections")
        .flag("-fdata-sections")
        .flag("-fno-exceptions")
        .flag("-fno-rtti")
        .flag("-fvisibility=hidden")
        .flag("-fvisibility-inlines-hidden")
        .flag("-Wno-deprecated-declarations")
        .flag("-Wno-unused-parameter")
        .include(root.join("include"))
        .include(root.join("src"))
        .include(root.join("vendor/zucchini/aosp/include"))
        .include(root.join("vendor/zucchini/aosp/include/components"))
        .include(root.join("vendor/libchrome"))
        .files(ZUCCHINI_SOURCES);

    let compiler = build.get_compiler();
    build.compile("otadump_zucchini");
    add_static_runtime(&compiler, "libstdc++.a", "stdc++");
    add_static_runtime(&compiler, "libgcc.a", "gcc");
    println!("cargo:rustc-link-arg=-static-libgcc");
}

fn track_directory(root: &Path) {
    let mut tracked = Vec::new();
    collect_files(root, &mut tracked);
    tracked.sort();
    for path in tracked {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn add_static_runtime(compiler: &cc::Tool, archive: &str, library: &str) {
    let output = compiler
        .to_command()
        .arg(format!("-print-file-name={archive}"))
        .output()
        .unwrap_or_else(|error| panic!("unable to locate {archive}: {error}"));
    assert!(output.status.success(), "unable to locate {archive}");
    let path =
        PathBuf::from(String::from_utf8(output.stdout).expect("compiler path is not UTF-8").trim());
    let directory = path
        .parent()
        .filter(|_| path.is_absolute() && path.is_file())
        .unwrap_or_else(|| panic!("compiler did not provide a usable {archive} path"));
    println!("cargo:rustc-link-search=native={}", directory.display());
    println!("cargo:rustc-link-lib=static={library}");
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
