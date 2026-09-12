fn main() {
    println!("cargo:rustc-check-cfg=cfg(otadump_zucchini)");
    println!("cargo:rerun-if-changed=src/protos/chromeos_update_engine/update_metadata.proto");
    println!("cargo:rerun-if-changed=native/zucchini/ARTIFACT_BUNDLE_LOCK.json");
    println!("cargo:rerun-if-changed=native/zucchini/ARTIFACT_LOCK.sha256");
    println!("cargo:rerun-if-changed=scripts/fetch-native-artifact.py");

    println!("cargo:rerun-if-env-changed=OTADUMP_NATIVE_DIR");
    println!("cargo:rerun-if-env-changed=OTADUMP_NATIVE_OFFLINE");
    println!("cargo:rerun-if-env-changed=OTADUMP_NATIVE_CACHE");
    println!("cargo:rerun-if-env-changed=OTADUMP_NATIVE_PRESEED");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu")
    {
        let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let bundle_lock = manifest_dir.join("native/zucchini/ARTIFACT_BUNDLE_LOCK.json");
        let checksum_lock = manifest_dir.join("native/zucchini/ARTIFACT_LOCK.sha256");
        let root = if let Some(path) = std::env::var_os("OTADUMP_NATIVE_DIR") {
            std::path::PathBuf::from(path)
        } else {
            let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
            let artifact = out.join("otadump-native/linux-x86_64-gnu");
            let cache = std::env::var_os("OTADUMP_NATIVE_CACHE")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| out.join("cache/otadump-native"));
            let mut command = std::process::Command::new("python3");
            command
                .arg(manifest_dir.join("scripts/fetch-native-artifact.py"))
                .arg("--bundle-lock")
                .arg(&bundle_lock)
                .arg("--checksum-lock")
                .arg(&checksum_lock)
                .arg("--out")
                .arg(&artifact)
                .arg("--cache")
                .arg(cache);
            let status = command.status().expect("unable to run native artifact fetch helper");
            assert!(status.success(), "native artifact fetch helper failed");
            artifact
        };
        let include = root.join("include");
        let archive = root.join("lib/libotadump_zucchini.a");
        assert!(
            include.join("zucchini_ffi.h").is_file(),
            "missing Zucchini artifact header: {}",
            include.display()
        );
        assert!(archive.is_file(), "missing Zucchini artifact archive: {}", archive.display());
        let status = std::process::Command::new("sha256sum")
            .arg("-c")
            .arg(&checksum_lock)
            .current_dir(&root)
            .status()
            .expect("unable to verify Zucchini artifact checksum lock");
        assert!(
            status.success(),
            "Zucchini artifact checksum lock failed: {}",
            checksum_lock.display()
        );
        println!("cargo:rustc-link-search=native={}", root.join("lib").display());
        println!("cargo:rustc-link-lib=static=otadump_zucchini");
        let cxx_archive = std::process::Command::new("g++")
            .args(["-print-file-name=libstdc++.a"])
            .output()
            .expect("unable to locate the C++ runtime")
            .stdout;
        let cxx_archive = std::path::PathBuf::from(String::from_utf8(cxx_archive).unwrap().trim());
        assert!(cxx_archive.is_file(), "static libstdc++ is required: {}", cxx_archive.display());
        println!("cargo:rustc-link-search=native={}", cxx_archive.parent().unwrap().display());
        println!("cargo:rustc-link-lib=static=stdc++");
        println!("cargo:rustc-link-arg=-static-libgcc");
        println!("cargo:rustc-cfg=otadump_zucchini");
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
