fn main() {
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
