use std::fs;
use std::path::Path;

use otadump::ExtractOptions;
use prost::Message;
use ring::digest;
use tempfile::TempDir;

#[derive(Clone, PartialEq, Message)]
struct Extent {
    #[prost(uint64, optional, tag = "1")]
    start_block: Option<u64>,
    #[prost(uint64, optional, tag = "2")]
    num_blocks: Option<u64>,
}

#[derive(Clone, PartialEq, Message)]
struct PartitionInfo {
    #[prost(uint64, optional, tag = "1")]
    size: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "2")]
    hash: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct InstallOperation {
    #[prost(int32, tag = "1")]
    operation_type: i32,
    #[prost(uint64, optional, tag = "2")]
    data_offset: Option<u64>,
    #[prost(uint64, optional, tag = "3")]
    data_length: Option<u64>,
    #[prost(message, repeated, tag = "4")]
    src_extents: Vec<Extent>,
    #[prost(uint64, optional, tag = "5")]
    src_length: Option<u64>,
    #[prost(message, repeated, tag = "6")]
    dst_extents: Vec<Extent>,
    #[prost(uint64, optional, tag = "7")]
    dst_length: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "8")]
    data_sha256_hash: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "9")]
    src_sha256_hash: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct PartitionUpdate {
    #[prost(string, tag = "1")]
    partition_name: String,
    #[prost(message, optional, tag = "6")]
    old_partition_info: Option<PartitionInfo>,
    #[prost(message, optional, tag = "7")]
    new_partition_info: Option<PartitionInfo>,
    #[prost(message, repeated, tag = "8")]
    operations: Vec<InstallOperation>,
}

#[derive(Clone, PartialEq, Message)]
struct DeltaArchiveManifest {
    #[prost(uint32, optional, tag = "3")]
    block_size: Option<u32>,
    #[prost(uint32, optional, tag = "12")]
    minor_version: Option<u32>,
    #[prost(message, repeated, tag = "13")]
    partitions: Vec<PartitionUpdate>,
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, bytes).as_ref().to_vec()
}

fn extent(start_block: u64, num_blocks: u64) -> Extent {
    Extent { start_block: Some(start_block), num_blocks: Some(num_blocks) }
}

fn write_payload(path: &Path, manifest: DeltaArchiveManifest, data: &[u8]) {
    let manifest = manifest.encode_to_vec();
    let mut payload = Vec::with_capacity(24 + manifest.len() + data.len());
    payload.extend_from_slice(b"CrAU");
    payload.extend_from_slice(&2u64.to_be_bytes());
    payload.extend_from_slice(&(manifest.len() as u64).to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&manifest);
    payload.extend_from_slice(data);
    fs::write(path, payload).unwrap();
}

fn partition_info(bytes: &[u8]) -> PartitionInfo {
    PartitionInfo { size: Some(bytes.len() as u64), hash: Some(sha256(bytes)) }
}

#[test]
fn source_copy_reconstructs_noncontiguous_extents_without_modifying_source() {
    let temporary = TempDir::new().unwrap();
    let source_dir = temporary.path().join("source");
    let output_dir = temporary.path().join("output");
    fs::create_dir(&source_dir).unwrap();
    let source = b"AAAABBBBCCCCDDDD";
    fs::write(source_dir.join("system.img"), source).unwrap();
    let expected = b"AAAACCCC";
    let operation = InstallOperation {
        operation_type: 4,
        src_extents: vec![extent(2, 1), extent(0, 1)],
        src_length: Some(8),
        dst_extents: vec![extent(1, 1), extent(0, 1)],
        dst_length: Some(8),
        src_sha256_hash: Some(sha256(b"CCCCAAAA")),
        ..Default::default()
    };
    let manifest = DeltaArchiveManifest {
        block_size: Some(4),
        minor_version: Some(2),
        partitions: vec![PartitionUpdate {
            partition_name: "system".into(),
            old_partition_info: Some(partition_info(source)),
            new_partition_info: Some(partition_info(expected)),
            operations: vec![operation],
        }],
    };
    let payload = temporary.path().join("payload.bin");
    write_payload(&payload, manifest, &[]);

    ExtractOptions::new()
        .source_dir(&source_dir)
        .num_threads(2)
        .extract(&payload, &output_dir)
        .unwrap();

    assert_eq!(fs::read(output_dir.join("system.img")).unwrap(), expected);
    assert_eq!(fs::read(source_dir.join("system.img")).unwrap(), source);
}

#[test]
fn source_validation_rejects_wrong_base_before_creating_output() {
    let temporary = TempDir::new().unwrap();
    let source_dir = temporary.path().join("source");
    let output_dir = temporary.path().join("output");
    fs::create_dir(&source_dir).unwrap();
    fs::write(source_dir.join("boot.img"), b"bad!").unwrap();
    let operation = InstallOperation {
        operation_type: 4,
        src_extents: vec![extent(0, 1)],
        dst_extents: vec![extent(0, 1)],
        ..Default::default()
    };
    let manifest = DeltaArchiveManifest {
        block_size: Some(4),
        minor_version: Some(2),
        partitions: vec![PartitionUpdate {
            partition_name: "boot".into(),
            old_partition_info: Some(partition_info(b"good")),
            new_partition_info: Some(partition_info(b"good")),
            operations: vec![operation],
        }],
    };
    let payload = temporary.path().join("payload.bin");
    write_payload(&payload, manifest, &[]);

    let error = ExtractOptions::new()
        .source_dir(&source_dir)
        .extract(&payload, &output_dir)
        .unwrap_err()
        .to_string();

    assert!(error.contains("Source partition hash mismatch"));
    assert!(!output_dir.join("boot.img").exists());
}

#[test]
fn delta_operation_without_source_directory_fails_clearly() {
    let temporary = TempDir::new().unwrap();
    let output_dir = temporary.path().join("output");
    let manifest = DeltaArchiveManifest {
        block_size: Some(4),
        minor_version: Some(2),
        partitions: vec![PartitionUpdate {
            partition_name: "boot".into(),
            old_partition_info: Some(partition_info(b"base")),
            new_partition_info: Some(partition_info(b"base")),
            operations: vec![InstallOperation {
                operation_type: 4,
                src_extents: vec![extent(0, 1)],
                dst_extents: vec![extent(0, 1)],
                ..Default::default()
            }],
        }],
    };
    let payload = temporary.path().join("payload.bin");
    write_payload(&payload, manifest, &[]);

    let error = ExtractOptions::new().extract(&payload, &output_dir).unwrap_err().to_string();

    assert!(error.contains("require a source directory"));
    assert!(!output_dir.join("boot.img").exists());
}

#[test]
fn malformed_partition_layouts_fail_without_escaping_or_leaving_partial_images() {
    for (name, operations, expected_error) in [
        (
            "../escape",
            vec![InstallOperation {
                operation_type: 0,
                data_offset: Some(0),
                data_length: Some(4),
                dst_extents: vec![extent(0, 1)],
                ..Default::default()
            }],
            "Unsafe partition name",
        ),
        (
            "system",
            vec![
                InstallOperation {
                    operation_type: 0,
                    data_offset: Some(0),
                    data_length: Some(4),
                    dst_extents: vec![extent(0, 1)],
                    ..Default::default()
                },
                InstallOperation {
                    operation_type: 0,
                    data_offset: Some(4),
                    data_length: Some(4),
                    dst_extents: vec![extent(0, 1)],
                    ..Default::default()
                },
            ],
            "Destination extents overlap",
        ),
    ] {
        let temporary = TempDir::new().unwrap();
        let output_dir = temporary.path().join("output");
        let target = b"data";
        let manifest = DeltaArchiveManifest {
            block_size: Some(4),
            minor_version: Some(0),
            partitions: vec![PartitionUpdate {
                partition_name: name.into(),
                old_partition_info: None,
                new_partition_info: Some(partition_info(target)),
                operations,
            }],
        };
        let payload = temporary.path().join("payload.bin");
        write_payload(&payload, manifest, b"datadata");

        let error = ExtractOptions::new().extract(&payload, &output_dir).unwrap_err().to_string();

        assert!(error.contains(expected_error), "unexpected error: {error}");
        assert!(!temporary.path().join("escape.img").exists());
        assert!(!output_dir.join("system.img").exists());
    }
}

#[test]
fn full_replace_payload_remains_compatible() {
    let temporary = TempDir::new().unwrap();
    let output_dir = temporary.path().join("output");
    let expected = b"full payload data";
    let operation = InstallOperation {
        operation_type: 0,
        data_offset: Some(0),
        data_length: Some(expected.len() as u64),
        dst_extents: vec![extent(0, 2)],
        data_sha256_hash: Some(sha256(expected)),
        ..Default::default()
    };
    let mut padded = expected.to_vec();
    padded.resize(32, 0);
    let manifest = DeltaArchiveManifest {
        block_size: Some(16),
        minor_version: Some(0),
        partitions: vec![PartitionUpdate {
            partition_name: "vendor".into(),
            old_partition_info: None,
            new_partition_info: Some(partition_info(&padded)),
            operations: vec![operation],
        }],
    };
    let payload = temporary.path().join("payload.bin");
    write_payload(&payload, manifest, expected);

    ExtractOptions::new().extract(&payload, &output_dir).unwrap();

    assert_eq!(fs::read(output_dir.join("vendor.img")).unwrap(), padded);
}

#[test]
fn verified_partitions_are_promoted_after_all_succeed() {
    let temporary = TempDir::new().unwrap();
    let output_dir = temporary.path().join("output");
    let boot = b"boot";
    let vendor = b"vend";
    let manifest = DeltaArchiveManifest {
        block_size: Some(4),
        minor_version: Some(0),
        partitions: vec![
            PartitionUpdate {
                partition_name: "boot".into(),
                old_partition_info: None,
                new_partition_info: Some(partition_info(boot)),
                operations: vec![InstallOperation {
                    operation_type: 0,
                    data_offset: Some(0),
                    data_length: Some(4),
                    dst_extents: vec![extent(0, 1)],
                    ..Default::default()
                }],
            },
            PartitionUpdate {
                partition_name: "vendor".into(),
                old_partition_info: None,
                new_partition_info: Some(partition_info(vendor)),
                operations: vec![InstallOperation {
                    operation_type: 0,
                    data_offset: Some(4),
                    data_length: Some(4),
                    dst_extents: vec![extent(0, 1)],
                    ..Default::default()
                }],
            },
        ],
    };
    let payload = temporary.path().join("payload.bin");
    write_payload(&payload, manifest, b"bootvend");

    ExtractOptions::new().extract(&payload, &output_dir).unwrap();

    assert_eq!(fs::read(output_dir.join("boot.img")).unwrap(), boot);
    assert_eq!(fs::read(output_dir.join("vendor.img")).unwrap(), vendor);
}

#[test]
fn no_clobber_rejects_existing_destination_without_modifying_source() {
    let temporary = TempDir::new().unwrap();
    let source_dir = temporary.path().join("source");
    let output_dir = temporary.path().join("output");
    fs::create_dir(&source_dir).unwrap();
    fs::create_dir(&output_dir).unwrap();
    let source = b"base";
    let existing = b"keep";
    fs::write(source_dir.join("system.img"), source).unwrap();
    fs::write(output_dir.join("system.img"), existing).unwrap();
    let manifest = DeltaArchiveManifest {
        block_size: Some(4),
        minor_version: Some(2),
        partitions: vec![PartitionUpdate {
            partition_name: "system".into(),
            old_partition_info: Some(partition_info(source)),
            new_partition_info: Some(partition_info(source)),
            operations: vec![InstallOperation {
                operation_type: 4,
                src_extents: vec![extent(0, 1)],
                dst_extents: vec![extent(0, 1)],
                ..Default::default()
            }],
        }],
    };
    let payload = temporary.path().join("payload.bin");
    write_payload(&payload, manifest, &[]);

    let error = ExtractOptions::new()
        .source_dir(&source_dir)
        .extract(&payload, &output_dir)
        .unwrap_err()
        .to_string();

    assert!(error.contains("already exists"));
    assert_eq!(fs::read(output_dir.join("system.img")).unwrap(), existing);
    assert_eq!(fs::read(source_dir.join("system.img")).unwrap(), source);
    assert_eq!(fs::read_dir(&output_dir).unwrap().count(), 1);
}

#[test]
fn verification_failure_preserves_existing_destinations_with_overwrite() {
    let temporary = TempDir::new().unwrap();
    let output_dir = temporary.path().join("output");
    fs::create_dir(&output_dir).unwrap();
    fs::write(output_dir.join("boot.img"), b"oldb").unwrap();
    fs::write(output_dir.join("vendor.img"), b"oldv").unwrap();
    let manifest = DeltaArchiveManifest {
        block_size: Some(4),
        minor_version: Some(0),
        partitions: vec![
            PartitionUpdate {
                partition_name: "boot".into(),
                old_partition_info: None,
                new_partition_info: Some(partition_info(b"boot")),
                operations: vec![InstallOperation {
                    operation_type: 0,
                    data_offset: Some(0),
                    data_length: Some(4),
                    dst_extents: vec![extent(0, 1)],
                    ..Default::default()
                }],
            },
            PartitionUpdate {
                partition_name: "vendor".into(),
                old_partition_info: None,
                new_partition_info: Some(partition_info(b"bad!")),
                operations: vec![InstallOperation {
                    operation_type: 0,
                    data_offset: Some(4),
                    data_length: Some(4),
                    dst_extents: vec![extent(0, 1)],
                    ..Default::default()
                }],
            },
        ],
    };
    let payload = temporary.path().join("payload.bin");
    write_payload(&payload, manifest, b"bootvend");

    let error = ExtractOptions::new()
        .overwrite(true)
        .extract(&payload, &output_dir)
        .unwrap_err()
        .to_string();

    assert!(error.contains("Output verification failed"));
    assert_eq!(fs::read(output_dir.join("boot.img")).unwrap(), b"oldb");
    assert_eq!(fs::read(output_dir.join("vendor.img")).unwrap(), b"oldv");
    assert_eq!(fs::read_dir(&output_dir).unwrap().count(), 2);
}

#[test]
fn partition_selection_does_not_require_unselected_delta_sources() {
    let temporary = TempDir::new().unwrap();
    let output_dir = temporary.path().join("output");
    let expected = b"boot";
    let manifest = DeltaArchiveManifest {
        block_size: Some(4),
        minor_version: Some(2),
        partitions: vec![
            PartitionUpdate {
                partition_name: "boot".into(),
                old_partition_info: None,
                new_partition_info: Some(partition_info(expected)),
                operations: vec![InstallOperation {
                    operation_type: 0,
                    data_offset: Some(0),
                    data_length: Some(4),
                    dst_extents: vec![extent(0, 1)],
                    ..Default::default()
                }],
            },
            PartitionUpdate {
                partition_name: "system".into(),
                old_partition_info: Some(partition_info(b"base")),
                new_partition_info: Some(partition_info(b"base")),
                operations: vec![InstallOperation {
                    operation_type: 4,
                    src_extents: vec![extent(0, 1)],
                    dst_extents: vec![extent(0, 1)],
                    ..Default::default()
                }],
            },
        ],
    };
    let payload = temporary.path().join("payload.bin");
    write_payload(&payload, manifest, expected);

    ExtractOptions::new().partitions(["boot"]).extract(&payload, &output_dir).unwrap();

    assert_eq!(fs::read(output_dir.join("boot.img")).unwrap(), expected);
    assert!(!output_dir.join("system.img").exists());
}

#[cfg(unix)]
#[test]
fn source_and_destination_aliases_are_rejected_without_modifying_the_source() {
    use std::os::unix::fs::symlink;

    for link in ["hard", "symbolic"] {
        let temporary = TempDir::new().unwrap();
        let source_dir = temporary.path().join("source");
        let output_dir = temporary.path().join("output");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&output_dir).unwrap();
        let source_path = source_dir.join("system.img");
        let source = b"base";
        fs::write(&source_path, source).unwrap();
        let destination_path = output_dir.join("system.img");
        if link == "hard" {
            fs::hard_link(&source_path, &destination_path).unwrap();
        } else {
            symlink(&source_path, &destination_path).unwrap();
        }

        let manifest = DeltaArchiveManifest {
            block_size: Some(4),
            minor_version: Some(2),
            partitions: vec![PartitionUpdate {
                partition_name: "system".into(),
                old_partition_info: Some(partition_info(source)),
                new_partition_info: Some(partition_info(source)),
                operations: vec![InstallOperation {
                    operation_type: 4,
                    src_extents: vec![extent(0, 1)],
                    dst_extents: vec![extent(0, 1)],
                    ..Default::default()
                }],
            }],
        };
        let payload = temporary.path().join("payload.bin");
        write_payload(&payload, manifest, &[]);

        let error = ExtractOptions::new()
            .source_dir(&source_dir)
            .overwrite(true)
            .extract(&payload, &output_dir)
            .unwrap_err()
            .to_string();

        assert!(error.contains("refer to the same file"));
        assert_eq!(fs::read(&source_path).unwrap(), source);
    }
}
