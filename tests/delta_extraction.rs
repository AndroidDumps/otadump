use std::fs;
use std::path::{Path, PathBuf};

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

fn partition_info(bytes: &[u8]) -> PartitionInfo {
    PartitionInfo { size: Some(bytes.len() as u64), hash: Some(sha256(bytes)) }
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

fn puffin_fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from("tests/fixtures/puffin").join(name);
    fs::read(path).unwrap()
}

#[test]
fn full_replace_payload_extracts_expected_partition() {
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
fn source_copy_keeps_source_immutable_and_respects_extent_order() {
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

    ExtractOptions::new().source_dir(&source_dir).extract(&payload, &output_dir).unwrap();

    assert_eq!(fs::read(output_dir.join("system.img")).unwrap(), expected);
    assert_eq!(fs::read(source_dir.join("system.img")).unwrap(), source);
}

#[test]
fn missing_source_image_fails_without_publishing_output() {
    let temporary = TempDir::new().unwrap();
    let source_dir = temporary.path().join("source");
    let output_dir = temporary.path().join("output");
    fs::create_dir(&source_dir).unwrap();
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
            old_partition_info: Some(partition_info(b"base")),
            new_partition_info: Some(partition_info(b"base")),
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

    assert!(error.contains("Unable to open source partition image"), "unexpected error: {error}");
    assert!(!output_dir.join("boot.img").exists());
    assert!(fs::read_dir(&output_dir).unwrap().next().is_none());
}

#[cfg(otadump_zucchini)]
#[test]
fn puffdiff_zucchini_golden_reconstructs_and_keeps_source() {
    let source = puffin_fixture("deflates-sample1.bin");
    let target = puffin_fixture("deflates-sample2.bin");
    let patch = puffin_fixture("patch-1-to-2-zucchini.puf");

    let temporary = TempDir::new().unwrap();
    let source_dir = temporary.path().join("source");
    let output_dir = temporary.path().join("output");
    fs::create_dir(&source_dir).unwrap();
    fs::write(source_dir.join("system.img"), &source).unwrap();

    let manifest = DeltaArchiveManifest {
        block_size: Some(1),
        minor_version: Some(5),
        partitions: vec![PartitionUpdate {
            partition_name: "system".into(),
            old_partition_info: Some(partition_info(&source)),
            new_partition_info: Some(partition_info(&target)),
            operations: vec![InstallOperation {
                operation_type: 9,
                data_offset: Some(0),
                data_length: Some(patch.len() as u64),
                src_extents: vec![extent(0, source.len() as u64)],
                src_length: Some(source.len() as u64),
                dst_extents: vec![extent(0, target.len() as u64)],
                dst_length: Some(target.len() as u64),
                data_sha256_hash: Some(sha256(&patch)),
                src_sha256_hash: Some(sha256(&source)),
            }],
        }],
    };
    let payload = temporary.path().join("payload.bin");
    write_payload(&payload, manifest, &patch);

    ExtractOptions::new().source_dir(&source_dir).extract(&payload, &output_dir).unwrap();

    assert_eq!(fs::read(output_dir.join("system.img")).unwrap(), target);
    assert_eq!(fs::read(source_dir.join("system.img")).unwrap(), source);
}
