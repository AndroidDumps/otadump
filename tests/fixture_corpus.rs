use std::collections::HashMap;
use std::fs::File;
use std::sync::OnceLock;

use zip::ZipArchive;

const CORPUS_ZIP: &str = "tests/fixtures/corpus/opaque-fixtures.zip";

static FIXTURES: OnceLock<HashMap<String, Vec<u8>>> = OnceLock::new();

fn load() -> HashMap<String, Vec<u8>> {
    let file = File::open(CORPUS_ZIP).expect("failed to open fixture corpus zip");
    let mut archive = ZipArchive::new(file).expect("failed to parse fixture corpus zip");
    let mut fixtures = HashMap::with_capacity(archive.len());
    for index in 0..archive.len() {
        let mut member = archive.by_index(index).expect("failed to read fixture corpus entry");
        let mut bytes = Vec::new();
        std::io::copy(&mut member, &mut bytes).expect("failed to decode fixture corpus entry");
        fixtures.insert(member.name().to_string(), bytes);
    }
    fixtures
}

pub fn read(path: &str) -> Vec<u8> {
    FIXTURES
        .get_or_init(load)
        .get(path)
        .unwrap_or_else(|| panic!("missing fixture in corpus zip: {path}"))
        .clone()
}
