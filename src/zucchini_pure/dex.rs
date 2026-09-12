//! DEX disassembler (apply path).
//!
//! Placeholder: the full port of `disassembler_dex.cc` is tracked in
//! `docs/zucchini-rust-port.md`. Until it lands, DEX elements are reported as
//! unsupported by the pure-Rust engine.

use super::{Disassembler, GroupTraits, Reference};

pub struct DexDisassembler;

impl DexDisassembler {
    pub fn parse(_image: &[u8]) -> Option<Self> {
        None
    }
}

impl Disassembler for DexDisassembler {
    fn size(&self) -> u32 {
        0
    }

    fn groups(&self) -> &[GroupTraits] {
        &[]
    }

    fn read(&self, _group: usize, _image: &[u8], _lo: u32, _hi: u32) -> Vec<Reference> {
        Vec::new()
    }

    fn write(&self, _group: usize, _image: &mut [u8], _reference: Reference) {}
}
