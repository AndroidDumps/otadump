// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Adapted from puffdiff 0.1.0, a pure-Rust port of ChromiumOS Puffin.

//! The "puff" intermediate serialization, ported from puffin `puff_data.h`,
//! `puff_writer.cc` and `puff_reader.cc`.
//!
//! The byte layout produced here must match puffin exactly, because the bsdiff
//! patch inside a PUFFDIFF op is computed against puffin's puffed bytes.

use crate::puffin::{Error, Result};

/// Maximum bytes a block-metadata blob can occupy: 1 header + 3 lengths +
/// 286 lit/len code lengths + 30 distance + 19 code-length codes.
pub const BLOCK_METADATA_MAX: usize = 1 + 3 + 286 + 30 + 19;

const LITERALS_HEADER: u8 = 0x00;
const LEN_DIST_HEADER: u8 = 0x80;
const LITERALS_MAX_LENGTH: usize = (1 << 16) + 127; // 65663

/// One decoded token exchanged between puffer/huffer and the puff buffer.
pub enum PuffData<'a> {
    Literal(u8),
    Literals(&'a [u8]),
    LenDist { length: usize, distance: usize },
    BlockMetadata(&'a [u8]),
    EndOfBlock,
}

#[inline]
fn write_u16_be(buf: &mut [u8], value: u16) -> Result<()> {
    let target =
        buf.get_mut(..2).ok_or_else(|| Error::Corrupt("puff writer u16 overflow".into()))?;
    target.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

#[inline]
fn read_u16_be(buf: &[u8]) -> Result<u16> {
    let bytes: [u8; 2] = buf
        .get(..2)
        .ok_or_else(|| Error::Corrupt("puff reader u16 overflow".into()))?
        .try_into()
        .map_err(|_| Error::Corrupt("puff reader u16 conversion failed".into()))?;
    Ok(u16::from_be_bytes(bytes))
}

#[derive(PartialEq)]
enum WState {
    None,
    Small,
    Large,
}

/// Serializes `PuffData` tokens into the puff byte format.
pub struct PuffWriter<'a> {
    out: &'a mut [u8],
    index: usize,
    state: WState,
    len_index: usize,
    cur_literals_length: usize,
}

impl<'a> PuffWriter<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        PuffWriter { out, index: 0, state: WState::None, len_index: 0, cur_literals_length: 0 }
    }

    fn insert_literal_bytes(&mut self, is_single: bool, byte: u8, bytes: &[u8]) -> Result<()> {
        let length = if is_single { 1 } else { bytes.len() };
        if !is_single && length == 0 {
            return Ok(());
        }
        if self.state == WState::None {
            self.need(1)?;
            self.len_index = self.index;
            self.index += 1;
            self.state = WState::Small;
        }
        let combined_length = self
            .cur_literals_length
            .checked_add(length)
            .ok_or_else(|| Error::Corrupt("puff literal length overflows".into()))?;
        if combined_length > LITERALS_MAX_LENGTH {
            return Err(Error::Corrupt("puff literal run is too long".into()));
        }
        if self.state == WState::Small && combined_length > 127 {
            // Open two bytes of space for a large-literal length prefix by
            // shifting the already-written literals forward.
            self.need(2)?;
            let literal_start = self
                .len_index
                .checked_add(1)
                .ok_or_else(|| Error::Corrupt("puff literal offset overflows".into()))?;
            let literal_end = literal_start
                .checked_add(self.cur_literals_length)
                .ok_or_else(|| Error::Corrupt("puff literal range overflows".into()))?;
            let destination = self
                .len_index
                .checked_add(3)
                .ok_or_else(|| Error::Corrupt("puff literal shift overflows".into()))?;
            self.out.copy_within(literal_start..literal_end, destination);
            self.index += 2;
            self.state = WState::Large;
        }

        self.need(length)?;
        let end = self
            .index
            .checked_add(length)
            .ok_or_else(|| Error::Corrupt("puff writer literal range overflows".into()))?;
        if is_single {
            self.out[self.index] = byte;
        } else {
            self.out[self.index..end].copy_from_slice(bytes);
        }
        self.index = end;
        self.cur_literals_length = combined_length;

        if self.cur_literals_length == LITERALS_MAX_LENGTH {
            self.flush_literals()?;
        }
        Ok(())
    }

    pub fn insert(&mut self, pd: &PuffData) -> Result<()> {
        match pd {
            PuffData::Literal(b) => self.insert_literal_bytes(true, *b, &[]),
            PuffData::Literals(bytes) => self.insert_literal_bytes(false, 0, bytes),
            PuffData::LenDist { length, distance } => {
                self.flush_literals()?;
                let (length, distance) = (*length, *distance);
                if !(3..=258).contains(&length) || !(1..=32768).contains(&distance) {
                    return Err(Error::Corrupt("len/dist out of range".into()));
                }
                if length < 130 {
                    self.need(3)?;
                    self.out[self.index] = LEN_DIST_HEADER | (length - 3) as u8;
                    self.index += 1;
                } else {
                    self.need(4)?;
                    self.out[self.index] = LEN_DIST_HEADER | 127;
                    self.index += 1;
                    self.out[self.index] = (length - 3 - 127) as u8;
                    self.index += 1;
                }
                write_u16_be(&mut self.out[self.index..], (distance - 1) as u16)?;
                self.index += 2;
                self.len_index = self.index;
                self.state = WState::None;
                Ok(())
            }
            PuffData::BlockMetadata(meta) => {
                self.flush_literals()?;
                let length = meta.len();
                if length == 0 || length > BLOCK_METADATA_MAX {
                    return Err(Error::Corrupt("block metadata length invalid".into()));
                }
                self.need(length.checked_add(2).ok_or_else(|| {
                    Error::Corrupt("block metadata output length overflows".into())
                })?)?;
                write_u16_be(&mut self.out[self.index..], (length - 1) as u16)?;
                self.index += 2;
                self.out[self.index..self.index + length].copy_from_slice(meta);
                self.index += length;
                self.len_index = self.index;
                self.state = WState::None;
                Ok(())
            }
            PuffData::EndOfBlock => {
                self.flush_literals()?;
                self.need(2)?;
                self.out[self.index] = LEN_DIST_HEADER | 127;
                self.index += 1;
                self.out[self.index] = (259 - 3 - 127) as u8;
                self.index += 1;
                self.len_index = self.index;
                self.state = WState::None;
                Ok(())
            }
        }
    }

    fn need(&self, count: usize) -> Result<()> {
        let end = self
            .index
            .checked_add(count)
            .ok_or_else(|| Error::Corrupt("puff writer range overflows".into()))?;
        if end > self.out.len() {
            return Err(Error::Corrupt("puff writer output overflow".into()));
        }
        Ok(())
    }

    fn flush_literals(&mut self) -> Result<()> {
        if self.cur_literals_length == 0 {
            return Ok(());
        }
        match self.state {
            WState::Small => {
                if self.cur_literals_length != self.index - self.len_index - 1 {
                    return Err(Error::Corrupt("small literal length mismatch".into()));
                }
                self.out[self.len_index] = LITERALS_HEADER | (self.cur_literals_length - 1) as u8;
                self.len_index = self.index;
                self.state = WState::None;
            }
            WState::Large => {
                if self.cur_literals_length != self.index - self.len_index - 3 {
                    return Err(Error::Corrupt("large literal length mismatch".into()));
                }
                self.out[self.len_index] = LITERALS_HEADER | 127;
                write_u16_be(
                    &mut self.out[self.len_index + 1..],
                    (self.cur_literals_length - 127 - 1) as u16,
                )?;
                self.len_index = self.index;
                self.state = WState::None;
            }
            WState::None => {}
        }
        self.cur_literals_length = 0;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.flush_literals()
    }

    pub fn size(&self) -> usize {
        self.index
    }
}

enum RState {
    ReadingLenDist,
    ReadingBlockMetadata,
}

/// Deserializes puff bytes back into `PuffData` tokens.
pub struct PuffReader<'a> {
    buf: &'a [u8],
    index: usize,
    state: RState,
}

impl<'a> PuffReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        PuffReader { buf, index: 0, state: RState::ReadingBlockMetadata }
    }

    pub fn bytes_left(&self) -> usize {
        self.buf.len() - self.index
    }

    fn need(&self, n: usize) -> Result<()> {
        let end = self
            .index
            .checked_add(n)
            .ok_or_else(|| Error::Corrupt("puff reader range overflows".into()))?;
        if end > self.buf.len() {
            return Err(Error::Corrupt("puff reader out of range".into()));
        }
        Ok(())
    }

    pub fn get_next(&mut self) -> Result<PuffData<'a>> {
        match self.state {
            RState::ReadingLenDist => {
                self.need(1)?;
                let header = self.buf[self.index];
                if header & 0x80 != 0 {
                    // length/distance (or end of block)
                    let mut length;
                    if (header & 0x7F) < 127 {
                        length = (header & 0x7F) as usize;
                    } else {
                        self.index += 1;
                        self.need(1)?;
                        length = self.buf[self.index] as usize + 127;
                    }
                    length += 3;
                    if length > 259 {
                        return Err(Error::Corrupt("len/dist length too large".into()));
                    }
                    self.index += 1;

                    if length == 259 {
                        self.state = RState::ReadingBlockMetadata;
                        return Ok(PuffData::EndOfBlock);
                    }

                    self.need(2)?;
                    let distance = read_u16_be(&self.buf[self.index..])?;
                    if distance >= (1 << 15) {
                        return Err(Error::Corrupt("distance too large".into()));
                    }
                    let distance = distance as usize + 1;
                    self.index += 2;
                    Ok(PuffData::LenDist { length, distance })
                } else {
                    // literals
                    let mut length;
                    if (header & 0x7F) < 127 {
                        length = (header & 0x7F) as usize;
                        self.index += 1;
                    } else {
                        self.index += 1;
                        self.need(2)?;
                        length = usize::from(read_u16_be(&self.buf[self.index..])?) + 127;
                        self.index += 2;
                    }
                    length += 1;
                    self.need(length)?;
                    let slice = &self.buf[self.index..self.index + length];
                    self.index += length;
                    Ok(PuffData::Literals(slice))
                }
            }
            RState::ReadingBlockMetadata => {
                self.need(2)?;
                let length = usize::from(read_u16_be(&self.buf[self.index..])?) + 1;
                self.index += 2;
                self.need(length)?;
                if length > BLOCK_METADATA_MAX {
                    return Err(Error::Corrupt("block metadata too large".into()));
                }
                let slice = &self.buf[self.index..self.index + length];
                self.index += length;
                self.state = RState::ReadingLenDist;
                Ok(PuffData::BlockMetadata(slice))
            }
        }
    }
}
