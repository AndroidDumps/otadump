// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Adapted from puffdiff 0.1.0 and ChromiumOS Puffin's puffin_stream.cc.

use crate::CancellationToken;
use crate::puffin::bit_io::{BitReader, BitWriter};
use crate::puffin::huffer::huff_deflate;
use crate::puffin::puff_io::{PuffReader, PuffWriter};
use crate::puffin::puffer::puff_deflate;
use crate::puffin::{BitExtent, ByteExtent, Error, Result, check_cancelled};

#[derive(Clone, Copy)]
struct Extent {
    offset: usize,
    length: usize,
}

struct Driver<'a> {
    source: Option<&'a [u8]>,
    output: Vec<u8>,
    output_position: usize,
    deflates: Vec<Extent>,
    puffs: Vec<Extent>,
    upper_bounds: Vec<usize>,
    current: usize,
    puff_position: usize,
    skip_bytes: usize,
    deflate_bit_position: usize,
    last_byte: u32,
    extra_byte: usize,
    max_puff_length: usize,
}

fn allocate_zeroed(length: usize, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|error| Error::Allocation(format!("{label}: {error}")))?;
    bytes.resize(length, 0);
    Ok(bytes)
}

fn checked_end(extent: Extent, label: &str) -> Result<usize> {
    extent
        .offset
        .checked_add(extent.length)
        .ok_or_else(|| Error::Corrupt(format!("{label} extent end overflows")))
}

impl<'a> Driver<'a> {
    fn new(
        source: Option<&'a [u8]>,
        raw_size: usize,
        puff_size: usize,
        deflates: &[BitExtent],
        puffs: &[ByteExtent],
    ) -> Result<Self> {
        if deflates.len() != puffs.len() {
            return Err(Error::Corrupt("deflate and puff extent counts differ".into()));
        }

        let mut driver_deflates = Vec::new();
        driver_deflates
            .try_reserve_exact(deflates.len().saturating_add(1))
            .map_err(|error| Error::Allocation(format!("deflate stream metadata: {error}")))?;
        driver_deflates.extend(
            deflates.iter().map(|extent| Extent { offset: extent.offset, length: extent.length }),
        );
        driver_deflates.push(Extent {
            offset: raw_size
                .checked_mul(8)
                .ok_or_else(|| Error::Corrupt("raw stream bit length overflows".into()))?,
            length: 0,
        });

        let mut driver_puffs = Vec::new();
        driver_puffs
            .try_reserve_exact(puffs.len().saturating_add(1))
            .map_err(|error| Error::Allocation(format!("puff stream metadata: {error}")))?;
        driver_puffs.extend(
            puffs.iter().map(|extent| Extent { offset: extent.offset, length: extent.length }),
        );
        driver_puffs.push(Extent { offset: puff_size, length: 0 });

        let mut upper_bounds = Vec::new();
        upper_bounds
            .try_reserve_exact(driver_puffs.len())
            .map_err(|error| Error::Allocation(format!("puff stream index: {error}")))?;
        for puff in &driver_puffs {
            upper_bounds.push(checked_end(*puff, "puff")?);
        }

        let output = if source.is_some() {
            Vec::new()
        } else {
            allocate_zeroed(raw_size, "raw Puffin output")?
        };
        Ok(Self {
            source,
            output,
            output_position: 0,
            deflates: driver_deflates,
            puffs: driver_puffs,
            upper_bounds,
            current: 0,
            puff_position: 0,
            skip_bytes: 0,
            deflate_bit_position: 0,
            last_byte: 0,
            extra_byte: 0,
            max_puff_length: puffs.iter().map(|extent| extent.length).max().unwrap_or(0),
        })
    }

    fn seek_to_zero(&mut self, huffing: bool) -> Result<()> {
        self.current = self
            .upper_bounds
            .iter()
            .position(|&bound| bound > 0)
            .ok_or_else(|| Error::Corrupt("empty Puffin stream index".into()))?;
        let puff = self.puffs[self.current];
        let deflate = self.deflates[self.current];
        if puff.offset > 0 {
            self.puff_position = 0;
            let rounded_deflate = deflate
                .offset
                .checked_add(7)
                .ok_or_else(|| Error::Corrupt("deflate offset rounding overflows".into()))?
                / 8;
            self.deflate_bit_position = rounded_deflate
                .checked_sub(puff.offset)
                .and_then(|offset| offset.checked_mul(8))
                .ok_or_else(|| Error::Corrupt("initial raw region is inconsistent".into()))?;
        } else {
            self.puff_position = puff.offset;
            self.deflate_bit_position = deflate.offset;
        }
        if huffing {
            self.set_extra_byte()?;
        }
        Ok(())
    }

    fn set_extra_byte(&mut self) -> Result<()> {
        let deflate = *self
            .deflates
            .get(self.current)
            .ok_or_else(|| Error::Corrupt("deflate index is out of range".into()))?;
        let Some(next) = self.deflates.get(self.current + 1).copied() else {
            self.extra_byte = 0;
            return Ok(());
        };
        let end_bit = checked_end(deflate, "deflate")?;
        let rounded_end = end_bit
            .checked_add(7)
            .ok_or_else(|| Error::Corrupt("deflate end rounding overflows".into()))?
            & !7usize;
        self.extra_byte = usize::from(end_bit & 7 != 0 && rounded_end <= next.offset);
        Ok(())
    }

    fn source_slice(&self, range: std::ops::Range<usize>) -> Result<&'a [u8]> {
        self.source
            .and_then(|source| source.get(range))
            .ok_or_else(|| Error::Corrupt("read past end of raw stream".into()))
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self
            .output_position
            .checked_add(bytes.len())
            .ok_or_else(|| Error::Corrupt("raw output position overflows".into()))?;
        let destination = self
            .output
            .get_mut(self.output_position..end)
            .ok_or_else(|| Error::Corrupt("write past end of raw stream".into()))?;
        destination.copy_from_slice(bytes);
        self.output_position = end;
        Ok(())
    }

    fn run_puff(
        &mut self,
        output: &mut [u8],
        cancellation_token: &CancellationToken,
    ) -> Result<()> {
        let mut bytes_read = 0usize;
        while bytes_read < output.len() {
            check_cancelled(cancellation_token)?;
            let deflate = self.deflates[self.current];
            let puff = self.puffs[self.current];
            if self.puff_position < puff.offset {
                let start_byte = self.deflate_bit_position / 8;
                let end_byte =
                    deflate.offset.checked_add(7).ok_or_else(|| {
                        Error::Corrupt("deflate offset rounding overflows".into())
                    })? / 8;
                let available = end_byte
                    .checked_sub(start_byte)
                    .ok_or_else(|| Error::Corrupt("raw region runs backward".into()))?;
                let count = (output.len() - bytes_read).min(available);
                if count == 0 {
                    return Err(Error::Corrupt("raw region makes no progress".into()));
                }
                let source_end = start_byte
                    .checked_add(count)
                    .ok_or_else(|| Error::Corrupt("raw source range overflows".into()))?;
                let destination_end = bytes_read
                    .checked_add(count)
                    .ok_or_else(|| Error::Corrupt("puff output range overflows".into()))?;
                output[bytes_read..destination_end]
                    .copy_from_slice(self.source_slice(start_byte..source_end)?);
                if source_end
                    .checked_mul(8)
                    .ok_or_else(|| Error::Corrupt("raw bit position overflows".into()))?
                    > deflate.offset
                {
                    let mask = ((1u16 << (deflate.offset & 7)) - 1) as u8;
                    output[destination_end - 1] &= mask;
                }
                if start_byte * 8 < self.deflate_bit_position {
                    output[bytes_read] >>= self.deflate_bit_position & 7;
                }
                self.deflate_bit_position = (self.deflate_bit_position & !7usize)
                    .checked_add(count * 8)
                    .ok_or_else(|| Error::Corrupt("raw bit position overflows".into()))?
                    .min(deflate.offset);
                bytes_read = destination_end;
                self.puff_position = self
                    .puff_position
                    .checked_add(count)
                    .ok_or_else(|| Error::Corrupt("puff position overflows".into()))?;
                if self.puff_position > puff.offset {
                    return Err(Error::Corrupt("raw region overruns puff extent".into()));
                }
                continue;
            }

            let deflate_end = checked_end(deflate, "deflate")?;
            let start_byte = deflate.offset / 8;
            let end_byte = deflate_end
                .checked_add(7)
                .ok_or_else(|| Error::Corrupt("deflate end rounding overflows".into()))?
                / 8;
            let deflate_bytes = self.source_slice(start_byte..end_byte)?;
            let direct = self.skip_bytes == 0 && output.len() - bytes_read >= puff.length;
            let mut temporary = Vec::new();
            let target = if direct {
                let end = bytes_read
                    .checked_add(puff.length)
                    .ok_or_else(|| Error::Corrupt("puff output range overflows".into()))?;
                &mut output[bytes_read..end]
            } else {
                temporary = allocate_zeroed(puff.length, "temporary puff buffer")?;
                &mut temporary
            };
            let mut bit_reader = BitReader::new(deflate_bytes);
            let skipped_bits = deflate.offset & 7;
            if !bit_reader.cache_bits(skipped_bits) {
                return Err(Error::Corrupt("deflate extent starts past its bytes".into()));
            }
            bit_reader.drop_bits(skipped_bits);
            let mut puff_writer = PuffWriter::new(target);
            puff_deflate(&mut bit_reader, &mut puff_writer, cancellation_token)?;
            let expected_bits = skipped_bits
                .checked_add(deflate.length)
                .ok_or_else(|| Error::Corrupt("deflate bit length overflows".into()))?;
            if bit_reader.offset_in_bits()? != expected_bits
                || bit_reader.offset() != deflate_bytes.len()
                || puff_writer.size() != puff.length
            {
                return Err(Error::Corrupt("puffed extent size does not match metadata".into()));
            }
            let copy_count = (output.len() - bytes_read).min(
                puff.length
                    .checked_sub(self.skip_bytes)
                    .ok_or_else(|| Error::Corrupt("puff skip exceeds extent".into()))?,
            );
            if !direct {
                let copy_end = self
                    .skip_bytes
                    .checked_add(copy_count)
                    .ok_or_else(|| Error::Corrupt("puff copy range overflows".into()))?;
                output[bytes_read..bytes_read + copy_count]
                    .copy_from_slice(&temporary[self.skip_bytes..copy_end]);
            }
            self.skip_bytes += copy_count;
            bytes_read += copy_count;
            if self
                .puff_position
                .checked_add(self.skip_bytes)
                .ok_or_else(|| Error::Corrupt("puff position overflows".into()))?
                == checked_end(puff, "puff")?
            {
                self.puff_position += self.skip_bytes;
                self.skip_bytes = 0;
                self.deflate_bit_position = deflate_end;
                self.current += 1;
                if self.current >= self.puffs.len() {
                    break;
                }
            } else if copy_count == 0 {
                return Err(Error::Corrupt("puff extent makes no progress".into()));
            }
        }
        if bytes_read != output.len() {
            return Err(Error::Corrupt("puffer did not fill its output".into()));
        }
        Ok(())
    }

    fn run_huff(&mut self, input: &[u8], cancellation_token: &CancellationToken) -> Result<()> {
        let puff_buffer_size = self
            .max_puff_length
            .checked_add(1)
            .ok_or_else(|| Error::Corrupt("puff buffer size overflows".into()))?;
        let mut puff_buffer = allocate_zeroed(puff_buffer_size, "huffer puff buffer")?;
        let mut bytes_written = 0usize;
        while bytes_written < input.len() {
            check_cancelled(cancellation_token)?;
            let deflate = self.deflates[self.current];
            let puff = self.puffs[self.current];
            if self.deflate_bit_position < (deflate.offset & !7usize) {
                if self.deflate_bit_position & 7 != 0 {
                    return Err(Error::Corrupt("raw output is not byte-aligned".into()));
                }
                let raw_count = (deflate.offset / 8)
                    .checked_sub(self.deflate_bit_position / 8)
                    .ok_or_else(|| Error::Corrupt("raw output region runs backward".into()))?;
                let copy_count = raw_count.min(input.len() - bytes_written);
                if copy_count == 0 {
                    return Err(Error::Corrupt("raw output makes no progress".into()));
                }
                self.write(&input[bytes_written..bytes_written + copy_count])?;
                bytes_written += copy_count;
                self.puff_position += copy_count;
                self.deflate_bit_position += copy_count * 8;
                continue;
            }

            if self.deflate_bit_position < deflate.offset {
                let byte = *input
                    .get(bytes_written)
                    .ok_or_else(|| Error::Corrupt("missing shared boundary byte".into()))?;
                self.last_byte |= u32::from(byte) << (self.deflate_bit_position & 7);
                bytes_written += 1;
                self.skip_bytes = 0;
                self.deflate_bit_position = deflate.offset;
                self.puff_position += 1;
                if self.puff_position != puff.offset {
                    return Err(Error::Corrupt("puff boundary position does not match".into()));
                }
            }

            let required = puff
                .length
                .checked_add(self.extra_byte)
                .and_then(|length| length.checked_sub(self.skip_bytes))
                .ok_or_else(|| Error::Corrupt("puff buffer accounting is invalid".into()))?;
            let copy_count = (input.len() - bytes_written).min(required);
            let copy_end = self
                .skip_bytes
                .checked_add(copy_count)
                .ok_or_else(|| Error::Corrupt("puff buffer range overflows".into()))?;
            let destination = puff_buffer
                .get_mut(self.skip_bytes..copy_end)
                .ok_or_else(|| Error::Corrupt("puff buffer is too small".into()))?;
            destination.copy_from_slice(&input[bytes_written..bytes_written + copy_count]);
            self.skip_bytes = copy_end;
            bytes_written += copy_count;

            if self.skip_bytes == puff.length + self.extra_byte {
                let deflate_end = checked_end(deflate, "deflate")?;
                let start_byte = deflate.offset / 8;
                let end_byte = deflate_end
                    .checked_add(7)
                    .ok_or_else(|| Error::Corrupt("deflate end rounding overflows".into()))?
                    / 8;
                let mut deflate_buffer = allocate_zeroed(
                    end_byte
                        .checked_sub(start_byte)
                        .ok_or_else(|| Error::Corrupt("deflate byte range runs backward".into()))?,
                    "huffed deflate buffer",
                )?;
                let mut count = deflate_buffer.len();
                {
                    let mut bit_writer = BitWriter::new(&mut deflate_buffer);
                    bit_writer.write_bits(deflate.offset & 7, self.last_byte)?;
                    self.last_byte = 0;
                    let puff_bytes = puff_buffer
                        .get(..puff.length)
                        .ok_or_else(|| Error::Corrupt("puff extent exceeds buffer".into()))?;
                    let mut puff_reader = PuffReader::new(puff_bytes);
                    huff_deflate(&mut puff_reader, &mut bit_writer, cancellation_token)?;
                    let expected_bits = (deflate.offset & 7)
                        .checked_add(deflate.length)
                        .ok_or_else(|| Error::Corrupt("deflate bit length overflows".into()))?;
                    if bit_writer.offset_in_bits()? != expected_bits
                        || puff_reader.bytes_left() != 0
                    {
                        return Err(Error::Corrupt(
                            "huffed deflate bit length does not match metadata".into(),
                        ));
                    }
                    bit_writer.flush()?;
                    if bit_writer.size() != count {
                        return Err(Error::Corrupt(
                            "huffed deflate size does not match metadata".into(),
                        ));
                    }
                }
                self.deflate_bit_position = deflate_end;
                if self.extra_byte == 1 {
                    let last = deflate_buffer
                        .last_mut()
                        .ok_or_else(|| Error::Corrupt("empty deflate buffer".into()))?;
                    *last |= puff_buffer[puff.length] << (self.deflate_bit_position & 7);
                    self.deflate_bit_position = self
                        .deflate_bit_position
                        .checked_add(7)
                        .ok_or_else(|| Error::Corrupt("deflate position overflows".into()))?
                        & !7usize;
                } else if self.deflate_bit_position & 7 != 0 {
                    self.last_byte = u32::from(
                        *deflate_buffer
                            .last()
                            .ok_or_else(|| Error::Corrupt("empty deflate buffer".into()))?,
                    );
                    count -= 1;
                }
                self.write(&deflate_buffer[..count])?;
                self.puff_position += self.skip_bytes;
                self.skip_bytes = 0;
                self.current += 1;
                if self.current >= self.puffs.len() {
                    break;
                }
                self.set_extra_byte()?;
            } else if copy_count == 0 {
                return Err(Error::Corrupt("huffer makes no progress".into()));
            }
        }
        if bytes_written != input.len() || self.output_position != self.output.len() {
            return Err(Error::Corrupt("huffer output size does not match destination".into()));
        }
        Ok(())
    }
}

pub fn puff(
    source: &[u8],
    deflates: &[BitExtent],
    puffs: &[ByteExtent],
    puff_size: usize,
    cancellation_token: &CancellationToken,
) -> Result<Vec<u8>> {
    let mut driver = Driver::new(Some(source), source.len(), puff_size, deflates, puffs)?;
    driver.seek_to_zero(false)?;
    let mut output = allocate_zeroed(puff_size, "puffed source")?;
    driver.run_puff(&mut output, cancellation_token)?;
    Ok(output)
}

pub fn huff(
    puffed: &[u8],
    deflates: &[BitExtent],
    puffs: &[ByteExtent],
    puff_size: usize,
    raw_size: usize,
    cancellation_token: &CancellationToken,
) -> Result<Vec<u8>> {
    if puffed.len() != puff_size {
        return Err(Error::SizeMismatch { expected: puff_size, actual: puffed.len() });
    }
    let mut driver = Driver::new(None, raw_size, puff_size, deflates, puffs)?;
    driver.seek_to_zero(true)?;
    driver.run_huff(puffed, cancellation_token)?;
    Ok(driver.output)
}
