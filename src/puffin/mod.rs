// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Adapted from puffdiff 0.1.0, a pure-Rust port of ChromiumOS Puffin.

mod bit_io;
mod huffer;
mod huffman;
mod patch;
mod puff_io;
mod puffer;
mod stream;

use std::error;
use std::fmt;

use crate::ExtractionCancelled;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BitExtent {
    offset: usize,
    length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ByteExtent {
    offset: usize,
    length: usize,
}

#[derive(Debug)]
pub(crate) enum Error {
    BadPatchHeader(String),
    BadProto(String),
    UnsupportedPatchType(i32),
    InvalidMetadata(String),
    Corrupt(String),
    Bsdiff(String),
    SizeMismatch { expected: usize, actual: usize },
    Allocation(String),
    Cancelled(ExtractionCancelled),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadPatchHeader(message) => {
                write!(formatter, "invalid PUFFDIFF header: {message}")
            }
            Self::BadProto(message) => {
                write!(formatter, "invalid PUFFDIFF protobuf: {message}")
            }
            Self::UnsupportedPatchType(patch_type) => {
                write!(formatter, "unsupported PUFFDIFF patch type {patch_type}")
            }
            Self::InvalidMetadata(message) => {
                write!(formatter, "invalid PUFFDIFF metadata: {message}")
            }
            Self::Corrupt(message) => write!(formatter, "corrupt Puffin stream: {message}"),
            Self::Bsdiff(message) => write!(formatter, "inner BSDIFF patch is invalid: {message}"),
            Self::SizeMismatch { expected, actual } => {
                write!(formatter, "PUFFDIFF size mismatch: expected {expected}, got {actual}")
            }
            Self::Allocation(message) => write!(formatter, "unable to allocate {message}"),
            Self::Cancelled(error) => error.fmt(formatter),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Cancelled(error) => Some(error),
            _ => None,
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

fn check_cancelled(token: &crate::CancellationToken) -> Result<()> {
    if token.is_cancelled() {
        return Err(Error::Cancelled(ExtractionCancelled));
    }
    Ok(())
}

pub(crate) fn apply(
    source: &[u8],
    patch: &[u8],
    destination_size: usize,
    cancellation_token: &crate::CancellationToken,
) -> Result<Vec<u8>> {
    patch::apply(source, patch, destination_size, cancellation_token)
}

pub(crate) fn validate_bsdiff_resources(
    patch: &[u8],
    output_size: usize,
    cancellation_token: &crate::CancellationToken,
) -> Result<()> {
    patch::validate_bsdiff_resources(patch, output_size, cancellation_token)
}
