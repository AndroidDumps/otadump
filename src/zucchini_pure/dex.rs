//! Pure-Rust port of `disassembler_dex.cc` for the apply path.

use std::collections::BTreeMap;

use super::bytes::{align_ceil, read_i16, read_i32, read_i8, read_u16, read_u32, write_u16, write_u32};
use super::{Disassembler, GroupTraits, Reference, K_INVALID_OFFSET, OFFSET_BOUND};

const HEADER_SIZE: usize = 112;
const CODE_ITEM_HEADER: usize = 16;
const MAP_ITEM_SIZE: usize = 12;
const K_MAX_ITEM_LIST_SIZE: u32 = 21;
const K_MAX_LEB128_SIZE: usize = 5;
const SENTINEL_OFFSET: u32 = 0;
const SENTINEL_INDEX: u32 = 0xFFFF_FFFF;

// Map item type codes.
const T_STRING_ID: u16 = 0x0001;
const T_TYPE_ID: u16 = 0x0002;
const T_PROTO_ID: u16 = 0x0003;
const T_FIELD_ID: u16 = 0x0004;
const T_METHOD_ID: u16 = 0x0005;
const T_CLASS_DEF: u16 = 0x0006;
const T_CALL_SITE_ID: u16 = 0x0007;
const T_METHOD_HANDLE: u16 = 0x0008;
const T_TYPE_LIST: u16 = 0x1001;
const T_ANNOTATION_SET_REF_LIST: u16 = 0x1002;
const T_ANNOTATION_SET_ITEM: u16 = 0x1003;
const T_CODE_ITEM: u16 = 0x2001;
const T_ANNOTATIONS_DIRECTORY: u16 = 0x2006;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MapItem {
    size: u32,
    offset: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Format {
    B,
    C,
    H,
    I,
    L,
    N,
    S,
    T,
    X,
}

#[derive(Clone, Copy, Debug)]
struct Bytecode {
    layout: u8,
    format: Format,
}

/// `dex::kByteCode`, expanded into a flat 256-entry opcode table.
const BYTECODE: &[(u8, u8, Format, u8)] = &[
    (0x00, 1, Format::X, 1),
    (0x01, 1, Format::X, 1),
    (0x02, 2, Format::X, 1),
    (0x03, 3, Format::X, 1),
    (0x04, 1, Format::X, 1),
    (0x05, 2, Format::X, 1),
    (0x06, 3, Format::X, 1),
    (0x07, 1, Format::X, 1),
    (0x08, 2, Format::X, 1),
    (0x09, 3, Format::X, 1),
    (0x0A, 1, Format::X, 1),
    (0x0B, 1, Format::X, 1),
    (0x0C, 1, Format::X, 1),
    (0x0D, 1, Format::X, 1),
    (0x0E, 1, Format::X, 1),
    (0x0F, 1, Format::X, 1),
    (0x10, 1, Format::X, 1),
    (0x11, 1, Format::X, 1),
    (0x12, 1, Format::N, 1),
    (0x13, 2, Format::S, 1),
    (0x14, 3, Format::I, 1),
    (0x15, 2, Format::H, 1),
    (0x16, 2, Format::S, 1),
    (0x17, 3, Format::I, 1),
    (0x18, 5, Format::L, 1),
    (0x19, 2, Format::H, 1),
    (0x1A, 2, Format::C, 1),
    (0x1B, 3, Format::C, 1),
    (0x1C, 2, Format::C, 1),
    (0x1D, 1, Format::X, 1),
    (0x1E, 1, Format::X, 1),
    (0x1F, 2, Format::C, 1),
    (0x20, 2, Format::C, 1),
    (0x21, 1, Format::X, 1),
    (0x22, 2, Format::C, 1),
    (0x23, 2, Format::C, 1),
    (0x24, 3, Format::C, 1),
    (0x25, 3, Format::C, 1),
    (0x26, 3, Format::T, 1),
    (0x27, 1, Format::X, 1),
    (0x28, 1, Format::T, 1),
    (0x29, 2, Format::T, 1),
    (0x2A, 3, Format::T, 1),
    (0x2B, 3, Format::T, 1),
    (0x2C, 3, Format::T, 1),
    (0x2D, 2, Format::X, 5),
    (0x32, 2, Format::T, 6),
    (0x38, 2, Format::T, 6),
    (0x44, 2, Format::X, 14),
    (0x52, 2, Format::C, 14),
    (0x60, 2, Format::C, 14),
    (0x6E, 3, Format::C, 5),
    (0x74, 3, Format::C, 5),
    (0x7B, 1, Format::X, 21),
    (0x90, 2, Format::X, 32),
    (0xB0, 1, Format::X, 32),
    (0xD0, 2, Format::S, 8),
    (0xD8, 2, Format::B, 11),
    (0xFA, 4, Format::C, 1),
    (0xFB, 4, Format::C, 1),
    (0xFC, 3, Format::C, 1),
    (0xFD, 3, Format::C, 1),
    (0xFE, 2, Format::C, 1),
    (0xFF, 2, Format::C, 1),
];

fn find_instruction(opcode: u8) -> Option<Bytecode> {
    BYTECODE
        .iter()
        .find(|(start, _, _, variant)| {
            opcode >= *start && opcode < start.wrapping_add(*variant)
        })
        .map(|(_, layout, format, _)| Bytecode { layout: *layout, format: *format })
}

#[derive(Clone, Debug)]
pub struct DexDisassembler {
    size: u32,
    groups: Vec<GroupTraits>,
    string_map: MapItem,
    type_map: MapItem,
    proto_map: MapItem,
    field_map: MapItem,
    method_map: MapItem,
    class_def_map: MapItem,
    call_site_map: MapItem,
    method_handle_map: MapItem,
    code_map: MapItem,
    code_item_offsets: Vec<u32>,
    type_list_offsets: Vec<u32>,
    annotation_set_ref_list_offsets: Vec<u32>,
    annotation_set_offsets: Vec<u32>,
    annotations_directory_item_offsets: Vec<u32>,
    field_annotation_offsets: Vec<u32>,
    method_annotation_offsets: Vec<u32>,
    parameter_annotation_offsets: Vec<u32>,
}

fn get_item_base_size(kind: u16) -> usize {
    match kind {
        T_STRING_ID => 4,
        T_TYPE_ID => 4,
        T_PROTO_ID => 12,
        T_FIELD_ID => 8,
        T_METHOD_ID => 8,
        T_CLASS_DEF => 32,
        T_CALL_SITE_ID => 4,
        T_METHOD_HANDLE => 8,
        T_TYPE_LIST => 4,
        T_ANNOTATION_SET_REF_LIST => 4,
        T_ANNOTATION_SET_ITEM => 4,
        T_CODE_ITEM => CODE_ITEM_HEADER,
        T_ANNOTATIONS_DIRECTORY => 16,
        _ => 1,
    }
}

fn covers_array(image: &[u8], offset: usize, num: usize, elt_size: usize) -> bool {
    if elt_size == 0 {
        return false;
    }
    offset <= image.len() && (image.len() - offset) / elt_size >= num
}

impl DexDisassembler {
    pub fn parse(image: &[u8]) -> Option<Self> {
        let (file_size, map_off) = read_dex_header(image)?;
        let image = &image[..file_size as usize];

        let list_start = map_off as usize;
        let list_size = read_u32(image, list_start)?;
        if list_size > K_MAX_ITEM_LIST_SIZE {
            return None;
        }
        let items_start = list_start.checked_add(4)?;
        let items_end = items_start.checked_add(list_size as usize * MAP_ITEM_SIZE)?;
        if items_end > image.len() {
            return None;
        }
        let mut map: BTreeMap<u16, MapItem> = BTreeMap::new();
        for index in 0..list_size as usize {
            let base = items_start + index * MAP_ITEM_SIZE;
            let kind = read_u16(image, base)?;
            let size = read_u32(image, base + 4)?;
            let offset = read_u32(image, base + 8)?;
            let item_size = get_item_base_size(kind);
            if !covers_array(image, offset as usize, size as usize, item_size) {
                return None;
            }
            if map.insert(kind, MapItem { size, offset }).is_some() {
                return None;
            }
        }

        let get = |kind: u16| *map.get(&kind).unwrap_or(&MapItem::default());

        let type_list_map = get(T_TYPE_LIST);
        let annotation_set_ref_map = get(T_ANNOTATION_SET_REF_LIST);
        let annotation_set_map = get(T_ANNOTATION_SET_ITEM);
        let annotations_directory_map = get(T_ANNOTATIONS_DIRECTORY);
        let code_map = get(T_CODE_ITEM);

        let type_list_offsets = parse_item_offsets(image, type_list_map, 2)?;
        let annotation_set_ref_list_offsets =
            parse_item_offsets(image, annotation_set_ref_map, 4)?;
        let annotation_set_offsets = parse_item_offsets(image, annotation_set_map, 4)?;
        let (
            annotations_directory_item_offsets,
            field_annotation_offsets,
            method_annotation_offsets,
            parameter_annotation_offsets,
        ) = parse_annotations_directory_items(image, annotations_directory_map)?;

        let code_item_offsets = parse_code_item_offsets(image, code_map)?;
        if code_item_offsets.is_empty() {
            return None;
        }

        Some(DexDisassembler {
            size: file_size,
            groups: build_groups(),
            string_map: get(T_STRING_ID),
            type_map: get(T_TYPE_ID),
            proto_map: get(T_PROTO_ID),
            field_map: get(T_FIELD_ID),
            method_map: get(T_METHOD_ID),
            class_def_map: get(T_CLASS_DEF),
            call_site_map: get(T_CALL_SITE_ID),
            method_handle_map: get(T_METHOD_HANDLE),
            code_map,
            code_item_offsets,
            type_list_offsets,
            annotation_set_ref_list_offsets,
            annotation_set_offsets,
            annotations_directory_item_offsets,
            field_annotation_offsets,
            method_annotation_offsets,
            parameter_annotation_offsets,
        })
    }
}

fn read_dex_header(image: &[u8]) -> Option<(u32, u32)> {
    if image.len() < HEADER_SIZE {
        return None;
    }
    let magic = &image[..8];
    if &magic[..4] != b"dex\n" || magic[7] != 0 {
        return None;
    }
    let mut version = 0u32;
    for &byte in &magic[4..7] {
        if !byte.is_ascii_digit() {
            return None;
        }
        version = version * 10 + u32::from(byte - b'0');
    }
    if !matches!(version, 35 | 37 | 38 | 39) {
        return None;
    }
    let file_size = read_u32(image, 32)?;
    let map_off = read_u32(image, 52)?;
    if file_size > image.len() as u32 || file_size < HEADER_SIZE as u32 || map_off < HEADER_SIZE as u32
    {
        return None;
    }
    Some((file_size, map_off))
}

fn parse_item_offsets(
    image: &[u8],
    map_item: MapItem,
    item_width: usize,
) -> Option<Vec<u32>> {
    if !covers_array(image, map_item.offset as usize, map_item.size as usize, 4) {
        return None;
    }
    let mut offsets = Vec::new();
    let mut pos = map_item.offset as usize;
    for _ in 0..map_item.size {
        // AlignOn(image, 4).
        let aligned = align_ceil(pos as u64, 4) as usize;
        if aligned > image.len() {
            return None;
        }
        pos = aligned;
        let count = read_u32(image, pos)? as usize;
        pos += 4;
        if (image.len() - pos) / item_width < count {
            return None;
        }
        for _ in 0..count {
            offsets.push(pos as u32);
            pos += item_width;
        }
    }
    Some(offsets)
}

fn parse_annotations_directory_items(
    image: &[u8],
    map_item: MapItem,
) -> Option<(Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>)> {
    if !covers_array(image, map_item.offset as usize, map_item.size as usize, 16) {
        return None;
    }
    let mut directory_offsets = Vec::new();
    let mut field_offsets = Vec::new();
    let mut method_offsets = Vec::new();
    let mut parameter_offsets = Vec::new();
    let mut pos = map_item.offset as usize;

    let mut parse_list = |pos: &mut usize, count: u32, width: usize, out: &mut Vec<u32>| -> Option<()> {
        if (image.len() - *pos) / width < count as usize {
            return None;
        }
        for _ in 0..count {
            out.push(*pos as u32);
            *pos += width;
        }
        Some(())
    };

    for _ in 0..map_item.size {
        let aligned = align_ceil(pos as u64, 4) as usize;
        if aligned > image.len() {
            return None;
        }
        pos = aligned;
        if pos + 16 > image.len() {
            return None;
        }
        directory_offsets.push(pos as u32);
        let class_annotations_off = read_u32(image, pos)?;
        let fields_size = read_u32(image, pos + 4)?;
        let methods_size = read_u32(image, pos + 8)?;
        let parameters_size = read_u32(image, pos + 12)?;
        let _ = class_annotations_off;
        pos += 16;
        parse_list(&mut pos, fields_size, 8, &mut field_offsets)?;
        parse_list(&mut pos, methods_size, 8, &mut method_offsets)?;
        parse_list(&mut pos, parameters_size, 8, &mut parameter_offsets)?;
    }
    Some((directory_offsets, field_offsets, method_offsets, parameter_offsets))
}

fn parse_code_item_offsets(image: &[u8], code_map: MapItem) -> Option<Vec<u32>> {
    if !covers_array(image, code_map.offset as usize, code_map.size as usize, CODE_ITEM_HEADER) {
        return None;
    }
    let mut parser = CodeItemParser::new(code_map.offset as usize);
    let mut offsets = Vec::with_capacity(code_map.size as usize);
    for _ in 0..code_map.size {
        offsets.push(parser.get_next(image)?);
    }
    Some(offsets)
}

struct CodeItemParser {
    pos: usize,
}

impl CodeItemParser {
    fn new(pos: usize) -> Self {
        Self { pos }
    }

    fn get_next(&mut self, image: &[u8]) -> Option<u32> {
        let aligned = align_ceil(self.pos as u64, 4) as usize;
        if aligned > image.len() {
            return None;
        }
        self.pos = aligned;
        let code_item_offset = self.pos;
        if self.pos + CODE_ITEM_HEADER > image.len() {
            return None;
        }
        let tries_size = read_u16(image, self.pos + 6)? as usize;
        let insns_size = read_u32(image, self.pos + 12)? as usize;
        self.pos += CODE_ITEM_HEADER;
        let insns_bytes = insns_size.checked_mul(2)?;
        self.pos = self.pos.checked_add(insns_bytes)?;
        if self.pos > image.len() {
            return None;
        }
        if tries_size > 0 {
            let aligned = align_ceil(self.pos as u64, 4) as usize;
            if aligned > image.len() {
                return None;
            }
            self.pos = aligned;
            self.pos = self.pos.checked_add(tries_size.checked_mul(8)?)?;
            if self.pos > image.len() {
                return None;
            }
            let handlers_size = get_uleb128(image, &mut self.pos)?;
            if image.len() - self.pos < handlers_size as usize {
                return None;
            }
            for _ in 0..handlers_size {
                let encoded_size = get_sleb128(image, &mut self.pos)?;
                let abs_size = encoded_size.unsigned_abs() as usize;
                if image.len() - self.pos < abs_size {
                    return None;
                }
                for _ in 0..abs_size {
                    if !skip_leb128(image, &mut self.pos) || !skip_leb128(image, &mut self.pos) {
                        return None;
                    }
                }
                if encoded_size <= 0 && !skip_leb128(image, &mut self.pos) {
                    return None;
                }
            }
        }
        Some(code_item_offset as u32)
    }
}

fn get_uleb128(image: &[u8], pos: &mut usize) -> Option<u32> {
    let limit = K_MAX_LEB128_SIZE.min(image.len() - *pos) * 7;
    let mut value = 0u32;
    let mut shift = 0usize;
    while shift < limit {
        let byte = *image.get(*pos)?;
        *pos += 1;
        value |= u32::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
    None
}

fn get_sleb128(image: &[u8], pos: &mut usize) -> Option<i32> {
    let limit = K_MAX_LEB128_SIZE.min(image.len() - *pos) * 7;
    let mut value: i32 = 0;
    let mut shift = 0usize;
    while shift < limit {
        let byte = *image.get(*pos)?;
        *pos += 1;
        value |= ((u32::from(byte & 0x7F)) << shift) as i32;
        if byte & 0x80 == 0 {
            return Some(if shift == 28 {
                value
            } else {
                let num_bits = 32i32;
                let s = num_bits - 1 - (shift as i32 + 6);
                (value << s) >> s
            });
        }
        shift += 7;
    }
    None
}

fn skip_leb128(image: &[u8], pos: &mut usize) -> bool {
    let limit = K_MAX_LEB128_SIZE.min(image.len() - *pos);
    for _ in 0..limit {
        let byte = match image.get(*pos) {
            Some(byte) => *byte,
            None => return false,
        };
        *pos += 1;
        if byte & 0x80 == 0 {
            return true;
        }
    }
    false
}

fn build_groups() -> Vec<GroupTraits> {
    const WIDTHS: [u32; 42] = [
        4, 4, 4, 4, 4, 2, 4, 4, 2, 2, 2, 4, 4, 2, 2, 2, 2, 2, 2, 4, 2, 2, 4, 4, 2, 2, 4, 4, 4,
        4, 4, 4, 4, 4, 1, 2, 4, 4, 4, 4, 4, 4,
    ];
    const POOLS: [u8; 42] = [
        0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 3, 3, 3, 4, 4, 4, 4, 5, 6, 7, 7, 8,
        9, 9, 9, 9, 10, 11, 11, 11, 12, 13, 14, 15, 16,
    ];
    (0..42)
        .map(|index| GroupTraits {
            width: WIDTHS[index],
            type_tag: index as u8,
            pool_tag: POOLS[index],
        })
        .collect()
}

// Readers.

#[derive(Clone, Copy)]
enum ItemMapper {
    TargetIndex { map: MapItem, item_size: u32, width: u8 },
    TargetOffset32,
    MethodHandle { map: MapItem, item_size: u32, min_type: u16, max_type: u16 },
}

#[derive(Clone, Copy)]
enum ListMapper {
    TargetIndex { map: MapItem, item_size: u32 },
    TargetOffset32,
}

#[derive(Clone, Copy)]
enum InstrMapper {
    TargetIndex { map: MapItem, item_size: u32, width: u8 },
    RelCode8,
    RelCode16,
    RelCode32,
}

#[derive(Clone, Copy, PartialEq)]
enum CodeFilter {
    String16,
    String32,
    Type,
    Proto,
    CallSite,
    MethodHandle,
    Field,
    Method,
    Rel8,
    Rel16,
    Rel32,
}

fn read_target_index(
    image: &[u8],
    map: MapItem,
    item_size: u32,
    location: u32,
    width: u8,
) -> u32 {
    let unsafe_idx = if width == 2 {
        u32::from(read_u16(image, location as usize).unwrap_or(0))
    } else {
        read_u32(image, location as usize).unwrap_or(0)
    };
    if width == 4 && unsafe_idx == SENTINEL_INDEX {
        return SENTINEL_INDEX;
    }
    if unsafe_idx >= map.size {
        return K_INVALID_OFFSET;
    }
    map.offset.wrapping_add(unsafe_idx.wrapping_mul(item_size))
}

fn read_target_offset32(image: &[u8], location: u32) -> u32 {
    let target = read_u32(image, location as usize).unwrap_or(0);
    if target == SENTINEL_OFFSET {
        return SENTINEL_OFFSET;
    }
    if target as usize >= image.len() {
        return K_INVALID_OFFSET;
    }
    target
}

fn read_method_handle_field_or_method_id(
    image: &[u8],
    map: MapItem,
    item_size: u32,
    min_type: u16,
    max_type: u16,
    location: u32,
) -> u32 {
    let method_handle_type = read_u16(image, location as usize).unwrap_or(0);
    if method_handle_type >= 0x09 {
        return K_INVALID_OFFSET;
    }
    if method_handle_type < min_type || method_handle_type > max_type {
        return SENTINEL_INDEX;
    }
    read_target_index(image, map, item_size, location + 4, 2)
}

fn run_item_mapper(mapper: ItemMapper, image: &[u8], input: u32) -> u32 {
    match mapper {
        ItemMapper::TargetIndex { map, item_size, width } => {
            read_target_index(image, map, item_size, input, width)
        }
        ItemMapper::TargetOffset32 => read_target_offset32(image, input),
        ItemMapper::MethodHandle { map, item_size, min_type, max_type } => {
            read_method_handle_field_or_method_id(image, map, item_size, min_type, max_type, input)
        }
    }
}

fn run_list_mapper(mapper: ListMapper, image: &[u8], location: u32) -> u32 {
    match mapper {
        ListMapper::TargetIndex { map, item_size } => {
            read_target_index(image, map, item_size, location, 2)
        }
        ListMapper::TargetOffset32 => read_target_offset32(image, location),
    }
}

fn item_reader(
    image: &[u8],
    lo: u32,
    hi: u32,
    map: MapItem,
    item_size: u32,
    rel_location: u32,
    mapper: ItemMapper,
    wants_item: bool,
) -> Vec<Reference> {
    let item_base_offset = map.offset;
    let num_items = map.size;
    let mapper_input_delta = if wants_item { 0 } else { rel_location };
    let offset_of_index = |index: u32| item_base_offset.wrapping_add(index.wrapping_mul(item_size));

    let mut cur_idx: u32;
    if item_base_offset == 0 {
        cur_idx = num_items;
    } else if lo < item_base_offset {
        cur_idx = 0;
    } else if lo < offset_of_index(num_items) {
        cur_idx = (lo - item_base_offset) / item_size;
        if lo > offset_of_index(cur_idx).wrapping_add(rel_location) {
            cur_idx += 1;
        }
    } else {
        cur_idx = num_items;
    }

    let mut result = Vec::new();
    while cur_idx < num_items {
        let item_offset = offset_of_index(cur_idx);
        let location = item_offset.wrapping_add(rel_location);
        if location >= hi {
            break;
        }
        let target = run_item_mapper(mapper, image, item_offset.wrapping_add(mapper_input_delta));
        if target == SENTINEL_OFFSET || target == SENTINEL_INDEX {
            cur_idx += 1;
            continue;
        }
        if target == K_INVALID_OFFSET {
            break;
        }
        cur_idx += 1;
        if location >= lo {
            result.push(Reference { location, target });
        }
    }
    result
}

fn cached_item_list_reader(
    image: &[u8],
    lo: u32,
    hi: u32,
    rel_location: u32,
    offsets: &[u32],
    mapper: ListMapper,
) -> Vec<Reference> {
    let mut index = offsets.partition_point(|offset| *offset <= lo);
    if index != 0 && offsets[index - 1].wrapping_add(rel_location) >= lo {
        index -= 1;
    }
    let mut result = Vec::new();
    while index < offsets.len() {
        let location = offsets[index].wrapping_add(rel_location);
        if location >= hi {
            break;
        }
        let target = run_list_mapper(mapper, image, location);
        if target == K_INVALID_OFFSET {
            break;
        }
        index += 1;
        if target == SENTINEL_OFFSET {
            continue;
        }
        result.push(Reference { location, target });
    }
    result
}

#[derive(Clone, Copy)]
struct InstructionValue {
    instr_offset: u32,
    opcode: u8,
    format: Format,
}

fn code_item_insns(image: &[u8], base_offset: u32) -> Option<(usize, usize)> {
    let base = base_offset as usize;
    if base + CODE_ITEM_HEADER > image.len() {
        return None;
    }
    let insns_size = read_u32(image, base + 12)? as usize;
    let start = base + CODE_ITEM_HEADER;
    let end = start.checked_add(insns_size.checked_mul(2)?)?;
    if end > image.len() {
        return None;
    }
    Some((start, end))
}

fn parse_instructions(image: &[u8], base_offset: u32) -> Vec<InstructionValue> {
    let Some((insns_start, insns_end)) = code_item_insns(image, base_offset) else {
        return Vec::new();
    };
    let mut pos = insns_start;
    let mut boundary = insns_end;
    let mut result = Vec::new();
    while pos < boundary {
        let opcode = image[pos];
        let Some(instruction) = find_instruction(opcode) else { break };
        let length_bytes = instruction.layout as usize * 2;
        if insns_end - pos < length_bytes {
            break;
        }
        if opcode == 0x26 || opcode == 0x2B || opcode == 0x2C {
            let payload_rel = read_i32(image, pos + 2).unwrap_or(0);
            if payload_rel < i32::from(instruction.layout)
                || payload_rel as u32 >= (insns_end - insns_start) as u32 / 2
            {
                break;
            }
            boundary = boundary.min(pos + payload_rel as usize * 2);
        }
        result.push(InstructionValue {
            instr_offset: pos as u32,
            opcode,
            format: instruction.format,
        });
        pos += length_bytes;
    }
    result
}

fn filter_location(filter: CodeFilter, value: InstructionValue) -> Option<u32> {
    let format_c = value.format == Format::C;
    let format_t = value.format == Format::T;
    let location = match filter {
        CodeFilter::String16 if format_c && value.opcode == 0x1A => value.instr_offset + 2,
        CodeFilter::String32 if format_c && value.opcode == 0x1B => value.instr_offset + 2,
        CodeFilter::Type
            if format_c
                && matches!(value.opcode, 0x1C | 0x1F | 0x20 | 0x22 | 0x23 | 0x24 | 0x25) =>
        {
            value.instr_offset + 2
        }
        CodeFilter::Proto if format_c && matches!(value.opcode, 0xFA | 0xFB) => {
            value.instr_offset + 6
        }
        CodeFilter::Proto if format_c && value.opcode == 0xFF => value.instr_offset + 2,
        CodeFilter::CallSite if format_c && matches!(value.opcode, 0xFC | 0xFD) => {
            value.instr_offset + 2
        }
        CodeFilter::MethodHandle if format_c && value.opcode == 0xFE => value.instr_offset + 2,
        CodeFilter::Field if format_c && matches!(value.opcode, 0x52 | 0x60) => {
            value.instr_offset + 2
        }
        CodeFilter::Method
            if format_c && matches!(value.opcode, 0x6E | 0x74 | 0xFA | 0xFB) =>
        {
            value.instr_offset + 2
        }
        CodeFilter::Rel8 if format_t && value.opcode == 0x28 => value.instr_offset + 1,
        CodeFilter::Rel16 if format_t && matches!(value.opcode, 0x29 | 0x32 | 0x38) => {
            value.instr_offset + 2
        }
        CodeFilter::Rel32 if format_t && matches!(value.opcode, 0x26 | 0x2A | 0x2B | 0x2C) => {
            value.instr_offset + 2
        }
        _ => return None,
    };
    Some(location)
}

fn run_instr_mapper(mapper: InstrMapper, image: &[u8], location: u32) -> u32 {
    match mapper {
        InstrMapper::TargetIndex { map, item_size, width } => {
            read_target_index(image, map, item_size, location, width)
        }
        InstrMapper::RelCode8 => {
            let delta = read_i8(image, location as usize).unwrap_or(0) as i32;
            location.wrapping_add((delta - 1).wrapping_mul(2) as u32)
        }
        InstrMapper::RelCode16 => {
            let delta = read_i16(image, location as usize).unwrap_or(0) as i32;
            location.wrapping_add((delta - 1).wrapping_mul(2) as u32)
        }
        InstrMapper::RelCode32 => {
            let delta = read_i32(image, location as usize).unwrap_or(0);
            let target = i64::from(location) + i64::from(delta - 1) * 2;
            if !(0..=u32::MAX as i64).contains(&target) || target >= i64::from(OFFSET_BOUND as u32) {
                K_INVALID_OFFSET
            } else {
                target as u32
            }
        }
    }
}

fn instruction_reader(
    image: &[u8],
    lo: u32,
    hi: u32,
    code_item_offsets: &[u32],
    filter: CodeFilter,
    mapper: InstrMapper,
) -> Vec<Reference> {
    if code_item_offsets.is_empty() {
        return Vec::new();
    }
    let mut index = code_item_offsets.partition_point(|offset| *offset <= lo);
    if index != 0 {
        index -= 1;
    }
    let mut result = Vec::new();
    loop {
        for value in parse_instructions(image, code_item_offsets[index]) {
            if value.instr_offset >= hi {
                return result;
            }
            let Some(location) = filter_location(filter, value) else { continue };
            if location == K_INVALID_OFFSET || location < lo {
                continue;
            }
            if location >= hi {
                return result;
            }
            let target = run_instr_mapper(mapper, image, location);
            if target != K_INVALID_OFFSET {
                result.push(Reference { location, target });
            }
        }
        index += 1;
        if index >= code_item_offsets.len() {
            return result;
        }
    }
}

// Writers.

#[derive(Clone, Copy)]
enum WriteKind {
    StringId16,
    StringId32,
    TypeId16,
    TypeId32,
    ProtoId16,
    FieldId16,
    FieldId32,
    MethodId16,
    MethodId32,
    CallSiteId16,
    MethodHandle16,
    Abs32,
    RelCode8,
    RelCode16,
    RelCode32,
}

fn write_kind(group: usize) -> WriteKind {
    match group {
        0 | 1 | 2 | 3 | 4 | 6 => WriteKind::StringId32,
        5 => WriteKind::StringId16,
        7 | 11 | 12 => WriteKind::TypeId32,
        8 | 9 | 10 | 13 | 14 => WriteKind::TypeId16,
        15 | 16 => WriteKind::ProtoId16,
        17 | 18 => WriteKind::FieldId16,
        19 => WriteKind::FieldId32,
        20 | 21 => WriteKind::MethodId16,
        22 | 23 => WriteKind::MethodId32,
        24 => WriteKind::CallSiteId16,
        25 => WriteKind::MethodHandle16,
        34 => WriteKind::RelCode8,
        35 => WriteKind::RelCode16,
        36 => WriteKind::RelCode32,
        _ => WriteKind::Abs32,
    }
}

impl DexDisassembler {
    fn write_target_index(
        &self,
        image: &mut [u8],
        map: MapItem,
        item_size: u32,
        reference: Reference,
        width: u8,
    ) {
        let unsafe_idx = reference.target.wrapping_sub(map.offset) / item_size;
        if unsafe_idx >= map.size {
            return;
        }
        if width == 2 {
            let _ = write_u16(image, reference.location as usize, unsafe_idx as u16);
        } else {
            let _ = write_u32(image, reference.location as usize, unsafe_idx);
        }
    }
}

impl Disassembler for DexDisassembler {
    fn size(&self) -> u32 {
        self.size
    }

    fn groups(&self) -> &[GroupTraits] {
        &self.groups
    }

    #[allow(clippy::too_many_lines)]
    fn read(&self, group: usize, image: &[u8], lo: u32, hi: u32) -> Vec<Reference> {
        let string_index = |width: u8| ItemMapper::TargetIndex {
            map: self.string_map,
            item_size: 4,
            width,
        };
        let type_index = |width: u8| ItemMapper::TargetIndex {
            map: self.type_map,
            item_size: 4,
            width,
        };
        let proto_index = ItemMapper::TargetIndex { map: self.proto_map, item_size: 12, width: 2 };
        match group {
            0 => item_reader(image, lo, hi, self.type_map, 4, 0, string_index(2), false),
            1 => item_reader(image, lo, hi, self.proto_map, 12, 0, string_index(4), false),
            2 => item_reader(image, lo, hi, self.field_map, 8, 4, string_index(4), false),
            3 => item_reader(image, lo, hi, self.method_map, 8, 4, string_index(4), false),
            4 => item_reader(image, lo, hi, self.class_def_map, 32, 16, string_index(4), false),
            5 => instruction_reader(
                image,
                lo,
                hi,
                &self.code_item_offsets,
                CodeFilter::String16,
                InstrMapper::TargetIndex { map: self.string_map, item_size: 4, width: 2 },
            ),
            6 => instruction_reader(
                image,
                lo,
                hi,
                &self.code_item_offsets,
                CodeFilter::String32,
                InstrMapper::TargetIndex { map: self.string_map, item_size: 4, width: 4 },
            ),
            7 => item_reader(image, lo, hi, self.proto_map, 12, 4, type_index(4), false),
            8 => item_reader(image, lo, hi, self.field_map, 8, 0, type_index(2), false),
            9 => item_reader(image, lo, hi, self.field_map, 8, 2, type_index(2), false),
            10 => item_reader(image, lo, hi, self.method_map, 8, 0, type_index(2), false),
            11 => item_reader(image, lo, hi, self.class_def_map, 32, 0, type_index(4), false),
            12 => item_reader(image, lo, hi, self.class_def_map, 32, 8, type_index(4), false),
            13 => cached_item_list_reader(
                image,
                lo,
                hi,
                0,
                &self.type_list_offsets,
                ListMapper::TargetIndex { map: self.type_map, item_size: 4 },
            ),
            14 => instruction_reader(
                image,
                lo,
                hi,
                &self.code_item_offsets,
                CodeFilter::Type,
                InstrMapper::TargetIndex { map: self.type_map, item_size: 4, width: 2 },
            ),
            15 => instruction_reader(
                image,
                lo,
                hi,
                &self.code_item_offsets,
                CodeFilter::Proto,
                InstrMapper::TargetIndex { map: self.proto_map, item_size: 12, width: 2 },
            ),
            16 => item_reader(image, lo, hi, self.method_map, 8, 2, proto_index, false),
            17 => instruction_reader(
                image,
                lo,
                hi,
                &self.code_item_offsets,
                CodeFilter::Field,
                InstrMapper::TargetIndex { map: self.field_map, item_size: 8, width: 2 },
            ),
            18 => item_reader(
                image,
                lo,
                hi,
                self.method_handle_map,
                8,
                2,
                ItemMapper::MethodHandle {
                    map: self.field_map,
                    item_size: 8,
                    min_type: 0,
                    max_type: 3,
                },
                true,
            ),
            19 => cached_item_list_reader(
                image,
                lo,
                hi,
                0,
                &self.field_annotation_offsets,
                ListMapper::TargetIndex { map: self.field_map, item_size: 8 },
            ),
            20 => instruction_reader(
                image,
                lo,
                hi,
                &self.code_item_offsets,
                CodeFilter::Method,
                InstrMapper::TargetIndex { map: self.method_map, item_size: 8, width: 2 },
            ),
            21 => item_reader(
                image,
                lo,
                hi,
                self.method_handle_map,
                8,
                2,
                ItemMapper::MethodHandle {
                    map: self.method_map,
                    item_size: 8,
                    min_type: 4,
                    max_type: 8,
                },
                true,
            ),
            22 => cached_item_list_reader(
                image,
                lo,
                hi,
                0,
                &self.method_annotation_offsets,
                ListMapper::TargetIndex { map: self.method_map, item_size: 8 },
            ),
            23 => cached_item_list_reader(
                image,
                lo,
                hi,
                0,
                &self.parameter_annotation_offsets,
                ListMapper::TargetIndex { map: self.method_map, item_size: 8 },
            ),
            24 => instruction_reader(
                image,
                lo,
                hi,
                &self.code_item_offsets,
                CodeFilter::CallSite,
                InstrMapper::TargetIndex { map: self.call_site_map, item_size: 4, width: 2 },
            ),
            25 => instruction_reader(
                image,
                lo,
                hi,
                &self.code_item_offsets,
                CodeFilter::MethodHandle,
                InstrMapper::TargetIndex { map: self.method_handle_map, item_size: 8, width: 2 },
            ),
            26 => item_reader(image, lo, hi, self.proto_map, 12, 8, ItemMapper::TargetOffset32, false),
            27 => item_reader(
                image,
                lo,
                hi,
                self.class_def_map,
                32,
                12,
                ItemMapper::TargetOffset32,
                false,
            ),
            28 => cached_item_list_reader(
                image,
                lo,
                hi,
                4,
                &self.parameter_annotation_offsets,
                ListMapper::TargetOffset32,
            ),
            29 => cached_item_list_reader(
                image,
                lo,
                hi,
                0,
                &self.annotation_set_ref_list_offsets,
                ListMapper::TargetOffset32,
            ),
            30 => cached_item_list_reader(
                image,
                lo,
                hi,
                0,
                &self.annotations_directory_item_offsets,
                ListMapper::TargetOffset32,
            ),
            31 => cached_item_list_reader(
                image,
                lo,
                hi,
                4,
                &self.field_annotation_offsets,
                ListMapper::TargetOffset32,
            ),
            32 => cached_item_list_reader(
                image,
                lo,
                hi,
                4,
                &self.method_annotation_offsets,
                ListMapper::TargetOffset32,
            ),
            33 => item_reader(
                image,
                lo,
                hi,
                self.class_def_map,
                32,
                24,
                ItemMapper::TargetOffset32,
                false,
            ),
            34 => instruction_reader(
                image,
                lo,
                hi,
                &self.code_item_offsets,
                CodeFilter::Rel8,
                InstrMapper::RelCode8,
            ),
            35 => instruction_reader(
                image,
                lo,
                hi,
                &self.code_item_offsets,
                CodeFilter::Rel16,
                InstrMapper::RelCode16,
            ),
            36 => instruction_reader(
                image,
                lo,
                hi,
                &self.code_item_offsets,
                CodeFilter::Rel32,
                InstrMapper::RelCode32,
            ),
            37 => item_reader(image, lo, hi, self.string_map, 4, 0, ItemMapper::TargetOffset32, false),
            38 => cached_item_list_reader(
                image,
                lo,
                hi,
                0,
                &self.annotation_set_offsets,
                ListMapper::TargetOffset32,
            ),
            39 => item_reader(
                image,
                lo,
                hi,
                self.class_def_map,
                32,
                28,
                ItemMapper::TargetOffset32,
                false,
            ),
            40 => item_reader(
                image,
                lo,
                hi,
                self.class_def_map,
                32,
                20,
                ItemMapper::TargetOffset32,
                false,
            ),
            41 => item_reader(
                image,
                lo,
                hi,
                self.call_site_map,
                4,
                0,
                ItemMapper::TargetOffset32,
                false,
            ),
            _ => Vec::new(),
        }
    }

    fn write(&self, group: usize, image: &mut [u8], reference: Reference) {
        match write_kind(group) {
            WriteKind::StringId16 => {
                self.write_target_index(image, self.string_map, 4, reference, 2);
            }
            WriteKind::StringId32 => {
                self.write_target_index(image, self.string_map, 4, reference, 4);
            }
            WriteKind::TypeId16 => {
                self.write_target_index(image, self.type_map, 4, reference, 2);
            }
            WriteKind::TypeId32 => {
                self.write_target_index(image, self.type_map, 4, reference, 4);
            }
            WriteKind::ProtoId16 => {
                self.write_target_index(image, self.proto_map, 12, reference, 2);
            }
            WriteKind::FieldId16 => {
                self.write_target_index(image, self.field_map, 8, reference, 2);
            }
            WriteKind::FieldId32 => {
                self.write_target_index(image, self.field_map, 8, reference, 4);
            }
            WriteKind::MethodId16 => {
                self.write_target_index(image, self.method_map, 8, reference, 2);
            }
            WriteKind::MethodId32 => {
                self.write_target_index(image, self.method_map, 8, reference, 4);
            }
            WriteKind::CallSiteId16 => {
                self.write_target_index(image, self.call_site_map, 4, reference, 2);
            }
            WriteKind::MethodHandle16 => {
                self.write_target_index(image, self.method_handle_map, 8, reference, 2);
            }
            WriteKind::Abs32 => {
                let _ = write_u32(image, reference.location as usize, reference.target);
            }
            WriteKind::RelCode8 => {
                let diff = reference.target as i64 - i64::from(reference.location);
                let delta = diff / 2 + 1;
                if i8::try_from(delta).is_ok() {
                    if let Some(slot) = image.get_mut(reference.location as usize) {
                        *slot = delta as i8 as u8;
                    }
                }
            }
            WriteKind::RelCode16 => {
                let diff = reference.target as i64 - i64::from(reference.location);
                let delta = diff / 2 + 1;
                if i16::try_from(delta).is_ok() {
                    let _ = write_u16(image, reference.location as usize, delta as i16 as u16);
                }
            }
            WriteKind::RelCode32 => {
                let diff = reference.target as i64 - i64::from(reference.location);
                let delta = diff / 2 + 1;
                if i32::try_from(delta).is_ok() {
                    let _ = write_u32(image, reference.location as usize, delta as i32 as u32);
                }
            }
        }
    }
}
