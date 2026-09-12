#include "zucchini_ffi.h"

#include <stdint.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <vector>

#include "components/zucchini/disassembler.h"
#include "components/zucchini/disassembler_dex.h"
#include "components/zucchini/element_detection.h"
#include "components/zucchini/equivalence_map.h"
#include "components/zucchini/image_utils.h"
#include "components/zucchini/patch_reader.h"
#include "components/zucchini/target_pool.h"
#include "components/zucchini/type_dex.h"
#include "components/zucchini/type_elf.h"
#include "components/zucchini/zucchini_apply.h"

namespace {

otadump_zucchini_result Error(otadump_zucchini_status status, const char* error) {
  return {status, error};
}

bool RangeIsRepresentable(const uint8_t* data, size_t size) {
  uintptr_t begin = reinterpret_cast<uintptr_t>(data);
  return size <= std::numeric_limits<uintptr_t>::max() - begin;
}

bool RangesOverlap(const uint8_t* left,
                   size_t left_size,
                   const uint8_t* right,
                   size_t right_size) {
  if (!left_size || !right_size)
    return false;
  uintptr_t left_begin = reinterpret_cast<uintptr_t>(left);
  uintptr_t right_begin = reinterpret_cast<uintptr_t>(right);
  return left_begin < right_begin + right_size &&
         right_begin < left_begin + left_size;
}

bool IsAndroidExecutable(zucchini::ExecutableType exe_type) {
  return exe_type == zucchini::kExeTypeDex ||
         exe_type == zucchini::kExeTypeElfX86 ||
         exe_type == zucchini::kExeTypeElfX64 ||
         exe_type == zucchini::kExeTypeElfAArch32 ||
         exe_type == zucchini::kExeTypeElfAArch64;
}

bool ReadDexMapItem(zucchini::ConstBufferView image,
                    uint16_t type,
                    zucchini::dex::MapItem* result) {
  using Header = zucchini::dex::HeaderItem;
  using MapItem = zucchini::dex::MapItem;
  if (!image.can_access<Header>(0))
    return false;
  Header header;
  std::memcpy(&header, image.begin(), sizeof(header));
  if (!image.can_access<uint32_t>(header.map_off))
    return false;
  uint32_t count = 0;
  std::memcpy(&count, image.begin() + header.map_off, sizeof(count));
  size_t items_offset = header.map_off + sizeof(count);
  if (!image.covers_array(items_offset, count, sizeof(MapItem)))
    return false;
  for (uint32_t index = 0; index < count; ++index) {
    MapItem item;
    std::memcpy(&item, image.begin() + items_offset + index * sizeof(item),
                sizeof(item));
    if (item.type == type) {
      *result = item;
      return true;
    }
  }
  return false;
}

bool ValidateDexWriterWidths(zucchini::ConstBufferView image) {
  const uint16_t narrow_types[] = {
      zucchini::dex::kTypeTypeIdItem,
      zucchini::dex::kTypeProtoIdItem,
      zucchini::dex::kTypeFieldIdItem,
      zucchini::dex::kTypeMethodIdItem,
      zucchini::dex::kTypeCallSiteIdItem,
      zucchini::dex::kTypeMethodHandleItem,
  };
  for (uint16_t type : narrow_types) {
    zucchini::dex::MapItem item;
    if (ReadDexMapItem(image, type, &item) &&
        item.size > static_cast<uint32_t>(UINT16_MAX) + 1) {
      return false;
    }
  }
  return true;
}

bool ValidateDexReferenceTargets(
    const zucchini::PatchElementReader& element,
    zucchini::Disassembler* old_disasm,
    zucchini::Disassembler* new_disasm,
    size_t old_size,
    size_t new_size,
    zucchini::ConstBufferView new_image) {
  zucchini::dex::MapItem string_ids;
  if (!ReadDexMapItem(new_image, zucchini::dex::kTypeStringIdItem,
                      &string_ids)) {
    return false;
  }

  zucchini::ReferenceDeltaSource deltas = element.GetReferenceDeltaSource();
  std::map<zucchini::PoolTag, std::vector<zucchini::ReferenceGroup>> pools;
  for (const auto& group : old_disasm->MakeReferenceGroups())
    pools[group.pool_tag()].push_back(group);
  std::vector<zucchini::ReferenceGroup> new_groups =
      new_disasm->MakeReferenceGroups();
  zucchini::OffsetMapper mapper(
      element.GetEquivalenceSource(),
      base::checked_cast<zucchini::offset_t>(old_size),
      base::checked_cast<zucchini::offset_t>(new_size));

  for (const auto& pool : pools) {
    zucchini::TargetPool targets;
    for (zucchini::ReferenceGroup group : pool.second)
      targets.InsertTargets(std::move(*group.GetReader(old_disasm)));
    targets.FilterAndProject(mapper);

    zucchini::TargetSource extras = element.GetExtraTargetSource(pool.first);
    targets.InsertTargets(&extras);
    if (!extras.Done())
      return false;

    for (const zucchini::ReferenceGroup& group : pool.second) {
      if (group.type_tag().value() >= new_groups.size())
        return false;
      zucchini::EquivalenceSource equivalences =
          element.GetEquivalenceSource();
      for (auto equivalence = equivalences.GetNext(); equivalence.has_value();
           equivalence = equivalences.GetNext()) {
        std::unique_ptr<zucchini::ReferenceReader> references =
            group.GetReader(equivalence->src_offset, equivalence->src_end(),
                            old_disasm);
        for (auto reference = references->GetNext(); reference.has_value();
             reference = references->GetNext()) {
          zucchini::offset_t projected =
              mapper.ExtendedForwardProject(reference->target);
          zucchini::key_t expected = targets.KeyForNearestOffset(projected);
          std::optional<int32_t> delta = deltas.GetNext();
          if (!delta.has_value())
            return false;
          int64_t key = static_cast<int64_t>(expected) + delta.value();
          if (key < 0 || key > UINT32_MAX ||
              !targets.KeyIsValid(static_cast<zucchini::key_t>(key))) {
            return false;
          }
          if (group.type_tag().value() ==
              zucchini::DisassemblerDex::kCodeToStringId16) {
            zucchini::offset_t target =
                targets.OffsetForKey(static_cast<zucchini::key_t>(key));
            if (target < string_ids.offset ||
                (target - string_ids.offset) %
                        sizeof(zucchini::dex::StringIdItem) !=
                    0 ||
                (target - string_ids.offset) /
                        sizeof(zucchini::dex::StringIdItem) >
                    UINT16_MAX) {
              return false;
            }
          }
        }
      }
    }
  }
  return deltas.Done();
}

bool ValidateReferenceBoundaries(
    const zucchini::PatchElementReader& element,
    zucchini::Disassembler* old_disasm,
    zucchini::ExecutableType exe_type,
    size_t new_size) {
  std::vector<zucchini::offset_t> boundaries;
  std::vector<zucchini::Equivalence> parsed_equivalences;
  zucchini::EquivalenceSource equivalences = element.GetEquivalenceSource();
  for (auto equivalence = equivalences.GetNext(); equivalence.has_value();
       equivalence = equivalences.GetNext()) {
    boundaries.push_back(equivalence->src_offset);
    boundaries.push_back(equivalence->src_end());
    parsed_equivalences.push_back(*equivalence);
  }
  std::sort(boundaries.begin(), boundaries.end());

  for (const auto& group : old_disasm->MakeReferenceGroups()) {
    size_t writer_width = group.width();
    if (group.type_tag().value() == 0) {
      if (exe_type == zucchini::kExeTypeElfX86 ||
          exe_type == zucchini::kExeTypeElfAArch32) {
        writer_width = sizeof(zucchini::elf::Elf32_Rel);
      } else if (exe_type == zucchini::kExeTypeElfX64 ||
                 exe_type == zucchini::kExeTypeElfAArch64) {
        writer_width = sizeof(zucchini::elf::Elf64_Rel);
      }
    }

    std::unique_ptr<zucchini::ReferenceReader> reader =
        group.GetReader(old_disasm);
    for (auto reference = reader->GetNext(); reference.has_value();
         reference = reader->GetNext()) {
      auto boundary =
          std::upper_bound(boundaries.begin(), boundaries.end(),
                           reference->location);
      if (boundary != boundaries.end() &&
          *boundary < reference->location + group.width()) {
        return false;
      }
    }

    // Upstream creates a fresh ranged reader for each equivalence. Mirror
    // those reads so an invalid target before a later equivalence cannot hide
    // a reference whose source or projected writer body crosses a boundary.
    for (const auto& equivalence : parsed_equivalences) {
      std::unique_ptr<zucchini::ReferenceReader> ranged_reader =
          group.GetReader(equivalence.src_offset, equivalence.src_end(),
                          old_disasm);
      for (auto reference = ranged_reader->GetNext(); reference.has_value();
           reference = ranged_reader->GetNext()) {
        if (reference->location < equivalence.src_offset ||
            reference->location > equivalence.src_end() ||
            group.width() > equivalence.src_end() - reference->location) {
          return false;
        }
        size_t projected = equivalence.dst_offset +
                           reference->location - equivalence.src_offset;
        if (projected > new_size || writer_width > new_size - projected)
          return false;
      }
    }
  }
  return true;
}

bool PreflightAndroidElements(
    zucchini::ConstBufferView old_image,
    const zucchini::EnsemblePatchReader& patch,
    zucchini::MutableBufferView new_image) {
  if (!patch.CheckOldFile(old_image))
    return false;
  for (const auto& element : patch.elements()) {
    zucchini::ExecutableType exe_type = element.element_match().exe_type();
    if (!IsAndroidExecutable(exe_type))
      continue;
    zucchini::ConstBufferView old_element = old_image[element.old_element()];
    zucchini::MutableBufferView new_element = new_image[element.new_element()];
    if (!zucchini::ApplyEquivalenceAndExtraData(old_element, element,
                                                 new_element) ||
        !zucchini::ApplyRawDelta(element, new_element)) {
      return false;
    }
    auto old_disasm = zucchini::MakeDisassemblerOfType(old_element, exe_type);
    auto new_disasm = zucchini::MakeDisassemblerOfType(
        zucchini::ConstBufferView(new_element), exe_type);
    if (!old_disasm || !new_disasm ||
        old_disasm->size() != old_element.size() ||
        new_disasm->size() != new_element.size() ||
        !ValidateReferenceBoundaries(element, old_disasm.get(), exe_type,
                                     new_element.size())) {
      return false;
    }
    if (exe_type == zucchini::kExeTypeDex) {
      if (!ValidateDexWriterWidths(zucchini::ConstBufferView(new_element)) ||
          !ValidateDexReferenceTargets(
              element, old_disasm.get(), new_disasm.get(), old_element.size(),
              new_element.size(), zucchini::ConstBufferView(new_element))) {
        return false;
      }
    }
  }
  return true;
}

}  // namespace

extern "C" otadump_zucchini_result otadump_zucchini_apply(
    const uint8_t* old_data,
    size_t old_size,
    const uint8_t* patch_data,
    size_t patch_size,
    uint8_t* new_data,
    size_t new_size) {
  if ((!old_data && old_size) || (!patch_data && patch_size) ||
      (!new_data && new_size)) {
    return Error(OTADUMP_ZUCCHINI_INVALID_ARGUMENT, "null non-empty buffer");
  }
  if (!RangeIsRepresentable(old_data, old_size) ||
      !RangeIsRepresentable(patch_data, patch_size) ||
      !RangeIsRepresentable(new_data, new_size)) {
    return Error(OTADUMP_ZUCCHINI_INVALID_ARGUMENT, "buffer range wraps");
  }
  if (RangesOverlap(new_data, new_size, old_data, old_size) ||
      RangesOverlap(new_data, new_size, patch_data, patch_size)) {
    return Error(OTADUMP_ZUCCHINI_INVALID_ARGUMENT,
                 "output overlaps an input buffer");
  }
  if (old_size >= zucchini::kOffsetBound || new_size >= zucchini::kOffsetBound) {
    return Error(OTADUMP_ZUCCHINI_INVALID_ARGUMENT,
                 "image exceeds Zucchini offset bound");
  }

  // BufferView performs pointer arithmetic in its constructor. Normalize
  // empty null buffers to a valid one-past-capable address.
  static const uint8_t empty_input = 0;
  static uint8_t empty_output = 0;
  old_data = old_data ? old_data : &empty_input;
  patch_data = patch_data ? patch_data : &empty_input;
  new_data = new_data ? new_data : &empty_output;

  auto patch = zucchini::EnsemblePatchReader::Create(
      zucchini::ConstBufferView(patch_data, patch_size));
  if (!patch) {
    return Error(OTADUMP_ZUCCHINI_INVALID_PATCH, "invalid ensemble patch");
  }
  if (patch->header().new_size != new_size) {
    return Error(OTADUMP_ZUCCHINI_WRONG_OUTPUT_SIZE,
                 "output buffer size does not match patch");
  }

  for (const auto& element : patch->elements()) {
    const zucchini::ExecutableType exe_type =
        element.element_match().exe_type();
    if (exe_type != zucchini::kExeTypeNoOp && !IsAndroidExecutable(exe_type)) {
      return Error(OTADUMP_ZUCCHINI_UNSUPPORTED_ELEMENT,
                    "element format is not enabled by Android");
    }
  }

  if (!PreflightAndroidElements(
          zucchini::ConstBufferView(old_data, old_size), *patch,
          zucchini::MutableBufferView(new_data, new_size))) {
    return Error(OTADUMP_ZUCCHINI_APPLY_ERROR,
                 "android executable preflight failed");
  }

  zucchini::status::Code status = zucchini::ApplyBuffer(
      zucchini::ConstBufferView(old_data, old_size), *patch,
      zucchini::MutableBufferView(new_data, new_size));
  if (status != zucchini::status::kStatusSuccess) {
    return Error(OTADUMP_ZUCCHINI_APPLY_ERROR, "zucchini apply failed");
  }
  return {OTADUMP_ZUCCHINI_OK, nullptr};
}
