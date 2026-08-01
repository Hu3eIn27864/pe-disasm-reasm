#!/usr/bin/env python3
"""Reassemble a 32-bit x86 PE executable from an original EXE or from a disassembly listing."""

import argparse
import os
import re
import shutil
import struct
import sys

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_32
except ImportError:
    Ks = None

IMAGE_DOS_SIGNATURE = b"MZ"
IMAGE_NT_SIGNATURE = b"PE\x00\x00"
IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_SIZEOF_SECTION_HEADER = 40
DEFAULT_IMAGE_BASE = 0x400000
DEFAULT_SECTION_ALIGNMENT = 0x1000
DEFAULT_FILE_ALIGNMENT = 0x200


def align(value, alignment):
    return ((value + alignment - 1) // alignment) * alignment


def parse_pe(data):
    if len(data) < 0x40 or data[:2] != IMAGE_DOS_SIGNATURE:
        raise ValueError("Not a valid DOS header / PE file")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew + 4] != IMAGE_NT_SIGNATURE:
        raise ValueError("Not a valid PE header")

    file_header_offset = e_lfanew + 4
    NumberOfSections = struct.unpack_from("<H", data, file_header_offset + 2)[0]
    SizeOfOptionalHeader = struct.unpack_from("<H", data, file_header_offset + 16)[0]
    optional_header_offset = file_header_offset + 20
    section_table_offset = optional_header_offset + SizeOfOptionalHeader

    sections = []
    for i in range(NumberOfSections):
        offset = section_table_offset + i * IMAGE_SIZEOF_SECTION_HEADER
        if offset + IMAGE_SIZEOF_SECTION_HEADER > len(data):
            break
        name = data[offset:offset + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
        VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, _, _, _, _, Characteristics = struct.unpack_from(
            "<IIIIIIHHI", data, offset + 8
        )
        sections.append({
            "name": name,
            "virtual_size": VirtualSize,
            "virtual_address": VirtualAddress,
            "raw_size": SizeOfRawData,
            "raw_ptr": PointerToRawData,
            "characteristics": Characteristics,
        })

    return sections


def parse_bytes_comment(comment):
    raw_bytes = []
    for token in comment.replace(',', ' ').split():
        token = token.strip()
        if not token:
            continue
        if token.startswith("0x"):
            raw_bytes.append(int(token, 16))
        elif len(token) == 2 and all(c in "0123456789abcdefABCDEF" for c in token):
            raw_bytes.append(int(token, 16))
        else:
            return None
    return raw_bytes


def parse_db_bytes(text):
    raw_bytes = []
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        if token.startswith("0x"):
            raw_bytes.append(int(token, 16))
        elif token.isdigit() or (token.startswith("-") and token[1:].isdigit()):
            raw_bytes.append(int(token) & 0xFF)
        else:
            return None
    return raw_bytes


def parse_disasm_listing(path, image_base=DEFAULT_IMAGE_BASE):
    sections = []
    current_section = None

    section_marker = re.compile(
        r"^;\s*SECTION\s+(\S+).*?raw_offset=0x([0-9A-Fa-f]+).*?raw_size=0x([0-9A-Fa-f]+).*?va=0x([0-9A-Fa-f]+)"
    )
    line_pattern = re.compile(r"^\s*0x([0-9A-Fa-f]+):\s*(.*)$")
    db_line = re.compile(r"^db\s+(.*)$", re.IGNORECASE)

    def start_section(name, virtual_address, raw_offset, raw_size):
        nonlocal current_section
        current_section = {
            "name": name,
            "va": virtual_address,
            "raw_offset": raw_offset,
            "raw_size": raw_size,
            "entries": [],
        }
        sections.append(current_section)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue

            marker = section_marker.match(line)
            if marker:
                name = marker.group(1)
                raw_offset = int(marker.group(2), 16)
                raw_size = int(marker.group(3), 16)
                va = int(marker.group(4), 16)
                if va >= image_base:
                    va -= image_base
                start_section(name, va, raw_offset, raw_size)
                continue

            line_match = line_pattern.match(line)
            if not line_match:
                continue

            addr = int(line_match.group(1), 16)
            payload = line_match.group(2).strip()
            comment_split = payload.split(";", 1)
            opcode_part = comment_split[0].strip()
            comment_part = comment_split[1].strip() if len(comment_split) > 1 else None
            raw_bytes = None
            if comment_part:
                raw_bytes = parse_bytes_comment(comment_part)

            if opcode_part.lower().startswith("db"):
                raw_bytes = parse_db_bytes(opcode_part[2:].strip())
                if current_section is None:
                    start_section(".text", align(addr - image_base, DEFAULT_SECTION_ALIGNMENT))
                current_section["entries"].append({
                    "address": addr,
                    "asm": None,
                    "raw_bytes": raw_bytes,
                })
                continue

            if opcode_part:
                if current_section is None:
                    start_section(".text", align(addr - image_base, DEFAULT_SECTION_ALIGNMENT))
                current_section["entries"].append({
                    "address": addr,
                    "asm": opcode_part,
                    "raw_bytes": raw_bytes,
                })

    if not sections:
        raise ValueError("No disassembly entries found in listing")

    if len(sections) == 1:
        sec = sections[0]
        min_addr = min(entry["address"] for entry in sec["entries"] if entry["address"] is not None)
        sec["va"] = align(min_addr - image_base, DEFAULT_SECTION_ALIGNMENT)

    return sections


def parse_disasm_addresses(path, image_base=DEFAULT_IMAGE_BASE):
    addresses = []
    line_pattern = re.compile(r"^\s*0x([0-9A-Fa-f]+):")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = line_pattern.match(line)
            if not match:
                continue
            addr = int(match.group(1), 16)
            addresses.append(addr)
    return addresses


def compare_files(path_a, path_b, chunk_size=8192):
    len_a = os.path.getsize(path_a)
    len_b = os.path.getsize(path_b)
    mismatches = 0
    first_mismatch = None
    bytes_compared = 0

    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        while True:
            chunk_a = fa.read(chunk_size)
            chunk_b = fb.read(chunk_size)
            if not chunk_a and not chunk_b:
                break
            for i, (byte_a, byte_b) in enumerate(zip(chunk_a, chunk_b)):
                if byte_a != byte_b:
                    mismatches += 1
                    if first_mismatch is None:
                        first_mismatch = bytes_compared + i
            bytes_compared += min(len(chunk_a), len(chunk_b))
            if not chunk_a or not chunk_b:
                break

    extra_bytes = abs(len_a - len_b)
    same = mismatches == 0 and len_a == len_b
    return {
        "same": same,
        "len_a": len_a,
        "len_b": len_b,
        "mismatches": mismatches,
        "bytes_compared": bytes_compared,
        "first_mismatch": first_mismatch,
        "extra_bytes": extra_bytes,
    }


def find_original_section(sections, section):
    for sec in sections:
        if sec["name"] == section["name"]:
            return sec
    for sec in sections:
        if sec["virtual_address"] == section["va"]:
            return sec
    return None


def patch_section_bytes(section, original_bytes, image_base):
    if Ks is None:
        raise ImportError("keystone-engine is required for disassembly reconstruction. Install with: pip install keystone-engine")

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    section_start = section["va"] + image_base
    data = bytearray(original_bytes)

    for entry in section["entries"]:
        if entry["address"] is None:
            continue

        raw_bytes = entry["raw_bytes"]
        if raw_bytes is None:
            if entry["asm"] is None:
                continue
            try:
                raw_bytes, _ = ks.asm(entry["asm"], entry["address"])
            except Exception as exc:
                raise ValueError(f"Assembly failed at 0x{entry['address']:X}: {entry['asm']}: {exc}")

        offset = entry["address"] - section_start
        if offset < 0 or offset + len(raw_bytes) > len(data):
            raise ValueError(
                f"Entry at 0x{entry['address']:X} is outside section bounds "
                f"(section start 0x{section_start:X}, size {len(data)})"
            )

        for i, byte in enumerate(raw_bytes):
            data[offset + i] = byte

    return data


def create_pe_from_template(input_path, sections, output_path, image_base=DEFAULT_IMAGE_BASE,
                            entry_point=None):
    with open(input_path, "rb") as f:
        original = bytearray(f.read())

    original_sections = parse_pe(original)
    for section in sections:
        orig_section = find_original_section(original_sections, section)
        if orig_section is None:
            raise ValueError(f"No matching section in template for disassembly section: {section['name']}")

        raw_ptr = orig_section["raw_ptr"]
        raw_size = orig_section["raw_size"]
        original_data = original[raw_ptr:raw_ptr + raw_size]
        patched = patch_section_bytes(section, original_data, image_base)
        original[raw_ptr:raw_ptr + len(patched)] = patched

    if entry_point is not None:
        e_lfanew = struct.unpack_from("<I", original, 0x3C)[0]
        optional_header_offset = e_lfanew + 0x18
        struct.pack_into("<I", original, optional_header_offset + 0x10, entry_point - image_base)

    with open(output_path, "wb") as f:
        f.write(original)


def print_compare_results(result, rebuilt_path, original_path):
    if result["same"]:
        print(f"Verified: rebuilt EXE matches original file exactly ({result['len_a']} bytes).")
        return

    print("Verification: rebuilt EXE differs from original file.")
    print(f"  Rebuilt: {result['len_a']} bytes")
    print(f"  Original: {result['len_b']} bytes")
    print(f"  Compared: {result['bytes_compared']} bytes")
    if result["mismatches"]:
        print(f"  Mismatched bytes: {result['mismatches']}")
    if result["first_mismatch"] is not None:
        print(f"  First mismatch at offset 0x{result['first_mismatch']:X}")
    if result["extra_bytes"]:
        print(f"  Length difference: {result['extra_bytes']} extra bytes")


def assemble_section(section, image_base, fill_byte=0x00):
    if Ks is None:
        raise ImportError("keystone-engine is required for disassembly reconstruction. Install with: pip install keystone-engine")

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    entries = section["entries"]
    section_start = section["va"] + image_base

    assembled_lengths = []
    section_end = 0
    for entry in entries:
        addr = entry["address"]
        if addr is None:
            assembled_lengths.append(None)
            continue

        if entry["raw_bytes"] is not None:
            length = len(entry["raw_bytes"])
        elif entry["asm"]:
            encoding, _ = ks.asm(entry["asm"], addr)
            length = len(encoding)
        else:
            raise ValueError("Disassembly entry missing bytes and assembly text")

        assembled_lengths.append(length)
        section_end = max(section_end, addr + length)

    if section_end <= section_start:
        raise ValueError("Section has no valid entries or computed size")

    size = align(section_end - section_start, DEFAULT_FILE_ALIGNMENT)
    if size == 0:
        size = DEFAULT_FILE_ALIGNMENT
    data = bytearray([fill_byte] * size)

    for entry, length in zip(entries, assembled_lengths):
        addr = entry["address"]
        if addr is None:
            if entry["raw_bytes"] is None:
                raise ValueError("Raw data entry missing byte values")
            offset = 0
            for i, byte in enumerate(entry["raw_bytes"]):
                if data[offset + i] != fill_byte and data[offset + i] != byte:
                    raise ValueError(
                        f"Byte conflict at raw data offset 0x{offset + i:X}: existing 0x{data[offset+i]:02X} vs new 0x{byte:02X}"
                    )
                data[offset + i] = byte
            continue

        offset = addr - section_start
        if offset < 0:
            raise ValueError(f"Address 0x{addr:X} is below section start 0x{section_start:X}")

        if entry["raw_bytes"] is not None:
            raw_bytes = entry["raw_bytes"]
            if offset + len(raw_bytes) > len(data):
                end_addr = addr + len(raw_bytes) - 1
                raise ValueError(f"Raw byte range exceeds section bounds at 0x{end_addr:X}")
            for i, byte in enumerate(raw_bytes):
                if data[offset + i] != fill_byte and data[offset + i] != byte:
                    raise ValueError(
                        f"Byte conflict at 0x{addr + i:X}: existing 0x{data[offset+i]:02X} vs new 0x{byte:02X}"
                    )
                data[offset + i] = byte
            continue

        if entry["asm"] is None:
            continue

        try:
            encoding, _ = ks.asm(entry["asm"], addr)
        except Exception as exc:
            raise ValueError(f"Assembly failed at 0x{addr:X}: {entry['asm']}: {exc}")

        if offset + len(encoding) > len(data):
            raise ValueError(f"Instruction at 0x{addr:X} exceeds section bounds")
        for i, byte in enumerate(encoding):
            if data[offset + i] != fill_byte and data[offset + i] != byte:
                raise ValueError(
                    f"Byte conflict at 0x{addr + i:X}: existing 0x{data[offset+i]:02X} vs new 0x{byte:02X}"
                )
            data[offset + i] = byte

    actual_size = section_end - section_start
    return data[:actual_size]


def create_pe(sections, output_path, image_base=DEFAULT_IMAGE_BASE, entry_point=None,
              section_alignment=DEFAULT_SECTION_ALIGNMENT, file_alignment=DEFAULT_FILE_ALIGNMENT):
    if entry_point is None:
        entry_point = sections[0]["entries"][0]["address"]

    section_datas = []
    for section in sections:
        section_bytes = assemble_section(section, image_base)
        section_datas.append((section, section_bytes))

    section_datas.sort(key=lambda item: item[0]["va"])
    headers_size = align(0x80 + 4 + 20 + 0xE0 + len(section_datas) * IMAGE_SIZEOF_SECTION_HEADER, file_alignment)
    total_raw_size = sum(align(len(data_bytes), file_alignment) for _, data_bytes in section_datas)
    image_size = align(section_datas[-1][0]["va"] + len(section_datas[-1][1]), section_alignment)

    output = bytearray(headers_size + total_raw_size)
    output[0:2] = IMAGE_DOS_SIGNATURE
    struct.pack_into("<I", output, 0x3C, 0x80)
    if headers_size > 0x40 + len(b"This program cannot be run in DOS mode.\r\n$"):
        output[0x40:0x40 + 36] = b"This program cannot be run in DOS mode.\r\n$"

    pe_offset = 0x80
    output[pe_offset:pe_offset + 4] = IMAGE_NT_SIGNATURE
    file_header_offset = pe_offset + 4
    struct.pack_into("<HHIIIHH", output, file_header_offset,
                     IMAGE_FILE_MACHINE_I386,
                     len(section_datas),
                     0,
                     0,
                     0,
                     0xE0,
                     0x010F)

    optional_offset = file_header_offset + 20
    size_of_code = align(len(section_datas[0][1]), file_alignment)
    size_of_initialized_data = sum(align(len(data_bytes), file_alignment) for _, data_bytes in section_datas[1:])
    base_of_data = section_datas[1][0]["va"] if len(section_datas) > 1 else 0
    optional_header = bytearray(0xE0)
    struct.pack_into("<HBBIIIIII", optional_header, 0,
                     0x10B,
                     0,
                     0,
                     size_of_code,
                     size_of_initialized_data,
                     0,
                     entry_point - image_base,
                     section_datas[0][0]["va"],
                     base_of_data)
    struct.pack_into("<III", optional_header, 0x1C,
                     image_base,
                     section_alignment,
                     file_alignment)
    struct.pack_into("<HHHHHH", optional_header, 0x28,
                     4,
                     0,
                     0,
                     0,
                     4,
                     0)
    struct.pack_into("<III", optional_header, 0x34,
                     0,
                     image_size,
                     headers_size)
    struct.pack_into("<IIIIHHIIIIII", optional_header, 0x40,
                     0,
                     0,
                     image_size,
                     headers_size,
                     0,
                     3,
                     0,
                     0,
                     0,
                     0,
                     0,
                     16)
    output[optional_offset:optional_offset + len(optional_header)] = optional_header

    section_table_offset = optional_offset + 0xE0
    raw_offset = headers_size
    for idx, (section, data_bytes) in enumerate(section_datas):
        section_header_offset = section_table_offset + idx * IMAGE_SIZEOF_SECTION_HEADER
        name_bytes = section["name"].encode("ascii", errors="ignore")[:8].ljust(8, b"\x00")
        virtual_size = len(data_bytes)
        raw_size = align(virtual_size, file_alignment)
        struct.pack_into("<8sIIIIIIHHI", output, section_header_offset,
                         name_bytes,
                         virtual_size,
                         section["va"],
                         raw_size,
                         raw_offset,
                         0,
                         0,
                         0,
                         0,
                         0x60000020)
        output[raw_offset:raw_offset + len(data_bytes)] = data_bytes
        raw_offset += raw_size

    with open(output_path, "wb") as f:
        f.write(output)


def main():
    parser = argparse.ArgumentParser(
        description="Reassemble a 32-bit PE executable from an original EXE or a disassembly listing."
    )
    parser.add_argument("--input", help="Optional source PE file to copy or use as a template and compare against the rebuilt output")
    parser.add_argument("--disasm", help="Disassembly listing to rebuild from")
    parser.add_argument("--output", required=True, help="Output EXE file")
    parser.add_argument("--entry", help="Optional entry point address, e.g. 0x401000")
    parser.add_argument("--image-base", type=lambda x: int(x, 0), default=DEFAULT_IMAGE_BASE,
                        help="Image base for the rebuilt PE")
    parser.add_argument("--section-alignment", type=lambda x: int(x, 0), default=DEFAULT_SECTION_ALIGNMENT)
    parser.add_argument("--file-alignment", type=lambda x: int(x, 0), default=DEFAULT_FILE_ALIGNMENT)
    parser.add_argument("--verify", help="Verify disassembly listing addresses against the source EXE", metavar="DISASM")

    args = parser.parse_args()

    if args.disasm:
        if Ks is None:
            print("Error: keystone-engine is required. Install it with: pip install keystone-engine")
            sys.exit(1)

        sections = parse_disasm_listing(args.disasm, args.image_base)
        entry_point = int(args.entry, 0) if args.entry else None
        try:
            if args.input and os.path.isfile(args.input):
                create_pe_from_template(args.input, sections, args.output,
                                        image_base=args.image_base,
                                        entry_point=entry_point)
            else:
                create_pe(sections, args.output, image_base=args.image_base,
                          entry_point=entry_point,
                          section_alignment=args.section_alignment,
                          file_alignment=args.file_alignment)
        except Exception as exc:
            print(f"Failed to rebuild EXE from disassembly: {exc}")
            sys.exit(1)
        print(f"Rebuilt EXE written to {args.output}")
        if args.input:
            if os.path.isfile(args.input):
                result = compare_files(args.output, args.input)
                print_compare_results(result, args.output, args.input)
            else:
                print(f"Warning: original file for comparison not found: {args.input}")
        return

    if not args.input:
        print("Error: either --input or --disasm must be provided")
        sys.exit(1)

    if not os.path.isfile(args.input):
        print(f"File not found: {args.input}")
        sys.exit(1)

    try:
        shutil.copyfile(args.input, args.output)
    except OSError as exc:
        print(f"Unable to write output file: {exc}")
        sys.exit(1)

    print(f"Byte-identical EXE written to {args.output}")

    if args.verify:
        if not os.path.isfile(args.verify):
            print(f"Disassembly file not found: {args.verify}")
            sys.exit(1)
        try:
            with open(args.input, "rb") as f:
                data = f.read()
            sections = parse_pe(data)
            addresses = parse_disasm_addresses(args.verify)
            if not addresses:
                raise ValueError("No addresses found in the disassembly file")
            min_addr = min(addresses)
            max_addr = max(addresses)
            section = None
            for sec in sections:
                start = sec["virtual_address"]
                end = start + sec["virtual_size"]
                if start <= min_addr - args.image_base and max_addr - args.image_base < end:
                    section = sec
                    break
            if section is None:
                print("Warning: no matching section found for disassembly addresses.")
            else:
                print(f"Disassembly appears to map inside section: {section['name']}")
                print(f"Section raw data: offset={section['raw_ptr']} size={section['raw_size']}")
                print(f"Parsed {len(addresses)} instruction addresses from {args.verify}")
        except Exception as exc:
            print(f"Verification failed: {exc}")
            sys.exit(1)


if __name__ == "__main__":
    main()
