#!/usr/bin/env python3
"""Disassemble a 32-bit x86 PE executable (.exe) into assembly listings."""

import argparse
import os
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
except ImportError:
    Cs = None

IMAGE_DOS_SIGNATURE = b"MZ"
IMAGE_NT_SIGNATURE = b"PE\x00\x00"
IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_SIZEOF_SECTION_HEADER = 40
IMAGE_SCN_CNT_CODE = 0x00000020


def read_struct(fmt, data, offset=0):
    size = struct.calcsize(fmt)
    return struct.unpack_from(fmt, data, offset), offset + size


def parse_pe(data):
    if len(data) < 0x40 or data[:2] != IMAGE_DOS_SIGNATURE:
        raise ValueError("Not a valid DOS header / PE file")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew + 4] != IMAGE_NT_SIGNATURE:
        raise ValueError("Not a valid PE header")

    file_header_offset = e_lfanew + 4
    (Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable,
     NumberOfSymbols, SizeOfOptionalHeader, Characteristics), _ = read_struct(
        "<HHIIIHH", data, file_header_offset
    )

    if Machine != IMAGE_FILE_MACHINE_I386:
        raise ValueError("Only x86 32-bit PE files are supported")

    optional_header_offset = file_header_offset + 20
    (Magic,), _ = read_struct("<H", data, optional_header_offset)
    if Magic != 0x10B:
        raise ValueError("Only 32-bit PE optional header is supported")

    optional_header_fmt = (
        "<HBBIIIQQQQHHHHHHIIIIII"
    )
    # We only need some fields from the Optional Header.
    optional_header_data = data[optional_header_offset:optional_header_offset + SizeOfOptionalHeader]
    if len(optional_header_data) < 96:
        raise ValueError("PE optional header is truncated")

    ImageBase = struct.unpack_from("<I", optional_header_data, 28)[0]

    section_table_offset = optional_header_offset + SizeOfOptionalHeader
    sections = []

    for i in range(NumberOfSections):
        header_offset = section_table_offset + i * IMAGE_SIZEOF_SECTION_HEADER
        if header_offset + IMAGE_SIZEOF_SECTION_HEADER > len(data):
            break

        Name = data[header_offset:header_offset + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
        (VirtualSize, VirtualAddress, SizeOfRawData,
         PointerToRawData, PointerToRelocations, PointerToLinenumbers,
         NumberOfRelocations, NumberOfLinenumbers, Characteristics), _ = read_struct(
            "<IIIIIIHHI", data, header_offset + 8
        )

        sections.append({
            "name": Name,
            "virtual_size": VirtualSize,
            "virtual_address": VirtualAddress,
            "raw_size": SizeOfRawData,
            "raw_ptr": PointerToRawData,
            "characteristics": Characteristics,
        })

    return {
        "image_base": ImageBase,
        "sections": sections,
    }


def find_code_section(sections, name=None):
    if name:
        for sec in sections:
            if sec["name"].lower() == name.lower():
                return sec

    for sec in sections:
        if sec["characteristics"] & IMAGE_SCN_CNT_CODE:
            return sec

    return None


def disassemble_code(data, section, image_base, count=None, offset=0):
    if Cs is None:
        raise ImportError("capstone is required for disassembly. Install with: pip install capstone")

    start = section["raw_ptr"] + offset
    end = section["raw_ptr"] + section["raw_size"]
    if start > len(data):
        raise ValueError("Start offset is outside section raw data")
    if end > len(data):
        end = len(data)

    code_bytes = data[start:end]
    address = image_base + section["virtual_address"] + offset

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False

    lines = []
    count_left = count
    for insn in md.disasm(code_bytes, address):
        lines.append(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}".rstrip())
        if count_left is not None:
            count_left -= 1
            if count_left <= 0:
                break

    return lines


def main():
    parser = argparse.ArgumentParser(
        description="Disassemble a 32-bit x86 PE executable (.exe) section to assembly text."
    )
    parser.add_argument("input", help="Path to the 32-bit PE executable")
    parser.add_argument("-o", "--output", help="Write disassembly to a file instead of stdout")
    parser.add_argument("-s", "--section", default=".text", help="Section name to disassemble (default: .text)")
    parser.add_argument("--count", type=int, help="Maximum number of instructions to decode")
    parser.add_argument("--offset", type=int, default=0, help="Byte offset into the selected section raw data")

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"File not found: {args.input}")
        sys.exit(1)

    with open(args.input, "rb") as f:
        data = f.read()

    try:
        pe = parse_pe(data)
    except ValueError as exc:
        print(f"PE parse error: {exc}")
        sys.exit(1)

    section = find_code_section(pe["sections"], args.section)
    if section is None:
        print(f"Code section not found: {args.section}")
        sys.exit(1)

    try:
        lines = disassemble_code(data, section, pe["image_base"], count=args.count, offset=args.offset)
    except ImportError as exc:
        print(exc)
        sys.exit(1)
    except ValueError as exc:
        print(f"Disassembly error: {exc}")
        sys.exit(1)

    output_data = "\n".join(lines)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            out.write(output_data)
        print(f"Disassembly written to {args.output}")
    else:
        print(output_data)


if __name__ == "__main__":
    main()
