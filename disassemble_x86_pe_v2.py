#!/usr/bin/env python3
"""Disassemble every byte inside a 32-bit x86 PE executable sections."""

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
    (Machine, NumberOfSections, _, _, _, SizeOfOptionalHeader, _), _ = read_struct(
        "<HHIIIHH", data, file_header_offset
    )

    if Machine != IMAGE_FILE_MACHINE_I386:
        raise ValueError("Only x86 32-bit PE files are supported")

    optional_header_offset = file_header_offset + 20
    (Magic,), _ = read_struct("<H", data, optional_header_offset)
    if Magic != 0x10B:
        raise ValueError("Only 32-bit PE optional header is supported")

    optional_header_data = data[optional_header_offset:optional_header_offset + SizeOfOptionalHeader]
    if len(optional_header_data) < 28 + 4:
        raise ValueError("PE optional header is truncated")

    ImageBase = struct.unpack_from("<I", optional_header_data, 28)[0]
    section_table_offset = optional_header_offset + SizeOfOptionalHeader
    sections = []

    for i in range(NumberOfSections):
        header_offset = section_table_offset + i * IMAGE_SIZEOF_SECTION_HEADER
        if header_offset + IMAGE_SIZEOF_SECTION_HEADER > len(data):
            break

        name = data[header_offset:header_offset + 8].rstrip(b"\x00").decode("ascii", errors="ignore")
        (VirtualSize, VirtualAddress, SizeOfRawData,
         PointerToRawData, _, _, _, _, Characteristics), _ = read_struct(
            "<IIIIIIHHI", data, header_offset + 8
        )

        sections.append({
            "name": name,
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


def format_bytes(buf):
    return " ".join(f"{b:02x}" for b in buf)


def format_db(buf):
    return ", ".join(f"0x{b:02x}" for b in buf)


def disassemble_section(data, section, image_base):
    if Cs is None:
        raise ImportError("capstone is required for disassembly. Install with: pip install capstone")

    start = section["raw_ptr"]
    length = section["raw_size"]

    if start >= len(data) or length == 0:
        return [f"; empty section {section['name']} or invalid raw data"]

    end = min(start + length, len(data))
    code = data[start:end]
    address = image_base + section["virtual_address"]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False

    lines = []
    cursor = 0
    for insn in md.disasm(code, address):
        insn_offset = insn.address - address
        if insn_offset > cursor:
            gap = code[cursor:insn_offset]
            lines.append(f"0x{address + cursor:08x}: db {format_db(gap)}")

        insn_bytes = code[insn_offset:insn_offset + insn.size]
        text = f"{insn.mnemonic} {insn.op_str}".rstrip()
        byte_comment = format_bytes(insn_bytes)
        lines.append(f"0x{insn.address:08x}: {text} ; {byte_comment}".rstrip())
        cursor = insn_offset + insn.size

    if cursor < len(code):
        rem = code[cursor:]
        lines.append(f"0x{address + cursor:08x}: db {format_db(rem)}")

    return lines


def main():
    parser = argparse.ArgumentParser(
        description="Disassemble every byte in a 32-bit x86 PE executable section."
    )
    parser.add_argument("input", help="Path to the 32-bit PE executable")
    parser.add_argument("-o", "--output", help="Write disassembly to a file instead of stdout")
    parser.add_argument("-s", "--section", help="Section name to disassemble (default: all sections)")

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

    sections = pe["sections"]
    if args.section:
        sections = [sec for sec in sections if sec["name"].lower() == args.section.lower()]
        if not sections:
            print(f"Section not found: {args.section}")
            sys.exit(1)

    output_lines = []
    for section in sections:
        output_lines.append(f"; SECTION {section['name']} raw_offset=0x{section['raw_ptr']:X} raw_size=0x{section['raw_size']:X} va=0x{section['virtual_address']:X}")
        output_lines.extend(disassemble_section(data, section, pe["image_base"]))
        output_lines.append("")

    output_text = "\n".join(output_lines)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as out:
            out.write(output_text)
        print(f"Disassembly written to {args.output}")
    else:
        print(output_text)


if __name__ == "__main__":
    main()
