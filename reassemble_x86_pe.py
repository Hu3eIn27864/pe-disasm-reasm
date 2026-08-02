#!/usr/bin/env python3
"""Reassemble a 32-bit x86 PE executable from a disassembly listing.

Features:
- Assemble sections from disasm (requires keystone-engine).
- Optionally inject a header binary (`--header-bin`) written at offset 0.
- Optionally override section contents with `--section-bin NAME=PATH`.
- Optionally inject arbitrary binaries at offsets with `--inject OFF=PATH`.
- Template mode: if `--input <orig.exe>` is provided, use it as template and patch sections.
"""

import argparse
import os
import re
import shutil
import struct
import sys
from pathlib import Path

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_32
except Exception:
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
    current = None
    section_marker = re.compile(r"^;\s*SECTION\s+(\S+).*?raw_offset=0x([0-9A-Fa-f]+).*?raw_size=0x([0-9A-Fa-f]+).*?va=0x([0-9A-Fa-f]+)")
    line_re = re.compile(r"^\s*0x([0-9A-Fa-f]+):\s*(.*)$")

    def start_section(name, va, raw_offset, raw_size):
        nonlocal current
        current = {"name": name, "va": va, "raw_offset": raw_offset, "raw_size": raw_size, "entries": []}
        sections.append(current)

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue
            m = section_marker.match(line)
            if m:
                name = m.group(1)
                raw_offset = int(m.group(2), 16)
                raw_size = int(m.group(3), 16)
                va = int(m.group(4), 16)
                if va >= image_base:
                    va -= image_base
                start_section(name, va, raw_offset, raw_size)
                continue
            lm = line_re.match(line)
            if not lm:
                continue
            addr = int(lm.group(1), 16)
            payload = lm.group(2).strip()
            parts = payload.split(';', 1)
            opcode = parts[0].strip()
            comment = parts[1].strip() if len(parts) > 1 else None
            raw_bytes = None
            if comment:
                raw_bytes = parse_bytes_comment(comment)
            if opcode.lower().startswith('db'):
                raw_bytes = parse_db_bytes(opcode[2:].strip())
                if current is None:
                    start_section('.text', align(addr - image_base, DEFAULT_SECTION_ALIGNMENT), 0x1000, 0)
                current['entries'].append({'address': addr, 'asm': None, 'raw_bytes': raw_bytes})
            elif opcode:
                if current is None:
                    start_section('.text', align(addr - image_base, DEFAULT_SECTION_ALIGNMENT), 0x1000, 0)
                current['entries'].append({'address': addr, 'asm': opcode, 'raw_bytes': raw_bytes})

    if not sections:
        raise ValueError('No disassembly entries found')

    if len(sections) == 1:
        sec = sections[0]
        min_addr = min(e['address'] for e in sec['entries'] if e['address'] is not None)
        sec['va'] = align(min_addr - image_base, DEFAULT_SECTION_ALIGNMENT)

    return sections


def assemble_section(section, image_base=DEFAULT_IMAGE_BASE, fill_byte=0x00):
    if Ks is None:
        raise ImportError('keystone-engine is required: pip install keystone-engine')
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    entries = section['entries']
    section_start = section['va'] + image_base
    assembled_lengths = []
    section_end = 0
    for entry in entries:
        addr = entry['address']
        if addr is None:
            assembled_lengths.append(None)
            continue
        if entry['raw_bytes'] is not None:
            length = len(entry['raw_bytes'])
        elif entry['asm']:
            encoding, _ = ks.asm(entry['asm'], addr)
            length = len(encoding)
        else:
            raise ValueError('Entry missing bytes and asm')
        assembled_lengths.append(length)
        section_end = max(section_end, addr + length)
    if section_end <= section_start:
        raise ValueError('Section has no valid entries')
    size = align(section_end - section_start, DEFAULT_FILE_ALIGNMENT)
    if size == 0:
        size = DEFAULT_FILE_ALIGNMENT
    data = bytearray([fill_byte] * size)
    for entry, length in zip(entries, assembled_lengths):
        addr = entry['address']
        if addr is None:
            if entry['raw_bytes'] is None:
                raise ValueError('Raw data entry missing bytes')
            offset = 0
            for i, b in enumerate(entry['raw_bytes']):
                data[offset + i] = b
            continue
        offset = addr - section_start
        if offset < 0:
            raise ValueError('Address below section start')
        if entry['raw_bytes'] is not None:
            rb = entry['raw_bytes']
            for i, b in enumerate(rb):
                data[offset + i] = b
            continue
        encoding, _ = ks.asm(entry['asm'], addr)
        for i, b in enumerate(encoding):
            data[offset + i] = b
    actual_size = section_end - section_start
    return data[:actual_size]


def parse_pe(data):
    if len(data) < 0x40 or data[:2] != IMAGE_DOS_SIGNATURE:
        raise ValueError('Not a valid DOS header / PE file')
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew + 4] != IMAGE_NT_SIGNATURE:
        raise ValueError('Not a valid PE header')
    fh_off = e_lfanew + 4
    NumberOfSections = struct.unpack_from('<H', data, fh_off + 2)[0]
    SizeOfOptionalHeader = struct.unpack_from('<H', data, fh_off + 16)[0]
    optional_header_offset = fh_off + 20
    section_table_offset = optional_header_offset + SizeOfOptionalHeader
    secs = []
    for i in range(NumberOfSections):
        off = section_table_offset + i * IMAGE_SIZEOF_SECTION_HEADER
        if off + IMAGE_SIZEOF_SECTION_HEADER > len(data):
            break
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
        VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, _, _, _, _, Characteristics = struct.unpack_from('<IIIIIIHHI', data, off+8)
        secs.append({'name': name, 'virtual_size': VirtualSize, 'virtual_address': VirtualAddress, 'raw_size': SizeOfRawData, 'raw_ptr': PointerToRawData, 'characteristics': Characteristics})
    return secs


def patch_section_bytes(section, original_bytes, image_base=DEFAULT_IMAGE_BASE):
    if Ks is None:
        raise ImportError('keystone-engine is required: pip install keystone-engine')
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    section_start = section['va'] + image_base
    data = bytearray(original_bytes)
    for entry in section['entries']:
        if entry['address'] is None:
            continue
        rb = entry.get('raw_bytes')
        if rb is None:
            if entry.get('asm') is None:
                continue
            rb, _ = ks.asm(entry['asm'], entry['address'])
        offset = entry['address'] - section_start
        for i, b in enumerate(rb):
            data[offset + i] = b
    return data


def create_pe_from_template(input_path, sections, output_path, image_base=DEFAULT_IMAGE_BASE, entry_point=None):
    with open(input_path, 'rb') as f:
        orig = bytearray(f.read())
    orig_secs = parse_pe(orig)
    for section in sections:
        match = None
        for s in orig_secs:
            if s['name'] == section['name'] or s['virtual_address'] == section['va']:
                match = s
                break
        if match is None:
            raise ValueError('No matching section in template for ' + section['name'])
        raw_ptr = match['raw_ptr']
        raw_size = match['raw_size']
        original_data = orig[raw_ptr:raw_ptr + raw_size]
        patched = patch_section_bytes(section, original_data, image_base)
        orig[raw_ptr:raw_ptr + len(patched)] = patched
    if entry_point is not None:
        e_lfanew = struct.unpack_from('<I', orig, 0x3C)[0]
        optional_header_offset = e_lfanew + 0x18
        struct.pack_into('<I', orig, optional_header_offset + 0x10, entry_point - image_base)
    with open(output_path, 'wb') as f:
        f.write(orig)


def create_pe(sections, output_path, image_base=DEFAULT_IMAGE_BASE, entry_point=None, section_alignment=DEFAULT_SECTION_ALIGNMENT, file_alignment=DEFAULT_FILE_ALIGNMENT, header_bin=None, section_bins=None, inject_bins=None):
    # assemble sections
    if entry_point is None:
        entry_point = sections[0]['entries'][0]['address']
    section_datas = []
    for section in sections:
        section_bytes = assemble_section(section, image_base)
        section_datas.append((section, section_bytes))
    section_datas.sort(key=lambda it: it[0]['va'])
    min_header_size = align(0x80 + 4 + 20 + 0xE0 + len(section_datas) * IMAGE_SIZEOF_SECTION_HEADER, file_alignment)
    raw_offsets = [s.get('raw_offset') for s, _ in section_datas if s.get('raw_offset') is not None]
    headers_size = max(min_header_size, align(min(raw_offsets), file_alignment)) if raw_offsets else min_header_size
    section_file_sizes = []
    for section, data_bytes in section_datas:
        raw_size = section.get('raw_size')
        if raw_size is None:
            raw_size = align(len(data_bytes), file_alignment)
        elif raw_size < len(data_bytes):
            raise ValueError('Declared raw_size too small')
        section_file_sizes.append(section.get('raw_offset', headers_size) + raw_size)
    output_size = max(headers_size, max(section_file_sizes, default=0))

    # If header bin provided, write it and then place section blobs at raw offsets
    if header_bin:
        header_bytes = Path(header_bin).read_bytes()
        if len(header_bytes) > output_size:
            output_size = len(header_bytes)
        out = bytearray(output_size)
        out[0:len(header_bytes)] = header_bytes
        if inject_bins:
            for off, path in inject_bins.items():
                b = Path(path).read_bytes()
                end = off + len(b)
                if end > len(out):
                    out.extend(b'\x00' * (end - len(out)))
                out[off:off+len(b)] = b
        for section, data_bytes in section_datas:
            raw_off = section.get('raw_offset', headers_size)
            if section_bins and section['name'] in section_bins:
                sec_data = Path(section_bins[section['name']]).read_bytes()
            else:
                sec_data = bytes(data_bytes)
            end = raw_off + len(sec_data)
            if end > len(out):
                out.extend(b'\x00' * (end - len(out)))
            out[raw_off:raw_off+len(sec_data)] = sec_data
        Path(output_path).write_bytes(out)
        return

    # synthesize headers
    out = bytearray(output_size)
    out[0:2] = IMAGE_DOS_SIGNATURE
    struct.pack_into('<I', out, 0x3C, 0x80)
    if headers_size > 0x40 + len(b"This program cannot be run in DOS mode.\r\n$"):
        out[0x40:0x40+36] = b"This program cannot be run in DOS mode.\r\n$"
    pe_off = 0x80
    out[pe_off:pe_off+4] = IMAGE_NT_SIGNATURE
    fh_off = pe_off + 4
    struct.pack_into('<HHIIIHH', out, fh_off, IMAGE_FILE_MACHINE_I386, len(section_datas), 0, 0, 0, 0xE0, 0x010F)
    opt_off = fh_off + 20
    size_of_code = align(len(section_datas[0][1]), file_alignment)
    size_of_init = sum(align(len(d), file_alignment) for _, d in section_datas[1:])
    base_of_data = section_datas[1][0]['va'] if len(section_datas) > 1 else 0
    optional_header = bytearray(0xE0)
    struct.pack_into('<HBBIIIIII', optional_header, 0, 0x10B, 0, 0, size_of_code, size_of_init, 0, entry_point - image_base, section_datas[0][0]['va'], base_of_data)
    struct.pack_into('<III', optional_header, 0x1C, image_base, section_alignment, file_alignment)
    struct.pack_into('<HHHHHH', optional_header, 0x28, 4, 0, 0, 0, 4, 0)
    image_size = align(section_datas[-1][0]['va'] + len(section_datas[-1][1]), section_alignment)
    struct.pack_into('<III', optional_header, 0x34, 0, image_size, headers_size)
    struct.pack_into('<IIIIHHIIIIII', optional_header, 0x40, 0, 0, image_size, headers_size, 0, 3, 0, 0, 0, 0, 0, 16)
    out[opt_off:opt_off+len(optional_header)] = optional_header
    sect_table_off = opt_off + 0xE0
    raw_ptr = headers_size
    for idx, (section, data_bytes) in enumerate(section_datas):
        sh_off = sect_table_off + idx * IMAGE_SIZEOF_SECTION_HEADER
        name = section['name'].encode('ascii', errors='ignore')[:8].ljust(8, b'\x00')
        vsize = len(data_bytes)
        rsize = align(vsize, file_alignment)
        struct.pack_into('<8sIIIIIIHHI', out, sh_off, name, vsize, section['va'], rsize, raw_ptr, 0, 0, 0, 0, 0x60000020)
        out[raw_ptr:raw_ptr+len(data_bytes)] = data_bytes
        raw_ptr += rsize

    if inject_bins:
        for off, path in inject_bins.items():
            b = Path(path).read_bytes()
            end = off + len(b)
            if end > len(out):
                out.extend(b'\x00' * (end - len(out)))
            out[off:off+len(b)] = b

    Path(output_path).write_bytes(out)


def compare_files(a, b, chunk_size=8192):
    la = Path(a).stat().st_size
    lb = Path(b).stat().st_size
    mismatches = 0
    first = None
    compared = 0
    with open(a, 'rb') as fa, open(b, 'rb') as fb:
        while True:
            ca = fa.read(chunk_size)
            cb = fb.read(chunk_size)
            if not ca and not cb:
                break
            for i, (x, y) in enumerate(zip(ca, cb)):
                if x != y:
                    mismatches += 1
                    if first is None:
                        first = compared + i
            compared += min(len(ca), len(cb))
            if not ca or not cb:
                break
    return {'same': mismatches == 0 and la == lb, 'len_a': la, 'len_b': lb, 'mismatches': mismatches, 'first_mismatch': first, 'bytes_compared': compared, 'extra_bytes': abs(la - lb)}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--input', help='Optional source PE file to copy or use as template')
    p.add_argument('--disasm', help='Disassembly listing to rebuild from')
    p.add_argument('--output', required=True)
    p.add_argument('--entry')
    p.add_argument('--image-base', type=lambda x: int(x, 0), default=DEFAULT_IMAGE_BASE)
    p.add_argument('--section-alignment', type=lambda x: int(x, 0), default=DEFAULT_SECTION_ALIGNMENT)
    p.add_argument('--file-alignment', type=lambda x: int(x, 0), default=DEFAULT_FILE_ALIGNMENT)
    p.add_argument('--header-bin', help='Binary to write at offset 0')
    p.add_argument('--section-bin', action='append', help='NAME=PATH')
    p.add_argument('--inject', action='append', help='OFF=PATH (OFF hex)')
    p.add_argument('--verify', help='Verify disasm addresses against source EXE')
    args = p.parse_args()

    if args.disasm:
        if Ks is None:
            print('Error: keystone-engine is required')
            sys.exit(1)
        sections = parse_disasm_listing(args.disasm, args.image_base)
        entry = int(args.entry, 0) if args.entry else None
        section_bins = {}
        if args.section_bin:
            for it in args.section_bin:
                if '=' not in it:
                    print('bad --section-bin', it); sys.exit(1)
                n, path = it.split('=', 1); section_bins[n] = path
        injects = {}
        if args.inject:
            for it in args.inject:
                if '=' not in it:
                    print('bad --inject', it); sys.exit(1)
                off_s, path = it.split('=', 1)
                inj_off = int(off_s, 0)
                injects[inj_off] = path
        try:
            if args.input and os.path.isfile(args.input):
                create_pe_from_template(args.input, sections, args.output, image_base=args.image_base, entry_point=entry)
            else:
                create_pe(sections, args.output, image_base=args.image_base, entry_point=entry, section_alignment=args.section_alignment, file_alignment=args.file_alignment, header_bin=args.header_bin, section_bins=section_bins if section_bins else None, inject_bins=injects if injects else None)
        except Exception as e:
            print('Failed to rebuild EXE:', e); sys.exit(1)
        print('Rebuilt EXE written to', args.output)
        return

    if not args.input:
        print('Error: either --input or --disasm must be provided')
        sys.exit(1)
    shutil.copyfile(args.input, args.output)
    print('Byte-identical EXE written to', args.output)


if __name__ == '__main__':
    main()
