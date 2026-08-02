from reassemble_x86_pe import parse_disasm_listing, assemble_section
from pathlib import Path
import os
os.chdir(r'C:\Users\salma\Documents\vscode5')
sections = parse_disasm_listing('game_disasm_v2.txt')
for s in sections:
    if s['name'].lower().startswith('.rsrc'):
        data = assemble_section(s, 0x400000)
        Path('rsrc.bin').write_bytes(bytes(data))
        print('wrote rsrc.bin', len(data))
        break
else:
    print('no .rsrc section found')
# write header.bin from original game.exe for testing (first 0x1000 bytes)
if Path('game.exe').exists():
    buf = Path('game.exe').read_bytes()
    Path('header.bin').write_bytes(buf[:0x1000])
    print('wrote header.bin', len(buf[:0x1000]))
else:
    print('game.exe not found for header extraction')
