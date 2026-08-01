# x86 PE Disassembler and Reassembler

This repository contains Python scripts for disassembling a 32-bit x86 PE executable and rebuilding it from a disassembly listing.

## Files

- `disassemble_x86_pe.py` - basic PE disassembler for `.text` section.
- `disassemble_x86_pe_v2.py` - improved disassembler covering sections and exact bytes.
- `reassemble_x86_pe.py` - rebuilds a PE executable from a disassembly listing. If `--input` is provided, it uses the original EXE as a template for exact-byte reconstruction.
- `game.exe` - original executable under analysis.
- `game_disasm_v2.txt` - generated disassembly listing from `disassemble_x86_pe_v2.py`.

## Requirements

- Python 3
- `keystone-engine` (for assembly reconstruction)

Install dependencies with:

```powershell
pip install keystone-engine
```

## Usage

### Disassemble

```powershell
python disassemble_x86_pe_v2.py game.exe -o game_disasm_v2.txt
```

### Rebuild from disassembly

```powershell
python reassemble_x86_pe.py --disasm game_disasm_v2.txt --output rebuilt_game.exe --entry 0x401000
```

### Rebuild using original EXE as a template (byte-identical)

```powershell
python reassemble_x86_pe.py --input game.exe --disasm game_disasm_v2.txt --output rebuilt_template_game.exe
```

## Notes

- The template rebuild preserves original PE headers and section layout.
- Use the `--entry` option only when you want to override the original entry point.

## GitHub upload

This environment does not have local `git` or `gh` available, so remote push is not possible here.

To initialize and push from your machine:

```powershell
cd C:\Users\salma\Documents\vscode5
git init
git add .
git commit -m "Add PE disassembler/reassembler scripts"
# Create a private repo on GitHub using the website or GitHub CLI:
# gh repo create <your-username>/<repo-name> --private
# then:
# git remote add origin https://github.com/<your-username>/<repo-name>.git
# git push -u origin main
```
