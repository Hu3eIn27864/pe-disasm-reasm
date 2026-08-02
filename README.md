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

### Exact-byte rebuild using injected binaries

If you need a byte-for-byte identical EXE but do not want to rely on the original at build-time,
you can extract exact header/section blobs and inject them into the rebuilt output.

1. Extract header and resource binaries (example helper):

```powershell
python extract_bins.py
# writes header.bin and rsrc.bin
```

2. Rebuild using injected blobs:

```powershell
python reassemble_x86_pe.py --disasm game_disasm_v2.txt --header-bin header.bin --section-bin .rsrc=rsrc.bin --output rebuilt_with_blobs.exe
```

### New CLI options

- `--header-bin PATH` : write the exact binary `PATH` at file offset 0 (useful to preserve DOS stub and PE header bytes).
- `--section-bin NAME=PATH` : override the assembled contents of section `NAME` with the file at `PATH` (can be repeated).
- `--inject OFF=PATH` : inject binary `PATH` at raw file offset `OFF` (hex or 0x-prefixed allowed).

## Notes

- `keystone-engine` is required for assembling instructions back into bytes. Install with `pip install keystone-engine`.
- The template mode (`--input`) remains the simplest way to produce an exact-byte rebuild when the original EXE is available.
- The repository now ignores generated blobs (`header.bin`, `rsrc.bin`, `rebuilt_with_blobs.exe`) via `.gitignore`.

- Important: To produce a byte-for-byte identical rebuild you need access to the original `game.exe` file and a legally licensed copy of the game. Do not attempt to reconstruct or distribute binaries you do not own or have rights to.

- Wichtig: Für eine exakte (byte-identische) Rekonstruktion wird die Original-EXE (`game.exe`) benötigt sowie eine rechtmäßig erworbene Kopie des Spiels. Verwende oder verbreite keine Binärdateien, die dir nicht gehören oder für die du keine Lizenz hast.

## GitHub push

Push from your machine as usual (this repo already contains commits and was pushed in-session):

```powershell
cd C:\Users\salma\Documents\vscode5
git add README.md
git commit -m "docs: update README with new rebuild options and examples"
git push origin master
```
