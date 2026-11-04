# x86 PE Disassembler and Reassembler

A set of Python experiments for inspecting 32-bit x86 Portable Executable files, producing assembly-oriented listings and rebuilding PE images from those listings.

> **Status: experimental.** Reassembly fidelity depends on the listing format, preserved metadata and the specific input executable. A successful output file is not automatically byte-identical, loadable or semantically equivalent.

## Tools

- `disassemble_x86_pe.py` — initial disassembly experiment for the PE code section.
- `disassemble_x86_pe_v2.py` — expanded section/byte-aware listing.
- `reassemble_x86_pe.py` — rebuild experiment with optional original-file template support.
- Optional extraction/injection helpers may exist in the working tree; inspect their CLI help before use.

## Requirements

- Python 3.
- `keystone-engine` for assembly reconstruction (install only if using the reassembler).

```bash
python -m pip install keystone-engine
```

## Usage

Inspect a PE file you are authorized to analyze:

```bash
python disassemble_x86_pe_v2.py /path/to/input.exe -o analysis.asm
```

Reassemble a listing:

```bash
python reassemble_x86_pe.py --disasm analysis.asm --output rebuilt.exe --entry 0x401000
```

If using template or binary-injection options, keep all source binaries and extracted sections local. Those modes depend on the exact input and should not be represented as standalone reconstruction unless a separate test proves it.

## Validation checklist

- Compare output file size and SHA-256.
- Compare headers, sections, data directories and overlays.
- Check relocation and import behavior.
- Open the output with an independent PE parser.
- Test execution only in a safe, isolated environment and only when authorized.
- Record byte equality separately from loadability and semantic equivalence.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for a staged plan and provisional time estimates.

## Repository hygiene and legal use

Do not commit commercial executables, DLLs, proprietary game files, raw disassembly dumps or extracted resources. Keep test binaries outside Git and use synthetic or redistributable fixtures. Analyze only files you are legally entitled to inspect.

Remove machine-specific paths, usernames and instructions from documentation before publishing. Keep examples portable across Windows, Linux and macOS where possible.
