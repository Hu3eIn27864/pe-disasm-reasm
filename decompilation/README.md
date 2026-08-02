# Decompilation

This folder contains helper files for decompiling the `game.exe` binary.

## Binary Ninja

The current environment does not have the Binary Ninja Python API installed, so the following helper is a template you can use on a machine with Binary Ninja installed.

### Recommended workflow

1. Open `game.exe` in Binary Ninja.
2. Let the analysis complete.
3. Use the `decompilation/binaryninja_export.py` script from Binary Ninja's built-in Python console or headless environment.
4. The script will export the function list and C-like pseudocode to `decompilation/bn_decompilation.txt`.

### Running the script from Binary Ninja UI

- In Binary Ninja, open `game.exe`.
- Open the Python console (`View > Python Console`).
- Run:
  ```python
  import sys
  sys.path.append(r"C:\Users\salma\Documents\vscode5\decompilation")
  import binaryninja_export
  binaryninja_export.export_all_functions(bv)
  ```

### Running headless (Binary Ninja stand-alone CLI)

```powershell
"C:\Program Files\Vector35\Binary Ninja\binaryninja.exe" -c "import sys; sys.path.append(r'C:\Users\salma\Documents\vscode5\decompilation'); import binaryninja_export; binaryninja_export.export_all_functions(bv)" "C:\Users\salma\Documents\vscode5\game.exe"
```

If you do not have Binary Ninja, use the script as a template for other decompilers.
