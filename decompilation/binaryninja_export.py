from __future__ import annotations

import os
from binaryninja import BinaryViewType, Function

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), 'bn_decompilation.txt')


def export_all_functions(bv):
    """Export all functions and decompiled pseudocode from a Binary Ninja BinaryView."""
    if not bv:
        raise ValueError('BinaryView is required')

    with open(OUTPUT_PATH, 'w', encoding='utf-8') as out:
        out.write(f'Binary Ninja decompilation export for: {bv.file.filename}\n')
        out.write('=' * 80 + '\n\n')

        for function in bv.functions:
            out.write(f'Function: {function.name}\n')
            out.write(f'Address: 0x{function.start:x}\n')
            out.write('-' * 80 + '\n')
            try:
                hlil = function.hlil
                out.write(str(hlil) + '\n')
            except Exception as exc:
                out.write(f'Unable to decompile function: {exc}\n')
            out.write('\n' + ('=' * 80) + '\n\n')

    print(f'Exported decompilation to: {OUTPUT_PATH}')


def open_and_export(path: str):
    bv = BinaryViewType.get_view_of_file(path)
    bv.update_analysis_and_wait()
    export_all_functions(bv)


def main():
    import sys
    if len(sys.argv) != 2:
        print('Usage: python binaryninja_export.py <path-to-game.exe>')
        return
    open_and_export(sys.argv[1])


if __name__ == '__main__':
    main()
