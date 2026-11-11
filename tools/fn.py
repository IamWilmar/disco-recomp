#!/usr/bin/env python3
"""Desensamblado de un método de C# (o de cualquier rango) de main, con los destinos de bl/b anotados.

Uso: python3 tools/fn.py <dirección hex o trozo del nombre del método> [nº máximo de instrucciones]
Necesita work/scope/main.elf, work/scope/il2cpp_methods.tsv (tools/il2cpp_map.py) y work/scope/plt.txt.
"""
import bisect, re, subprocess, sys
from pathlib import Path
MAIN = Path(__file__).resolve().parent.parent
OBJDUMP = Path.home() / 'Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-objdump'

def load():
    addrs, names = [], []
    for l in (MAIN / 'work/scope/il2cpp_methods.tsv').read_text().splitlines():
        p = l.split('\t')
        if len(p) >= 3:
            addrs.append(int(p[0], 16)); names.append(p[2])
    plt = {}
    for l in (MAIN / 'work/scope/plt.txt').read_text().splitlines():
        p = l.split('\t')
        if len(p) == 2: plt[int(p[0], 16)] = p[1]
    return addrs, names, plt

def main():
    addrs, names, plt = load()
    arg = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 400
    try:
        start = int(arg, 16)
    except ValueError:
        hits = [(a, n) for a, n in zip(addrs, names) if arg.lower() in n.lower()]
        if len(hits) != 1:
            for a, n in hits[:40]: print(f'{a:x}\t{n}')
            sys.exit(f'{len(hits)} métodos con "{arg}": afina')
        start = hits[0][0]
    i = bisect.bisect_right(addrs, start)
    end = addrs[i] if i < len(addrs) else start + 4 * limit
    end = min(end, start + 4 * limit)
    k = bisect.bisect_right(addrs, start) - 1
    print(f'; {names[k] if k >= 0 and addrs[k] == start else "?"}  [{start:x}, {end:x})')
    out = subprocess.run([str(OBJDUMP), '-d', '--no-show-raw-insn', f'--start-address={start:#x}', f'--stop-address={end:#x}',
                          str(MAIN / 'work/scope/main.elf')], capture_output=True, text=True).stdout
    def sym(m):
        t = int(m.group(2), 16)
        if t in plt: return f'{m.group(1)}{m.group(2)} <{plt[t]}>'
        j = bisect.bisect_right(addrs, t) - 1
        if j >= 0 and addrs[j] == t: return f'{m.group(1)}{m.group(2)} <{names[j]}>'
        return m.group(0)
    for l in out.splitlines():
        if re.match(r'\s+[0-9a-f]+:', l):
            l = re.sub(r'\s*<[^>]*>$', '', l)
            print(re.sub(r'(\bbl?\s+)(0x[0-9a-f]+)', sym, l))
main()
