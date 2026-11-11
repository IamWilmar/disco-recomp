#!/usr/bin/env python3
"""Qué imports de main quedan en stub (ni libnnsdk.so ni host_symbols.c los dan), por grupo.

Uso: python3 tools/stubs.py [--tsv]      (necesita build/android/libnnsdk.so y work/exefs/main)
Es la misma cuenta que hace el loader al arrancar ("imports: ... N stubs").
"""
import collections, re, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
import nso
NDK = Path.home() / 'Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin'

def main():
    mod = nso.Nso('main', (ROOT / 'work/exefs/main').read_bytes())
    imports = mod.imports() if callable(mod.imports) else mod.imports
    names = []
    for s in imports:
        names.append(s if isinstance(s, str) else getattr(s, 'name', s[0] if isinstance(s, (tuple, list)) else str(s)))
    dyn = set()
    out = subprocess.run([str(NDK / 'llvm-nm'), '-D', '--defined-only', str(ROOT / 'build/android/libnnsdk.so')],
                         capture_output=True, text=True).stdout
    for l in out.splitlines():
        q = l.split()
        if q: dyn.add(q[-1])
    host = set(re.findall(r'S\((\w+)\)', (ROOT / 'runtime/src/loader/host_symbols.c').read_text()))
    stubs = [n for n in names if n not in dyn and ('nngame_' + n) not in dyn and n not in host]
    dem = subprocess.run([str(NDK / 'llvm-cxxfilt')], input='\n'.join(stubs), capture_output=True, text=True).stdout.splitlines()
    def group(d):
        m = re.match(r'(nn::\w+|movie::|android::|std::|nv::)', d)
        return m.group(1) if m else 'C'
    rows = sorted(zip(map(group, dem), dem, stubs))
    if '--tsv' in sys.argv:
        for g, d, n in rows: print(f'{g}\t{d}\t{n}')
        return
    by = collections.Counter(g for g, _, _ in rows)
    print(f'{len(names)} imports de main, {len(stubs)} en stub')
    for g, c in by.most_common(): print(f'  {c:4d}  {g}')

main()
