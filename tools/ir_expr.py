#!/usr/bin/env python3
"""Expresión (árbol) de un valor de la IR de Eden que imprime shadertool con IR=1, sin los Identity.
Uso: ir_expr.py <ir.txt> %N [%M ...] [--prof P]"""
import re, sys
args = [a for a in sys.argv[1:] if not a.startswith('--')]
prof = int(sys.argv[sys.argv.index('--prof') + 1]) if '--prof' in sys.argv else 12
defs = {}
for l in open(args[0]):
    l = re.sub(r'^\[[0-9a-f]+\] ', '', l.strip())
    m = re.match(r'(%\d+)\s+= (\w+)\s*(.*?)\s*(\(uses: \d+\))?$', l)
    if m: defs[m.group(1)] = (m.group(2), m.group(3))
def res(v):
    while v in defs and defs[v][0] == 'Identity':
        v = defs[v][1].strip()
    return v
def expr(v, d):
    v = res(v)
    if v not in defs: return v
    op, a = defs[v]
    if d <= 0: return v
    if op == 'Phi': return f'{v}=Phi[{a}]'
    parts = []
    for tok in re.split(r',\s*', a):
        t = tok.strip()
        parts.append(expr(t, d - 1) if t.startswith('%') else t)
    return f'{op}({", ".join(parts)})'
for v in args[1:]:
    print(v, '=', expr(v, prof)); print()
