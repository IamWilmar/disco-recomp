#!/usr/bin/env python3
"""Dice a qué método de C# pertenece una dirección del ejecutable del juego.

Uso: python3 tools/donde.py [-a] [-t tabla.tsv] main+0x2b51fe0 25bf1e0 0x1899360 ...
     python3 tools/donde.py [--pila] [-t tabla.tsv] < log.txt

Con direcciones (main+0xADDR, 0xADDR o ADDR, siempre en hex) escribe una línea por cada una: la función
que la contiene (la de mayor dirección <= ADDR en la tabla), el desplazamiento dentro de ella y su
imagen. Cuando varias instancias genéricas comparten ese código sale la primera; -a las lista todas.

Sin direcciones filtra la entrada estándar: copia cada línea cambiando cada «main+0xADDR» por
«Método+0xdesp (main+0xADDR)». Lo que cae en código sin nombre (el motor, el runtime) se queda igual.
Con --pila, además, debajo de cada línea con una pila de las que escribe el runtime («pila a b c», en
hex sin prefijo) pone una línea por cada marco que sí tiene nombre.

La tabla es work/scope/il2cpp_methods.tsv; la genera tools/il2cpp_map.py.
"""
from __future__ import annotations

import bisect
import os
import re
import sys
from pathlib import Path

TABLE = Path(__file__).resolve().parent.parent / "work/scope/il2cpp_methods.tsv"
MAIN = re.compile(r"main\+0x([0-9a-fA-F]+)")
STACK = re.compile(r"\bpila((?: [0-9a-fA-F]+)+)")
ADDRESS = re.compile(r"(?:main\+)?(?:0x)?([0-9a-fA-F]+)")


class Table:
    """La tabla de tools/il2cpp_map.py: líneas «dirección <tab> imagen <tab> nombre» ordenadas."""

    def __init__(self, path: Path):
        try:
            self.lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            raise SystemExit(f"no existe {path}: se genera con python3 tools/il2cpp_map.py")
        self.addrs = [int(line[:line.index("\t")], 16) for line in self.lines]

    def find(self, addr: int):
        """(inicio, [(imagen, nombre), ...]) de la función que contiene `addr`, o None si esa dirección
        no tiene nombre (antes de la primera función, o tras una línea «-»: código nativo)."""
        last = bisect.bisect_right(self.addrs, addr) - 1
        if last < 0:
            return None
        start = self.addrs[last]
        first = bisect.bisect_left(self.addrs, start)
        rows = [tuple(line.split("\t")[1:]) for line in self.lines[first:last + 1]]
        return None if rows[0][1] == "-" else (start, rows)

    def symbol(self, addr: int):
        """«Nombre+0xdesp» de una dirección, o None si no tiene nombre."""
        found = self.find(addr)
        return found and f"{found[1][0][1]}+{addr - found[0]:#x}"


def describe(table: Table, text: str, all_names: bool) -> str:
    m = ADDRESS.fullmatch(text.strip("()[]<>,;:."))
    if not m:
        return f"{text}  (no es una dirección: main+0xADDR, 0xADDR o ADDR, en hex)"
    addr = int(m.group(1), 16)
    found = table.find(addr)
    if not found:
        outside = addr >= table.addrs[-1]  # la última línea es el final de .text
        return f"main+{addr:#x}  -  ({'fuera de .text' if outside else 'código sin nombre: no es un método de C#'})"
    start, rows = found
    image, name = rows[0]
    out = f"main+{addr:#x}  {name}+{addr - start:#x}" + (f"  [{image}]" if image != "-" else "")
    if len(rows) > 1 and all_names:
        out += "".join(f"\n    = {name}" for _, name in rows[1:])
    elif len(rows) > 1:
        out += f"  (+{len(rows) - 1} con el mismo código: -a los lista)"
    return out


def filter_log(table: Table, stacks: bool):
    def replace(m):
        symbol = table.symbol(int(m.group(1), 16))
        return f"{symbol} ({m.group(0)})" if symbol else m.group(0)

    # Los logs traen bytes que no son UTF-8: tienen que salir como entraron.
    sys.stdin.reconfigure(encoding="utf-8", errors="surrogateescape")
    sys.stdout.reconfigure(encoding="utf-8", errors="surrogateescape")
    for line in sys.stdin:
        sys.stdout.write(MAIN.sub(replace, line))
        for m in STACK.finditer(line) if stacks else ():
            for k, frame in enumerate(m.group(1).split()):
                symbol = table.symbol(int(frame, 16))
                if symbol:
                    sys.stdout.write(f"    #{k} {frame} {symbol}\n")


def main():
    args = sys.argv[1:]
    path, all_names, stacks, addresses = TABLE, False, False, []
    while args:
        arg = args.pop(0)
        if arg in ("-t", "--tabla") and args:
            path = Path(args.pop(0))
        elif arg in ("-a", "--todos"):
            all_names = True
        elif arg == "--pila":
            stacks = True
        elif arg.startswith("-"):
            raise SystemExit(__doc__)
        else:
            addresses.append(arg)
    if not addresses and sys.stdin.isatty():
        raise SystemExit(__doc__)
    table = Table(path)
    if addresses:
        for text in addresses:
            print(describe(table, text, all_names))
    else:
        filter_log(table, stacks)


if __name__ == "__main__":
    try:
        main()
        sys.stdout.flush()
    except BrokenPipeError:  # «donde.py < log | head»: que no ensucie con una traza
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
