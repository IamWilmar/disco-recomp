#!/usr/bin/env python3
"""Desensambla funciones del SDK de verdad (work/scope/sdk.elf, el módulo sdk del volcado) por su nombre.

El sdk conserva los símbolos de todo lo que exporta (nn::audio::AppendWaveBuffer…) y de mucho de lo interno
(nn::audio::server::…, nn::audio::dsp::…): leer la función de verdad dice qué escribe en los structs del juego, qué
devuelve y cuándo, en vez de deducirlo de cómo la usa el juego. Así salió la semántica de nn::audio
(runtime/src/nnsdk/audio_renderer.cpp, "sdk+0x…").

Uso: python3 tools/sdk_dis.py list <texto> [texto…]      símbolos cuyo nombre legible contiene todos los textos
     python3 tools/sdk_dis.py dis <texto | dirección hex> [bytes]
                                                          desensambla (hasta el siguiente símbolo, o `bytes`)

Las llamadas por la PLT salen con el nombre del import, y los adrp+add / adrp+ldr con la cadena o el valor al que apuntan.
El sdk.elf está en el repo principal (DISCO_MAIN, por defecto  este checkout).
"""
import bisect
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

MAIN = Path(os.environ.get("DISCO_MAIN", str(Path(__file__).resolve().parent.parent)))
ELF = MAIN / "work/scope/sdk.elf"
NDK = Path.home() / "Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin"


def run(*args, stdin=None):
    return subprocess.run([str(a) for a in args], input=stdin, capture_output=True, text=True).stdout


def demangle(names):
    # -n: en macOS llvm-cxxfilt quita por defecto un '_' inicial (convención Mach-O) y deja los nombres sin tocar.
    return run(NDK / "llvm-cxxfilt", "-n", stdin="\n".join(names)).splitlines()


def symbols():
    rows = [q for q in (line.split() for line in run(NDK / "llvm-nm", "-D", "--defined-only", ELF).splitlines()) if len(q) == 3]
    return [(int(a, 16), t, d) for (a, t, _), d in zip(rows, demangle([q[2] for q in rows]))]


class Image:
    def __init__(self):
        self.data = ELF.read_bytes()
        phoff, = struct.unpack_from("<Q", self.data, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", self.data, 0x36)
        self.segs = []
        for i in range(phnum):
            p_type, _, off, vaddr, _, filesz, _, _ = struct.unpack_from("<IIQQQQQQ", self.data, phoff + i * phentsize)
            if p_type == 1:
                self.segs.append((vaddr, off, filesz))

    def off(self, va):
        for v, o, s in self.segs:
            if v <= va < v + s:
                return o + va - v
        return None

    def cstr(self, va):
        o = self.off(va)
        if o is None:
            return None
        s = self.data[o:self.data.find(b"\0", o)]
        return s.decode() if 3 <= len(s) <= 160 and all(32 <= c < 127 or c in (9, 10) for c in s) else None


def got_names():
    got = {}
    for line in run(NDK / "llvm-readelf", "--dyn-relocations", ELF).splitlines():
        q = line.split(None, 4)
        if len(q) >= 5 and ("JUMP_SLOT" in q[2] or "GLOB_DAT" in q[2]):
            got[int(q[0], 16)] = q[4].split(" + ")[0]
    pretty = dict(zip(got.values(), demangle(list(got.values()))))
    return {slot: pretty.get(name, name) for slot, name in got.items()}


def disassemble(syms, start, size):
    img, got = Image(), got_names()
    by_addr = {}
    for a, _, d in syms:
        by_addr.setdefault(a, d)
    code = sorted({a for a, t, _ in syms if t in "TtWw"})
    if size is None:
        i = bisect.bisect_right(code, start)
        stop = code[i] if i < len(code) else start + 0x400
    else:
        stop = start + size
    out = run(NDK / "llvm-objdump", "-d", "--no-show-raw-insn", f"--start-address={start:#x}", f"--stop-address={stop:#x}", ELF)
    pages = {}
    for line in out.splitlines():
        if not re.match(r"^\s*[0-9a-f]+:", line):
            continue
        line, note = re.sub(r"\s*<[^>]*>", "", line), ""
        m = re.search(r"\s(bl|b)\s+0x([0-9a-f]+)$", line)
        if m and not start <= (t := int(m.group(2), 16)) < stop:
            note = by_addr.get(t, "")
            o = img.off(t)
            if not note and o is not None:  # entrada de la PLT: adrp x16 / ldr x17, [x16, #n]
                adrp, ldr = struct.unpack_from("<II", img.data, o)
                if adrp & 0x9F00001F == 0x90000010:
                    page = (t & ~0xFFF) + (((adrp >> 5 & 0x7FFFF) << 2 | adrp >> 29 & 3) << 12)
                    note = got.get(page + (ldr >> 10 & 0xFFF) * 8, "")
        if m := re.search(r"adrp\s+(x\d+), 0x([0-9a-f]+)", line):
            pages[m.group(1)] = int(m.group(2), 16)
        if (m := re.search(r"add\s+(x\d+), (x\d+), #0x([0-9a-f]+)$", line)) and m.group(2) in pages:
            va = pages[m.group(2)] + int(m.group(3), 16)
            note = f"{va:#x} " + (repr(img.cstr(va)) if img.cstr(va) else by_addr.get(va, ""))
        if (m := re.search(r"ldr\s+[xwdsq]\d+, \[(x\d+), #0x([0-9a-f]+)\]", line)) and m.group(1) in pages:
            va = pages[m.group(1)] + int(m.group(2), 16)
            if (o := img.off(va)) is not None:
                q, = struct.unpack_from("<Q", img.data, o)
                f, = struct.unpack_from("<f", img.data, o)
                note = f"[{va:#x}] = {q:#x} (float {f:g}) {by_addr.get(q, '')}"
        print(line + (f"   ; {note}" if note else ""))


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("list", "dis"):
        raise SystemExit(__doc__)
    syms = symbols()
    if sys.argv[1] == "list":
        for a, t, d in syms:
            if all(k in d for k in sys.argv[2:]):
                print(f"{a:8x} {t} {d}")
        return
    key, size = sys.argv[2], int(sys.argv[3], 0) if len(sys.argv) > 3 else None
    if re.fullmatch(r"(0x)?[0-9a-f]+", key):
        disassemble(syms, int(key, 16), size)
        return
    seen = set()
    for a, t, d in syms:
        if key in d and t in "TtWw" and a not in seen:
            seen.add(a)
            print(f"== {a:x} {d}")
            disassemble(syms, a, size)


if __name__ == "__main__":
    main()
