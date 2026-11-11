#!/usr/bin/env python3
"""Compila un .cpp de runtime/src con las mismas opciones que libnnsdk y comprueba qué imports del juego da.

Uso: python3 tools/hle_check.py runtime/src/nnsdk/<archivo>.cpp [más .cpp]

Vale desde el repo principal y desde un worktree de git: las cabeceras salen del árbol donde está el .cpp y lo que no está
en git (build/android/compile_commands.json, work/exefs/main, third_party) del repo principal (DISCO_MAIN, por defecto este checkout). No toca build/: compila a un temporal.

Por cada archivo: errores de compilación, qué imports de main define (con el mangling exacto que pide el juego) y de ellos
cuáles estaban en stub (work/scope/stubs_main.tsv, de tools/stubs.py), y los símbolos nn:: que exporta sin que main los
importe: casi siempre un tipo de parámetro mal declarado (el juego no los encontraría).
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
MAIN = Path(os.environ.get("DISCO_MAIN", str(Path(__file__).resolve().parent.parent)))
NDK = Path.home() / "Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin"
NM = NDK / "llvm-nm"
FILT = NDK / "llvm-cxxfilt"


def template_command(like: str) -> list[str]:
    db = json.loads((MAIN / "build/android/compile_commands.json").read_text())
    for entry in db:
        if entry["file"].endswith(like):
            return shlex.split(entry["command"])
    raise SystemExit(f"no encuentro {like} en compile_commands.json (cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON)")


def compile_one(src: Path, out: Path) -> tuple[bool, str]:
    # Las opciones de os.cpp valen para todo libnnsdk; las de run.cpp, para el loader.
    like = "src/loader/run.cpp" if "/loader/" in str(src) else "src/nnsdk/os.cpp"
    cmd = template_command(like)
    args, skip = [], False
    for a in cmd:
        if skip:
            skip = False
            continue
        if a in ("-o", "-c", "-MF", "-MT", "-MD"):
            skip = a in ("-o", "-c", "-MF", "-MT")
            continue
        if a.endswith(like.split("/")[-1]):
            continue
        # Cabeceras del árbol donde está el fuente (un worktree), no las del repo principal.
        a = a.replace(str(MAIN / "runtime"), str(HERE / "runtime"))
        args.append(a)
    args += ["-c", str(src), "-o", str(out)]
    r = subprocess.run(args, capture_output=True, text=True)
    return r.returncode == 0, r.stderr


def main_imports() -> set[str]:
    sys.path.insert(0, str(HERE / "tools"))
    import nso  # noqa: E402

    mod = nso.Nso("main", (MAIN / "work/exefs/main").read_bytes())
    imports = mod.imports() if callable(mod.imports) else mod.imports
    return {s if isinstance(s, str) else getattr(s, "name", None) or s[0] for s in imports}


def main():
    imported = main_imports()
    stubs = {}
    tsv = MAIN / "work/scope/stubs_main.tsv"
    if tsv.exists():
        for line in tsv.read_text().splitlines():
            _, pretty, mangled = line.split("\t")
            stubs[mangled] = pretty
    for path in sys.argv[1:]:
        src = Path(path).resolve()
        with tempfile.TemporaryDirectory() as tmp:
            obj = Path(tmp) / "x.o"
            ok, errs = compile_one(src, obj)
            print(f"== {src}: {'compila' if ok else 'NO COMPILA'}")
            if not ok:
                print("\n".join(l for l in errs.splitlines() if "error" in l)[:6000])
                continue
            warns = [l for l in errs.splitlines() if "warning" in l]
            if warns:
                print("\n".join(warns[:20]))
            syms = subprocess.run([str(NM), "-g", "--defined-only", "--format=just-symbols", str(obj)],
                                  capture_output=True, text=True).stdout.split()
        # Las de libc con nombre de bionic se exportan como nngame_<nombre> (loader/imports.cpp).
        syms = [s[len("nngame_"):] if s.startswith("nngame_") else s for s in syms]
        given = [s for s in syms if s in imported]
        was_stub = [s for s in given if s in stubs]
        print(f"   da {len(given)} imports de main; {len(was_stub)} de ellos estaban en stub")
        for s in was_stub:
            print(f"     + {stubs[s]}")
        odd = [s for s in syms if s not in imported and (s.startswith("_ZN2nn") or s.startswith("_ZNK2nn") or s.startswith("nn"))]
        if odd:
            demangled = subprocess.run([str(FILT)], input="\n".join(odd), capture_output=True, text=True).stdout
            print("   exporta y main NO lo importa con ese nombre (¿mangling?, o lo usaba otro juego):")
            for s, d in zip(odd, demangled.splitlines()):
                print(f"     {d}   [{s}]")


if __name__ == "__main__":
    main()
