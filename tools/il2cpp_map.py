#!/usr/bin/env python3
"""Pone nombre de método de C# a las direcciones del ejecutable de un juego Unity IL2CPP.

Uso: python3 tools/il2cpp_map.py [<main.elf> [<global-metadata.dat> [<salida.tsv>]]]

Sin argumentos lee work/scope/main.elf (el ELF con base 0 que deja tools/nso.py) y
work/romfs/Data/Managed/Metadata/global-metadata.dat, y escribe work/scope/il2cpp_methods.tsv:
una función por línea, ordenadas por dirección, sin cabecera:

    dirección en hex sin 0x <tab> imagen <tab> nombre

El nombre dice qué es la línea:
  Namespace.Clase::Método(tipos)        método de C#: methodPointers[rid - 1] del módulo de su imagen
  Namespace.Clase<int>::Método(int)     instancia de un método genérico (genericMethodPointers), con el
                                        nombre que sale de su Il2CppMethodSpec; las instancias que
                                        comparten código van todas, la de object la primera
  [thunk]Namespace.Tipo::Método(...)    adjustor thunk de un método de struct (ajusta this y salta a él)
  [pinvoke-inverso]Clase::Método(...)   entrada desde código nativo a un método estático de C#
  [delegado-pinvoke]Tipo                llamada a un puntero nativo a través de un delegado
  [marshal-a-nativo]Tipo, [marshal-de-nativo]Tipo, [marshal-limpieza]Tipo
  [invoker]#n                           RuntimeInvoker: por él entran el motor y la reflexión a C#
  [virtual-sin-resolver]#n              stub de una llamada virtual que no se compiló
  -                                     aquí empieza código sin nombre (motor, runtime de IL2CPP...): solo
                                        está para que la función anterior no se alargue hasta él

Con las líneas «-», la función de una dirección es la de mayor dirección <= ella: tools/donde.py.
No tienen nombre (quedan tras una línea «-»): los generadores de atributos y las funciones auxiliares
que IL2CPP genera fuera de las tablas, su runtime y el motor de Unity.

Los tipos de los parámetros van sin namespace; `&` es ref/out. Solo entiende la metadata versión 27
con el formato de Unity 2020.2.4 o posterior (27.1; Disco Elysium es 2020.3.12f1): con otro se para.
"""
from __future__ import annotations

import re
import struct
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULTS = (ROOT / "work/scope/main.elf",
            ROOT / "work/romfs/Data/Managed/Metadata/global-metadata.dat",
            ROOT / "work/scope/il2cpp_methods.tsv")

PT_LOAD, PT_DYNAMIC = 1, 2
DT_RELA, DT_RELASZ = 7, 8
R_AARCH64_RELATIVE = 1027
METHOD_ATTRIBUTE_ABSTRACT = 0x0400

# Il2CppTypeEnum: los tipos que no necesitan más datos, con su nombre en C#, y los compuestos.
PRIMITIVES = {
    0x01: "void", 0x02: "bool", 0x03: "char", 0x04: "sbyte", 0x05: "byte", 0x06: "short", 0x07: "ushort",
    0x08: "int", 0x09: "uint", 0x0A: "long", 0x0B: "ulong", 0x0C: "float", 0x0D: "double", 0x0E: "string",
    0x16: "TypedReference", 0x18: "IntPtr", 0x19: "UIntPtr", 0x1C: "object",
}
T_PTR, T_VALUETYPE, T_CLASS, T_VAR, T_ARRAY, T_GENERICINST = 0x0F, 0x11, 0x12, 0x13, 0x14, 0x15
T_SZARRAY, T_MVAR = 0x1D, 0x1E

# Secciones de global-metadata.dat en el orden de su cabecera (v27): de cada una, offset y tamaño.
SECTIONS = (
    "stringLiteral stringLiteralData string events properties methods parameterDefaultValues "
    "fieldDefaultValues fieldAndParameterDefaultValueData fieldMarshaledSizes parameters fields "
    "genericParameters genericParameterConstraints genericContainers nestedTypes interfaces vtableMethods "
    "interfaceOffsets typeDefinitions images assemblies fieldRefs referencedAssemblies attributesInfo "
    "attributeTypes unresolvedVirtualCallParameterTypes unresolvedVirtualCallParameterRanges "
    "windowsRuntimeTypeNames windowsRuntimeStrings exportedTypeDefinitions"
).split()

# Orden de las líneas que comparten dirección: método, instancia genérica, thunk, resto del pegamento.
METHOD, GENERIC, THUNK, GLUE = 0, 1, 2, 3


class Elf:
    """El ejecutable en memoria (base 0) con sus relocaciones relativas aplicadas.

    En un NSO los punteros de .data valen 0 en el fichero (los de las tablas de IL2CPP también): su
    valor es el addend de una relocación R_AARCH64_RELATIVE, que con base 0 ya es la dirección. La
    tabla de relocaciones va dentro de la propia imagen (DT_RELA), así que basta el ELF.
    """

    def __init__(self, path: Path):
        d = path.read_bytes()
        if d[:5] != b"\x7fELF\x02" or struct.unpack_from("<H", d, 18)[0] != 183:
            raise SystemExit(f"{path}: no es un ELF64 de AArch64")
        phoff = struct.unpack_from("<Q", d, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", d, 0x36)
        loads, dynamic = [], None
        for k in range(phnum):
            kind, flags, off, vaddr, _, filesz, _, _ = struct.unpack_from("<IIQQQQQQ", d, phoff + k * phentsize)
            if kind == PT_LOAD:
                loads.append((vaddr, off, filesz, flags))
            elif kind == PT_DYNAMIC:
                dynamic = vaddr
        self.mem = bytearray(max(vaddr + filesz for vaddr, _, filesz, _ in loads))
        for vaddr, off, filesz, _ in loads:
            self.mem[vaddr:vaddr + filesz] = d[off:off + filesz]
        self.text = next((vaddr, vaddr + filesz) for vaddr, _, filesz, flags in loads if flags & 1)
        self.data = [(vaddr, vaddr + filesz) for vaddr, _, filesz, flags in loads if not flags & 1]

        tags = {}
        while dynamic is not None:
            tag, value = struct.unpack_from("<qQ", self.mem, dynamic)
            if tag == 0:
                break
            tags.setdefault(tag, value)
            dynamic += 16
        start, size = tags.get(DT_RELA, 0), tags.get(DT_RELASZ, 0)
        self.relocations = 0
        self.code_pointers = set()  # todo puntero a .text guardado en los datos pasa por una relocación
        for where, info, addend in struct.iter_unpack("<QQq", bytes(self.mem[start:start + size])):
            if info & 0xFFFFFFFF == R_AARCH64_RELATIVE and where + 8 <= len(self.mem):
                struct.pack_into("<q", self.mem, where, addend)
                self.relocations += 1
                if self.is_code(addend):
                    self.code_pointers.add(addend)
        if not self.relocations:
            raise SystemExit(f"{path}: sin relocaciones R_AARCH64_RELATIVE, los punteros de .data quedarían a 0")

    def u64(self, addr: int) -> int:
        return struct.unpack_from("<Q", self.mem, addr)[0]

    def u64s(self, addr: int, n: int) -> tuple:
        return struct.unpack_from(f"<{n}Q", self.mem, addr) if n else ()

    def table(self, fmt: str, addr: int, n: int) -> list:
        return list(struct.iter_unpack(fmt, bytes(self.mem[addr:addr + n * struct.calcsize(fmt)])))

    def cstr(self, addr: int) -> str:
        end = self.mem.find(0, addr, addr + 512)
        return self.mem[addr:max(end, addr)].decode("utf-8", "replace")

    def is_data(self, addr: int) -> bool:
        return any(start <= addr < end for start, end in self.data)

    def is_code(self, addr: int) -> bool:
        return self.text[0] <= addr < self.text[1]

    def pointers_to(self, value: int):
        """Direcciones de los datos (alineadas a 8) que guardan `value`."""
        pattern = struct.pack("<Q", value)
        for start, end in self.data:
            pos = self.mem.find(pattern, start, end)
            while pos >= 0:
                if pos % 8 == 0:
                    yield pos
                pos = self.mem.find(pattern, pos + 1, end)

    def bl_targets(self) -> set:
        """Destinos de todas las instrucciones BL de .text: ahí empieza seguro una función."""
        start, end = self.text
        text = bytes(self.mem[start:end])
        targets = set()
        for m in re.finditer(rb"[\x94-\x97]", text[3::4]):  # el byte alto de BL es 100101xx
            pc = m.start() * 4
            imm = struct.unpack_from("<I", text, pc)[0] & 0x3FFFFFF
            targets.add(start + pc + ((imm ^ 0x2000000) - 0x2000000) * 4)
        return targets


class Metadata:
    """global-metadata.dat: las tablas con los nombres (imágenes, tipos, métodos, parámetros)."""

    def __init__(self, path: Path):
        d = self.d = path.read_bytes()
        magic, self.version = struct.unpack_from("<Ii", d, 0)
        if magic != 0xFAB11BAF:
            raise SystemExit(f"{path}: no es un global-metadata.dat (empieza por {magic:#x})")
        if self.version != 27:
            raise SystemExit(f"{path}: metadata versión {self.version}; este script solo entiende la 27")
        header = struct.unpack_from(f"<{2 * len(SECTIONS)}i", d, 8)
        self.sections = {name: (header[2 * k], header[2 * k + 1]) for k, name in enumerate(SECTIONS)}
        self._strings = {}
        # (nameIndex, assemblyIndex, typeStart, typeCount, exportedTypeStart, exportedTypeCount,
        #  entryPointIndex, token, customAttributeStart, customAttributeCount)
        self.images = self._table("images", "<IiiIiIiIiI")
        # [0] nameIndex  [1] namespaceIndex  [6] genericContainerIndex  [9] methodStart
        # [12] nestedTypesStart  [16] method_count  [20] nested_type_count
        self.types = self._table("typeDefinitions", "<IIiiiiiIiiiiiiii8HII")
        # (nameIndex, declaringType, returnType, parameterStart, genericContainerIndex, token, flags,
        #  iflags, slot, parameterCount)
        self.methods = self._table("methods", "<IiiiiI4H")
        self.params = self._table("parameters", "<IIi")  # (nameIndex, token, typeIndex)
        self.containers = self._table("genericContainers", "<iiii")  # (dueño, nº, es de método, primer parámetro)
        self.generic_params = self._table("genericParameters", "<iIhhHH")  # (dueño, nameIndex, -, -, num, flags)
        nested = [row[0] for row in self._table("nestedTypes", "<i")]
        self.parent = {}  # tipo anidado -> el tipo que lo declara
        for k, t in enumerate(self.types):
            for child in nested[t[12]:t[12] + t[20]]:
                self.parent[child] = k
        self.type_image = [0] * len(self.types)
        for k, image in enumerate(self.images):
            for t in range(image[2], image[2] + image[3]):
                self.type_image[t] = k

    def _table(self, section: str, fmt: str) -> list:
        off, size = self.sections[section]
        if size % struct.calcsize(fmt):
            raise SystemExit(f"metadata: la sección {section} no cuadra con el formato de la versión 27")
        return list(struct.iter_unpack(fmt, self.d[off:off + size]))

    def string(self, index: int) -> str:
        s = self._strings.get(index)
        if s is None:
            start = self.sections["string"][0] + index
            s = self._strings[index] = self.d[start:self.d.index(b"\0", start)].decode("utf-8", "replace")
        return s

    def image_name(self, k: int) -> str:
        return self.string(self.images[k][0])

    def generic_names(self, container: int) -> list:
        """Nombres de los parámetros genéricos de un contenedor (T, TKey...)."""
        if container < 0:
            return []
        _, n, _, first = self.containers[container]
        return [self.string(p[1]) for p in self.generic_params[first:first + n]]


class Il2Cpp:
    """Las tablas que IL2CPP deja en el binario: Il2CppCodeRegistration e Il2CppMetadataRegistration."""

    def __init__(self, elf: Elf, md: Metadata):
        self.elf, self.md = elf, md
        self._find_code_registration()
        self._find_metadata_registration()

    def _find_modules(self, names: set) -> tuple:
        """codeGenModules: un array de punteros a Il2CppCodeGenModule, uno por imagen de la metadata.

        Se llega desde el nombre de un módulo: su cadena -> el módulo que la apunta -> el array que
        apunta al módulo. Devuelve (dirección del array, nº de módulos).
        """
        elf = self.elf

        def is_module(p: int) -> bool:
            return elf.is_data(p) and elf.is_data(elf.u64(p)) and elf.cstr(elf.u64(p)) in names

        for name in sorted(names, key=lambda n: n != "mscorlib.dll"):
            pattern = b"\0" + name.encode() + b"\0"
            for start, end in elf.data:
                pos = elf.mem.find(pattern, start, end)
                while pos >= 0:
                    for module in elf.pointers_to(pos + 1):
                        for slot in elf.pointers_to(module):
                            while is_module(elf.u64(slot - 8)):
                                slot -= 8
                            n = 0
                            while is_module(elf.u64(slot + 8 * n)):
                                n += 1
                            if n == len(names):
                                return slot, n
                    pos = elf.mem.find(pattern, pos + 1, end)
        raise SystemExit("no encuentro codeGenModules (los módulos de IL2CPP) en el binario")

    def _find_code_registration(self):
        elf, md = self.elf, self.md
        array, n = self._find_modules({md.image_name(k) for k in range(len(md.images))})
        # Il2CppCodeGenModule (27.1), 18 campos de 8 bytes:
        #  0 moduleName  1 methodPointerCount  2 methodPointers  3 adjustorThunkCount  4 adjustorThunks
        #  5 invokerIndices  6 reversePInvokeWrapperCount  7 reversePInvokeWrapperIndices  8-11 rgctx
        #  12 debuggerMetadata  13 customAttributeCacheGenerator  14 moduleInitializer
        #  15 staticConstructorTypeIndices  16 metadataRegistration  17 codeRegistration
        self.modules = {}
        for p in elf.u64s(array, n):
            fields = elf.u64s(p, 18)
            # En el formato 27.0 (sin adjustor thunks) el campo 3 sería el puntero invokerIndices.
            if fields[1] and (elf.is_data(fields[3]) or not elf.is_data(fields[2])):
                raise SystemExit("Il2CppCodeGenModule no tiene el formato 27.1 (Unity 2020.2.4+): no soportado")
            self.modules[elf.cstr(fields[0])] = fields
        # Il2CppCodeRegistration (27.1), 15 campos; acaba en (codeGenModulesCount, codeGenModules):
        #  0 reversePInvokeWrapperCount  1 reversePInvokeWrappers  2 genericMethodPointersCount
        #  3 genericMethodPointers  4 genericAdjustorThunks  5 invokerPointersCount  6 invokerPointers
        #  7 unresolvedVirtualCallCount  8 unresolvedVirtualCallPointers  9 interopDataCount
        #  10 interopData  11 windowsRuntimeFactoryCount  12 windowsRuntimeFactoryTable
        #  13 codeGenModulesCount  14 codeGenModules
        for p in elf.pointers_to(array):
            fields = elf.u64s(p - 8 * 14, 15)
            counts_ok = fields[13] == n and all(fields[k] < 1 << 24 for k in (0, 2, 5, 7, 9, 11))
            if counts_ok and all(not fields[k] or elf.is_data(fields[k]) for k in (1, 3, 4, 6, 8, 10, 12)):
                self.code_registration, self.cr = p - 8 * 14, fields
                return
        raise SystemExit("no encuentro Il2CppCodeRegistration (¿formato distinto del 27.1?)")

    def _find_metadata_registration(self):
        """Il2CppMetadataRegistration, 16 campos: se reconoce porque fieldOffsetsCount y
        typeDefinitionsSizesCount valen los dos el número de tipos de la metadata.

         0 genericClassesCount  1 genericClasses  2 genericInstsCount  3 genericInsts
         4 genericMethodTableCount  5 genericMethodTable  6 typesCount  7 types  8 methodSpecsCount
         9 methodSpecs  10 fieldOffsetsCount  11 fieldOffsets  12 typeDefinitionsSizesCount
         13 typeDefinitionsSizes  14 metadataUsagesCount  15 metadataUsages
        """
        elf, n = self.elf, len(self.md.types)
        for p in elf.pointers_to(n):
            fields = elf.u64s(p - 8 * 10, 16)
            if fields[12] == n and all(elf.is_data(fields[k]) for k in (3, 5, 7, 9, 11, 13)):
                self.metadata_registration, self.mr = p - 8 * 10, fields
                self.types = elf.u64s(fields[7], fields[6])  # Il2CppType* de cada TypeIndex
                self.insts = elf.u64s(fields[3], fields[2])  # Il2CppGenericInst* de cada GenericInstIndex
                # (genericMethodIndex, methodIndex, invokerIndex, adjustorThunkIndex)
                self.generic_table = elf.table("<iiii", fields[5], fields[4])
                # Il2CppMethodSpec: (methodDefinitionIndex, classIndexIndex, methodIndexIndex)
                self.method_specs = elf.table("<iii", fields[9], fields[8])
                return
        raise SystemExit("no encuentro Il2CppMetadataRegistration en el binario")


class Names:
    """Nombres legibles de tipos y métodos, al estilo de C#."""

    def __init__(self, il2cpp: Il2Cpp):
        self.il2cpp, self.elf, self.md = il2cpp, il2cpp.elf, il2cpp.md
        self._types, self._chains = {}, {}

    def type_def(self, index: int, args=None, full: bool = False) -> str:
        """Nombre de un tipo de la metadata: Externo<T>.Anidado, con su namespace si `full`.

        `args` son los argumentos genéricos de una instancia; sin ellos salen los nombres T, TKey...
        """
        md = self.md
        chain = self._chains.get(index)
        if chain is None:  # del tipo más externo al pedido: (nombre sin `n, nº de parámetros propios)
            parts, k = [], index
            while k is not None:
                base, _, arity = md.string(md.types[k][0]).partition("`")
                parts.append((base, int(arity) if arity.isdigit() else 0))
                outer, k = k, md.parent.get(k)
            chain = self._chains[index] = (md.string(md.types[outer][1]), parts[::-1])
        namespace, parts = chain
        if args is None:
            args = md.generic_names(md.types[index][6])
        pieces, used = [], 0
        for base, arity in parts:
            if arity:
                own = list(args[used:used + arity])
                pieces.append(f"{base}<{','.join(own + ['?'] * (arity - len(own)))}>")
                used += arity
            else:
                pieces.append(base)
        name = ".".join(pieces)
        return f"{namespace}.{name}" if full and namespace else name

    def inst(self, addr: int, ctx) -> tuple:
        """Los tipos de un Il2CppGenericInst {type_argc, type_argv}."""
        if not addr:
            return ()
        argc, argv = self.elf.u64s(addr, 2)
        return tuple(self.type(t, ctx) for t in self.elf.u64s(argv, argc & 0xFFFFFFFF))

    def type(self, addr: int, ctx=(None, None), full: bool = False) -> str:
        """Nombre de un Il2CppType {dato, attrs:16 type:8 num_mods:6 byref:1 pinned:1}, sin namespace
        salvo `full`. `ctx` = (argumentos de la clase, argumentos del método) de una instancia genérica,
        para sustituir sus parámetros."""
        key = (addr, ctx, full)
        name = self._types.get(key)
        if name is not None:
            return name
        md, elf = self.md, self.elf
        datum, bits = struct.unpack_from("<QI", elf.mem, addr)
        kind = bits >> 16 & 0xFF
        if kind in PRIMITIVES:
            name = PRIMITIVES[kind]
        elif kind in (T_VALUETYPE, T_CLASS):  # el dato es el índice del tipo en la metadata
            name = self.type_def(datum, full=full) if datum < len(md.types) else "?"
        elif kind in (T_VAR, T_MVAR):  # el dato es el índice del parámetro genérico
            param = md.generic_params[datum]
            args = ctx[kind == T_MVAR]
            name = args[param[4]] if args is not None and param[4] < len(args) else md.string(param[1])
        elif kind == T_PTR:
            name = self.type(datum, ctx) + "*"
        elif kind == T_SZARRAY:
            name = self.type(datum, ctx) + "[]"
        elif kind == T_ARRAY:  # Il2CppArrayType {etype, rank, ...}
            name = self.type(elf.u64(datum), ctx) + "[" + "," * (elf.mem[datum + 8] - 1) + "]"
        elif kind == T_GENERICINST:  # Il2CppGenericClass {type, class_inst, method_inst, cached_class}
            definition, class_inst = elf.u64s(datum, 2)
            name = self.type_def(elf.u64(definition), self.inst(class_inst, ctx), full)
        else:
            name = f"?{kind:#x}"
        if bits >> 30 & 1:  # byref: ref, out, in
            name += "&"
        self._types[key] = name
        return name

    def method(self, index: int, ctx=(None, None)) -> str:
        """Namespace.Clase::Método(tipos de los parámetros) de un Il2CppMethodDefinition."""
        md = self.md
        name, declaring, _, first, container, _, _, _, _, n = md.methods[index]
        text = md.string(name)
        if container >= 0:
            text += "<" + ",".join(ctx[1] if ctx[1] is not None else md.generic_names(container)) + ">"
        params = ",".join(self.type(self.il2cpp.types[p[2]], ctx) for p in md.params[first:first + n])
        return f"{self.type_def(declaring, ctx[0], full=True)}::{text}({params})"


def collect(elf: Elf, md: Metadata, il2cpp: Il2Cpp) -> tuple:
    """Todas las funciones con nombre, {dirección: {(orden, imagen, nombre)}}, y cuántas hay de cada."""
    names = Names(il2cpp)
    rows, counts = {}, Counter()
    cr = il2cpp.cr

    def add(addr: int, order: tuple, image: str, name: str, what: str):
        if elf.is_code(addr):
            rows.setdefault(addr, set()).add((order, image, name))
            counts[what] += 1
        else:
            counts[f"{what} con el puntero fuera de .text"] += 1

    # Métodos: el puntero del método con token 0x06rrrrrr es methodPointers[rrrrrr - 1] de su módulo.
    reverse_wrappers = elf.u64s(cr[1], cr[0])
    for k, image in enumerate(md.images):
        image_name = md.image_name(k)
        module = il2cpp.modules[image_name]
        pointers = elf.u64s(module[2], module[1])
        by_token = {}
        for t in range(image[2], image[2] + image[3]):
            type_ = md.types[t]
            for m in range(type_[9], type_[9] + type_[16]):
                method = md.methods[m]
                by_token[method[5]] = m
                rid = method[5] & 0xFFFFFF
                addr = pointers[rid - 1] if 0 < rid <= len(pointers) else 0
                if addr:
                    add(addr, (METHOD,), image_name, names.method(m), "métodos con código")
                elif method[6] & METHOD_ATTRIBUTE_ABSTRACT:
                    counts["métodos sin código: abstractos y de interfaz"] += 1
                elif type_[6] >= 0 or method[4] >= 0:
                    counts["métodos sin código propio: genéricos (su código son las instancias)"] += 1
                else:
                    counts["métodos sin código: otros"] += 1
        # Adjustor thunks del módulo: pares {token, puntero}.
        for token, addr in elf.table("<IxxxxQ", module[4], module[3]):
            add(addr, (THUNK,), image_name, "[thunk]" + names.method(by_token[token]), "adjustor thunks")
        # Reverse P/Invoke: {token, índice en reversePInvokeWrappers, MethodInfo**, genericMethodIndex}.
        for token, index, _, _ in elf.table("<IiQQ", module[7], module[6]):
            add(reverse_wrappers[index], (GLUE,), image_name, "[pinvoke-inverso]" + names.method(by_token[token]),
                "reverse P/Invoke")

    # Instancias de métodos genéricos: cada fila de genericMethodTable da un Il2CppMethodSpec (la
    # definición y sus argumentos de clase y de método) y el índice de su código en
    # genericMethodPointers. Las instancias con tipos referencia comparten el código de la de object.
    pointers = elf.u64s(cr[3], cr[2])
    thunks = elf.u64s(cr[4], max((row[3] for row in il2cpp.generic_table), default=-1) + 1)
    for spec, index, _, thunk in il2cpp.generic_table:
        definition, class_inst, method_inst = il2cpp.method_specs[spec]
        ctx = (names.inst(il2cpp.insts[class_inst], (None, None)) if class_inst >= 0 else None,
               names.inst(il2cpp.insts[method_inst], (None, None)) if method_inst >= 0 else None)
        image_name = md.image_name(md.type_image[md.methods[definition][1]])
        name = names.method(definition, ctx)
        args = (ctx[0] or ()) + (ctx[1] or ())
        order = (GENERIC, sum(arg != "object" for arg in args), len(name))
        if 0 <= index < len(pointers) and pointers[index]:
            add(pointers[index], order, image_name, name, "instancias genéricas con código")
        else:
            counts["instancias genéricas sin código"] += 1
        if thunk >= 0 and thunks[thunk]:
            add(thunks[thunk], (THUNK,) + order, image_name, "[thunk]" + name,
                "adjustor thunks de instancias genéricas")

    # Pegamento que no es de ningún método.
    for n, addr in enumerate(elf.u64s(cr[6], cr[5])):
        add(addr, (GLUE,), "-", f"[invoker]#{n}", "invokers")
    for n, addr in enumerate(elf.u64s(cr[8], cr[7])):
        add(addr, (GLUE,), "-", f"[virtual-sin-resolver]#{n}", "stubs de llamada virtual sin resolver")
    # Il2CppInteropData {delegatePInvokeWrapper, marshalToNative, marshalFromNative, marshalCleanup,
    #                    createCCW, guid, type}
    kinds = ("delegado-pinvoke", "marshal-a-nativo", "marshal-de-nativo", "marshal-limpieza", "ccw")
    for interop in elf.table("<7Q", cr[10], cr[9]):
        type_name = names.type(interop[6], full=True) if interop[6] else "?"
        for kind, addr in zip(kinds, interop):
            if addr:
                add(addr, (GLUE,), "-", f"[{kind}]{type_name}", "funciones de interop (delegados y marshal)")
    return rows, counts


def write(elf: Elf, rows: dict, out: Path) -> tuple:
    """Escribe la tabla. Pone una línea «-» donde, después de una función con nombre, empieza otra
    que no lo tiene (un destino de BL o de un puntero de los datos) y al acabar .text.
    Devuelve (nº de líneas, nº de líneas «-», inicios de función sin nombre)."""
    unnamed = (elf.bl_targets() | elf.code_pointers) - set(rows)
    lines, cuts, named = [], 0, False
    for addr in sorted(set(rows) | unnamed | {elf.text[1]}):
        if addr in rows:
            lines += [f"{addr:x}\t{image}\t{name}\n" for _, image, name in sorted(rows[addr])]
            named = True
        elif named:
            lines.append(f"{addr:x}\t-\t-\n")
            cuts += 1
            named = False
    out.write_text("".join(lines), encoding="utf-8")
    return len(lines), cuts, unnamed


def main():
    args = sys.argv[1:]
    if len(args) > 3 or any(a.startswith("-") for a in args):
        raise SystemExit(__doc__)
    elf_path, metadata_path, out = [Path(a) for a in args] + list(DEFAULTS[len(args):])

    elf = Elf(elf_path)
    md = Metadata(metadata_path)
    il2cpp = Il2Cpp(elf, md)
    rows, counts = collect(elf, md, il2cpp)
    lines, cuts, unnamed = write(elf, rows, out)
    # Los métodos y las instancias genéricas van juntos en una sección propia al final de .text.
    managed = min(addr for addr, group in rows.items() if any(row[0][0] in (METHOD, GENERIC) for row in group))
    gaps = sorted(addr for addr in unnamed if addr >= managed)

    print(f"metadata v{md.version}: {len(md.images)} imágenes, {len(md.types)} tipos, {len(md.methods)} métodos")
    print(f"{elf_path.name}: {elf.relocations} relocaciones R_AARCH64_RELATIVE aplicadas")
    print(f"Il2CppCodeRegistration en {il2cpp.code_registration:#x} ({len(il2cpp.modules)} módulos), "
          f"Il2CppMetadataRegistration en {il2cpp.metadata_registration:#x}")
    for what, n in sorted(counts.items(), key=lambda item: (" sin código" in item[0], -item[1])):
        print(f"  {n:7d}  {what}")
    generic = {addr for addr, group in rows.items() if any(row[0][0] == GENERIC for row in group)}
    print(f"  las instancias genéricas ocupan {len(generic)} direcciones: las que comparten código son líneas "
          "seguidas con la misma dirección")
    print(f"código gestionado (métodos e instancias): {managed:#x}-{elf.text[1]:#x}")
    if gaps:
        print(f"  OJO: {len(gaps)} funciones sin nombre dentro (la primera en {gaps[0]:#x}): "
              "ahí la tabla no es completa")
    else:
        print("  completo: ahí todo destino de BL y todo puntero a código es una función de la tabla")
    print(f"{out}: {lines} líneas, {len(rows)} direcciones con nombre, {cuts} cortes «-»")


if __name__ == "__main__":
    main()
