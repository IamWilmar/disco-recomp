#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Auditoría offline de TODOS los shaders de Switch del juego (sin tocar la consola).

Saca del romfs y del ejecutable cada programa NVN (código de Maxwell + sección de control) con el nombre del Shader de
Unity, el pase, la variante (keywords) y la etapa; los pasa por shadertool (el mismo traductor que la Flip), valida el
SPIR-V con spirv-val y saca la tabla huella -> nombre y las estadísticas que importan en el Adreno.

    python3 tools/shader_audit.py                 todo: extraer, traducir e informe (work/shader_audit/)
    python3 tools/shader_audit.py extraer|traducir|informe
    python3 tools/shader_audit.py huella c806e344e1d295ec …     qué shader de Unity es cada huella
    python3 tools/shader_audit.py log work/runs/limbo1.log      pone nombre a las huellas de un log de la consola
    python3 tools/shader_audit.py volcados work/at work/pares   compara volcados de la consola con lo extraído

Solo biblioteca estándar (el Python 3.9 del sistema): los contenedores de Unity (UnityFS, ficheros serializados, type
trees) se leen aquí mismo; el LZ4 es el de libcompression de macOS (o uno en Python puro si no está).

Dónde están los shaders (comprobado en Disco Elysium, Unity 2020.3.12f1):
- Objetos Shader (clase 48): m_ParsedForm (pases, keywords) + compressedBlob (LZ4 por plataforma y segmento). Cada
  subprograma del blob (cabecera 201806140, tipo 26 = ConsoleVS) lleva TODAS las etapas de la variante en un contenedor:
  4 tablas de 6 enteros (una entrada por etapa de NVN: 0 vertex, 1 pixel, 2 geometry, 3 tess-control, 4 tess-eval,
  5 compute; -1 = no hay) y, por etapa, la sección de control (0x880 bytes, magia 0x98761234) seguida del código (cabecera
  0x12345678 de 0x30 bytes, SPH de Maxwell, instrucciones y constantes).
- Objetos ComputeShader (clase 72, solo en "unity default resources"): el mismo contenedor, sin comprimir, por kernel. El
  código de compute no lleva cabecera (el tipo va en control+0x714 == 5, como en MH Rise).
- El ejecutable (exefs/main, .rodata): shaders internos del motor como salidas completas de GLSLC (magia 0x19866891,
  cabecera de 0x240 bytes, control y código).
La huella es la del runtime (nnsdk/nvn/program.cpp, code_print): FNV-1a de 64 bits del código hasta donde empiezan sus
constantes (control+0x700).
"""

import argparse
import collections
import concurrent.futures
import ctypes
import hashlib
import json
import lzma
import mmap
import os
import re
import struct
import subprocess
import sys
import time

# --------------------------------------------------------------------------------------------------------------------
# Rutas

def raiz_principal():
    """El checkout que tiene work/, build/ y third_party/ (no van en git): este o, desde un worktree, el principal."""
    aqui = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.isdir(os.path.join(aqui, 'work')):
        return aqui
    try:
        comun = subprocess.run(['git', '-C', aqui, 'rev-parse', '--path-format=absolute', '--git-common-dir'],
                               capture_output=True, text=True).stdout.strip()
        if comun and os.path.isdir(os.path.join(os.path.dirname(comun), 'work')):
            return os.path.dirname(comun)
    except OSError:
        pass
    return aqui


RAIZ = raiz_principal()
NDK = os.path.join(os.environ.get('ANDROID_HOME', os.path.expanduser('~/Library/Android/sdk')), 'ndk', '28.2.13676358')

ETAPAS = ['vertex', 'pixel', 'geometry', 'tess-control', 'tess-eval', 'compute']  # orden de NVNshaderStage
SPH_ETAPA = {1: 'vertex', 2: 'tess-control', 3: 'tess-eval', 4: 'geometry', 5: 'pixel'}  # SPH common0.shader_type
MAGIA_CONTROL = b'\x34\x12\x76\x98'  # 0x98761234
MAGIA_CODIGO = b'\x78\x56\x34\x12'   # 0x12345678
MAGIA_GLSLC = b'\x91\x68\x86\x19'    # 0x19866891

# --------------------------------------------------------------------------------------------------------------------
# LZ4 (bloque crudo): los bloques de UnityFS y los blobs de los Shader


def _lz4_python(src, usize):
    dst = bytearray()
    i, n = 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        dst += src[i:i + lit]
        i += lit
        if i >= n:
            break
        offset = src[i] | src[i + 1] << 8
        i += 2
        length = token & 15
        if length == 15:
            while True:
                b = src[i]
                i += 1
                length += b
                if b != 255:
                    break
        length += 4
        start = len(dst) - offset
        if offset >= length:
            dst += dst[start:start + length]
        else:  # solapado: el patrón de `offset` bytes se repite
            chunk = bytes(dst[start:])
            dst += (chunk * (length // offset + 1))[:length]
    if len(dst) != usize:
        raise ValueError('LZ4: %d bytes, se esperaban %d' % (len(dst), usize))
    return bytes(dst)


try:
    _libcompression = ctypes.CDLL('/usr/lib/libcompression.dylib')
    _libcompression.compression_decode_buffer.restype = ctypes.c_size_t
    _libcompression.compression_decode_buffer.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                                                          ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
except OSError:
    _libcompression = None


def lz4(src, usize):
    src = bytes(src)
    if _libcompression is not None:
        dst = ctypes.create_string_buffer(usize)
        if _libcompression.compression_decode_buffer(dst, usize, src, len(src), None, 0x101) == usize:  # LZ4_RAW
            return dst.raw
    return _lz4_python(src, usize)


# --------------------------------------------------------------------------------------------------------------------
# Lector binario


class Lector:
    def __init__(self, datos, pos=0, big=False):
        self.b, self.p, self.e = datos, pos, '>' if big else '<'

    def _leer(self, fmt, n):
        v = struct.unpack_from(self.e + fmt, self.b, self.p)[0]
        self.p += n
        return v

    def u8(self): return self._leer('B', 1)
    def i16(self): return self._leer('h', 2)
    def u16(self): return self._leer('H', 2)
    def i32(self): return self._leer('i', 4)
    def u32(self): return self._leer('I', 4)
    def i64(self): return self._leer('q', 8)

    def crudo(self, n):
        if n < 0 or self.p + n > len(self.b):
            raise ValueError('lectura fuera del fichero (%d bytes en 0x%x)' % (n, self.p))
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    def cadena0(self):
        fin = self.b.index(b'\0', self.p)
        v = bytes(self.b[self.p:fin]).decode('utf8', 'replace')
        self.p = fin + 1
        return v

    def cadena(self):  # cadena de Unity: longitud, bytes y relleno a 4
        n = self.i32()
        if n < 0 or n > 4096:
            raise ValueError('cadena de %d bytes en 0x%x' % (n, self.p - 4))
        v = bytes(self.crudo(n)).decode('utf8', 'replace')
        self.alinear(4)
        return v

    def alinear(self, n=4):
        self.p = (self.p + n - 1) // n * n


# --------------------------------------------------------------------------------------------------------------------
# Unity: UnityFS, ficheros serializados y type trees

# La tabla de cadenas comunes de los type trees de Unity (los offsets con el bit 31 apuntan aquí). Cada offset es la suma
# de las longitudes anteriores, así que basta la lista en orden.
_COMUNES = ("AABB AnimationClip AnimationCurve AnimationState Array Base BitField bitset bool char ColorRGBA Component "
            "data deque double dynamic_array FastPropertyName first float Font GameObject Generic|Mono GradientNEW GUID "
            "GUIStyle int list long|long map Matrix4x4f MdFour MonoBehaviour MonoScript m_ByteSize m_Curve "
            "m_EditorClassIdentifier m_EditorHideFlags m_Enabled m_ExtensionPtr m_GameObject m_Index m_IsArray m_IsStatic "
            "m_MetaFlag m_Name m_ObjectHideFlags m_PrefabInternal m_PrefabParentObject m_Script m_StaticEditorFlags "
            "m_Type m_Version Object pair PPtr<Component> PPtr<GameObject> PPtr<Material> PPtr<MonoBehaviour> "
            "PPtr<MonoScript> PPtr<Object> PPtr<Prefab> PPtr<Sprite> PPtr<TextAsset> PPtr<Texture> PPtr<Texture2D> "
            "PPtr<Transform> Prefab Quaternionf Rectf RectInt RectOffset second set short size SInt16 SInt32 SInt64 "
            "SInt8 staticvector string TextAsset TextMesh Texture Texture2D Transform TypelessData UInt16 UInt32 UInt64 "
            "UInt8 unsigned|int unsigned|long|long unsigned|short vector Vector2f Vector3f Vector4f "
            "m_ScriptingClassIdentifier Gradient Type* int2_storage int3_storage BoundsInt m_CorrespondingSourceObject "
            "m_PrefabInstance m_PrefabAsset FileSize Hash128 RenderingLayerMask")
_COMUNES_BLOB = b''.join(s.replace('|', ' ').encode() + b'\0' for s in _COMUNES.split())

CLASE_SHADER, CLASE_COMPUTE = 48, 72


def abrir_bundle(datos):
    """Nodos de un UnityFS: [(ruta, es_serializado, bytes)] con los bloques ya descomprimidos."""
    r = Lector(datos, 0, True)
    if r.cadena0() != 'UnityFS':
        raise ValueError('no es UnityFS')
    version = r.u32()
    r.cadena0()
    r.cadena0()
    r.i64()
    csize, usize, flags = r.u32(), r.u32(), r.u32()
    if version >= 7:
        r.alinear(16)
    info = datos[len(datos) - csize:] if flags & 0x80 else r.crudo(csize)
    comp = flags & 0x3F
    if comp in (2, 3):
        info = lz4(info, usize)
    elif comp == 1:
        info = _lzma_unity(info, usize)
    elif comp != 0:
        raise ValueError('compresión %d del índice de bloques' % comp)
    ri = Lector(info, 16, True)
    bloques = [(ri.u32(), ri.u32(), ri.u16()) for _ in range(ri.i32())]
    nodos = []
    for _ in range(ri.i32()):
        off, tam, nflags = ri.i64(), ri.i64(), ri.u32()
        nodos.append((off, tam, nflags, ri.cadena0()))
    if flags & 0x200:
        r.alinear(16)
    partes, p = [], r.p
    for utam, ctam, bflags in bloques:
        trozo = datos[p:p + ctam]
        p += ctam
        c = bflags & 0x3F
        if c == 0:
            partes.append(bytes(trozo))
        elif c in (2, 3):
            partes.append(lz4(trozo, utam))
        elif c == 1:
            partes.append(_lzma_unity(trozo, utam))
        else:
            raise ValueError('compresión %d de un bloque' % c)
    todo = b''.join(partes)
    return [(ruta, bool(nflags & 4), todo[off:off + tam]) for off, tam, nflags, ruta in nodos]


def _lzma_unity(trozo, usize):
    props = trozo[0]
    filtro = {'id': lzma.FILTER_LZMA1, 'dict_size': struct.unpack_from('<I', trozo, 1)[0], 'lc': props % 9,
              'lp': props // 9 % 5, 'pb': props // 45}
    return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[filtro]).decompress(bytes(trozo[5:]), usize)


def es_serializado(cabeza):
    """Cabecera de un fichero serializado de Unity 2020+ (versión 22: tamaños de 64 bits)."""
    return len(cabeza) >= 48 and cabeza[:8] == b'\0' * 8 and 22 <= struct.unpack_from('>I', cabeza, 8)[0] <= 40


def abrir_serializado(b):
    """Tipos y objetos de un fichero serializado: ({'tipos': [(clase, hash, nodos|None)], 'objetos': [(id, pos, tam, clase, hash)]})."""
    r = Lector(b, 8, True)
    version = r.u32()
    r.u32()
    big = r.u8()
    r.crudo(3)
    r.u32()
    r.i64()
    datos = r.i64()
    r.i64()
    r.e = '>' if big else '<'
    unity = r.cadena0()
    r.i32()  # plataforma (38 = Switch)
    con_arbol = r.u8()
    tipos = []
    for _ in range(r.i32()):
        clase = r.i32()
        r.u8()
        r.i16()
        if clase == 114:  # MonoBehaviour: hash del script
            r.crudo(16)
        huella = bytes(r.crudo(16))
        nodos = None
        if con_arbol:
            n, tam = r.i32(), r.i32()
            crudos, cadenas = bytes(r.crudo(n * 32)), bytes(r.crudo(tam))
            nodos = _nodos_arbol(n, crudos, cadenas)
            r.crudo(4 * r.i32())  # dependencias de tipos
        tipos.append((clase, huella, nodos))
    objetos = []
    for _ in range(r.i32()):
        r.alinear(4)
        ident, pos, tam, tipo = r.i64(), r.i64(), r.u32(), r.i32()
        objetos.append((ident, pos + datos, tam, tipos[tipo][0], tipos[tipo][1]))
    return {'unity': unity, 'tipos': tipos, 'objetos': objetos}


def _nodos_arbol(n, crudos, cadenas):
    def texto(off):
        tabla = _COMUNES_BLOB if off & 0x80000000 else cadenas
        off &= 0x7FFFFFFF
        return tabla[off:tabla.index(b'\0', off)].decode()
    nodos = []
    for k in range(n):
        _, nivel, _, tipo, nombre, _, _, meta, _ = struct.unpack_from('<HBBIIiiiQ', crudos, k * 32)
        nodos.append((nivel, texto(tipo), texto(nombre), meta))
    return nodos


_PRIMITIVOS = {'SInt8': 'b', 'UInt8': 'B', 'char': 'B', 'bool': '?', 'SInt16': 'h', 'short': 'h', 'UInt16': 'H',
               'unsigned short': 'H', 'SInt32': 'i', 'int': 'i', 'UInt32': 'I', 'unsigned int': 'I', 'Type*': 'I',
               'SInt64': 'q', 'long long': 'q', 'UInt64': 'Q', 'unsigned long long': 'Q', 'FileSize': 'Q', 'float': 'f',
               'double': 'd'}


def _fin_subarbol(nodos, i):
    j = i + 1
    while j < len(nodos) and nodos[j][0] > nodos[i][0]:
        j += 1
    return j


def leer_arbol(nodos, r, i=0):
    """Un valor según su type tree: dict (clases), list (vectores), bytes (vectores de bytes), str, números."""
    nivel, tipo, _, meta = nodos[i]
    alinear = bool(meta & 0x4000)
    if tipo in _PRIMITIVOS:
        f = _PRIMITIVOS[tipo]
        v = r._leer(f, struct.calcsize(f))
    elif tipo == 'string':
        v = bytes(r.crudo(r.i32())).decode('utf8', 'replace')
        alinear = True
    elif tipo == 'TypelessData':
        v = bytes(r.crudo(r.i32()))
    elif i + 1 < len(nodos) and nodos[i + 1][1] == 'Array' and nodos[i + 1][0] == nivel + 1:
        alinear = alinear or bool(nodos[i + 1][3] & 0x4000)
        n = r.i32()
        if n < 0 or n > len(r.b) - r.p:  # cada elemento ocupa al menos un byte
            raise ValueError('vector de %d elementos en 0x%x' % (n, r.p - 4))
        e = i + 3  # Array, size, data
        f = _PRIMITIVOS.get(nodos[e][1])
        if f and _fin_subarbol(nodos, e) == e + 1:
            tam = struct.calcsize(f)
            if tam == 1 and f != '?':
                v = bytes(r.crudo(n))
            else:
                v = list(struct.unpack_from('<%d%s' % (n, f), r.b, r.p))
                r.p += n * tam
        else:
            v = [leer_arbol(nodos, r, e) for _ in range(n)]
    else:
        v, j, fin = {}, i + 1, _fin_subarbol(nodos, i)
        while j < fin:
            v[nodos[j][2]] = leer_arbol(nodos, r, j)
            j = _fin_subarbol(nodos, j)
    if alinear:
        r.alinear(4)
    return v


# --------------------------------------------------------------------------------------------------------------------
# Programas NVN


def fnv1a(datos):
    """La huella del runtime (program.cpp, code_print): FNV-1a de 64 bits."""
    h = 0xcbf29ce484222325
    for x in datos:
        h = ((h ^ x) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h


def huella_de(codigo, control):
    """Como code_length + code_print: hasta donde empiezan las constantes (control+0x700); 0 si no se sabe."""
    if len(control) < 0x704:
        return 0
    n = struct.unpack_from('<I', control, 0x700)[0]
    if not n or n > 0x100000 or n > len(codigo):
        return 0
    return fnv1a(codigo[:n])


def etapa_de(codigo, control):
    """La etapa: la del SPH si el código lleva la cabecera de gráficos; si no, la de la sección de control (+0x714)."""
    if codigo[:4] == MAGIA_CODIGO and len(codigo) >= 0x34:
        tipo = struct.unpack_from('<I', codigo, 0x30)[0] >> 10 & 0xF
        return SPH_ETAPA.get(tipo, 'sph%d' % tipo)
    nvn = struct.unpack_from('<I', control, 0x714)[0] if len(control) >= 0x718 else 99
    return ETAPAS[nvn] if nvn < 6 else 'etapa%d' % nvn


def partir_contenedor(blob):
    """El contenedor de Unity para Switch: 4 tablas de 6 enteros (¿?, offset, bytes de control, bytes de código) y los
    trozos control+código de cada etapa presente. Devuelve [(etapa NVN, control, código, primera tabla)]."""
    if len(blob) < 0x60:
        raise ValueError('contenedor de %d bytes' % len(blob))
    t = struct.unpack_from('<24i', blob, 0)
    que, offsets, ncontrol, ncodigo = t[0:6], t[6:12], t[12:18], t[18:24]
    fuera = []
    for k in range(6):
        if offsets[k] < 0:
            if ncontrol[k] != -1 or ncodigo[k] != -1:
                raise ValueError('tabla del contenedor incoherente')
            continue
        base = 0x60 + offsets[k]
        control = bytes(blob[base:base + ncontrol[k]])
        codigo = bytes(blob[base + ncontrol[k]:base + ncontrol[k] + ncodigo[k]])
        if control[:4] != MAGIA_CONTROL or len(codigo) != ncodigo[k] or ncontrol[k] < 0x760:
            raise ValueError('etapa %d del contenedor sin sección de control válida' % k)
        fuera.append((k, control, codigo, que[k]))
    if not fuera:
        raise ValueError('contenedor sin etapas')
    return fuera


def leer_subprograma(d):
    """Un subprograma del blob de un Shader (LoadGpuProgramFromData): keywords, código y, detrás, lo que Unity sabe de
    sus recursos (leer_reflexion)."""
    r = Lector(d)
    version, tipo = r.i32(), r.i32()
    r.crudo(16)  # estadísticas
    globales = [r.cadena() for _ in range(r.i32())]
    locales = [r.cadena() for _ in range(r.i32())] if 201806140 <= version < 202012090 else []
    codigo = bytes(r.crudo(r.i32()))
    r.alinear(4)
    try:
        reflexion = leer_reflexion(r)
    except (ValueError, struct.error, IndexError) as e:
        reflexion = {'error': repr(e)}
    return version, tipo, globales, locales, codigo, reflexion


def leer_reflexion(r):
    """La cola de un subprograma: canales de vértice, constant buffers con sus miembros (el grupo 0 son los uniforms
    sueltos) y los enlaces. En Switch el índice de un enlace lleva arriba la máscara de etapas de NVN que lo usan
    (bit 0 vertex, bit 1 pixel…) y abajo su número: la unidad de textura (handle en c2[0x168 + 8·unidad], con el sampler
    de c2[0x568 + 8·sampler]) o el binding del uniform block (el banco c3 + binding de Maxwell)."""
    r.i32()  # source map
    canales = [(r.u32(), r.u32()) for _ in range(r.i32())]

    def parametros():
        fuera = []
        for _ in range(r.i32()):
            nombre = r.cadena()
            _, filas, columnas, _, array, indice = (r.i32() for _ in range(6))
            fuera.append([nombre, indice, filas, columnas, array])
        return fuera

    cbs = {}
    for grupo in range(r.i32()):
        nombre, bytes_ = r.cadena(), r.i32()
        miembros = parametros()
        for _ in range(r.i32()):  # structs: nombre, índice, elementos, tamaño y sus miembros
            r.cadena()
            r.crudo(12)
            parametros()
        if grupo:
            cbs[nombre] = [bytes_, miembros]
    ref = {'canales': canales, 'cbs': cbs, 'texturas': [], 'bloques': [], 'buffers': [], 'uav': [], 'samplers': []}
    for _ in range(r.i32()):
        nombre, tipo, indice, extra = r.cadena(), r.i32(), r.i32(), r.i32()
        etapas, numero = indice >> 16 & 0xFFFF, indice & 0xFFFF
        if tipo == 0:
            marcas = r.u32()
            ref['texturas'].append([nombre, etapas, numero, extra, marcas >> 1, marcas & 1])  # sampler, dimensión, MS
        elif tipo == 1:
            ref['bloques'].append([nombre, etapas, numero])
        elif tipo == 2:
            ref['buffers'].append([nombre, etapas, numero])
        elif tipo == 3:
            ref['uav'].append([nombre, etapas, numero, extra])
        elif tipo == 4:
            ref['samplers'].append([etapas, numero, extra])
        else:
            raise ValueError('enlace de tipo %d' % tipo)
    ref['sobra'] = len(r.b) - r.p
    return ref


def programas_de_shader(v):
    """De un objeto Shader ya leído: [(blob, usos, keywords, [(etapa NVN, control, código, tabla0)])] por plataforma
    Switch, más los avisos. usos = pases que apuntan a ese blob."""
    forma = v['m_ParsedForm']
    usos = collections.defaultdict(list)  # blob -> [(subshader, pase, nombre, lightmode, tier)]
    for si, ss in enumerate(forma['m_SubShaders']):
        for pi, pase in enumerate(ss['m_Passes']):
            estado = pase['m_State']
            tags = {t['first']: t['second'] for t in estado['m_Tags']['tags']}
            for prog in ('progVertex', 'progFragment', 'progGeometry', 'progHull', 'progDomain', 'progRayTracing'):
                for sp in pase.get(prog, {}).get('m_SubPrograms', []):
                    usos[sp['m_BlobIndex']].append((si, pi, estado['m_Name'], tags.get('LIGHTMODE', ''),
                                                    sp['m_ShaderHardwareTier']))
    fuera, avisos = [], []
    blob = v['compressedBlob']
    for k, plataforma in enumerate(v['platforms']):
        segmentos = [lz4(blob[o:o + c], d) for o, c, d in
                     zip(v['offsets'][k], v['compressedLengths'][k], v['decompressedLengths'][k])]
        magias = sum(s.count(MAGIA_CONTROL + b'\x01\0\0\0') for s in segmentos)
        r = Lector(segmentos[0])
        entradas = [(r.i32(), r.i32(), r.i32()) for _ in range(r.i32())]  # offset, longitud, segmento (2019.3+)
        vistos = 0
        for indice, (off, lon, seg) in enumerate(entradas):
            try:
                _, _, globales, locales, codigo, reflexion = leer_subprograma(segmentos[seg][off:off + lon])
                etapas = partir_contenedor(codigo)
            except (ValueError, struct.error) as e:
                avisos.append('plataforma %d, blob %d: %s' % (plataforma, indice, e))
                continue
            vistos += len(etapas)
            if reflexion.get('error') or reflexion.get('sobra'):
                avisos.append('plataforma %d, blob %d: reflexión sin leer entera (%s)' % (
                    plataforma, indice, reflexion.get('error') or '%d bytes de más' % reflexion['sobra']))
            fuera.append((indice, usos.get(indice, []), globales + locales, etapas, reflexion))
        if vistos != magias:  # nada dentro del blob se queda sin extraer
            avisos.append('plataforma %d: %d secciones de control en el blob y %d extraídas' % (plataforma, magias, vistos))
    return fuera, avisos


def programas_de_compute(o):
    """Kernels de un objeto ComputeShader de Unity 2020.3 (sin type tree en el juego: disposición leída de los bytes de
    'unity default resources'): nombre; variantes por plataforma {renderer, nivel, kernels, constant buffers, bool};
    kernel {nombre, variantes {clave, índices de cb, cbs, texturas, samplers, buffers de entrada y de salida, código,
    tamaño de grupo}, keywords globales y locales}. Devuelve (nombre, [(kernel, nº, etapas)])."""
    r = Lector(o)
    nombre = r.cadena()

    def recursos():
        for _ in range(r.i32()):
            r.cadena()
            r.cadena()
            r.crudo(12)  # bind point, sampler, dimensión

    kernels = []
    for _ in range(r.i32()):  # plataformas
        r.crudo(8)
        for numero in range(r.i32()):
            kernel = r.cadena()
            for _ in range(r.i32()):  # variantes del kernel
                r.cadena()
                r.crudo(4 * r.i32())
                recursos()
                recursos()
                r.crudo(8 * r.i32())
                recursos()
                recursos()
                codigo = bytes(r.crudo(r.i32()))
                r.alinear(4)
                r.crudo(4 * r.i32())  # tamaño del grupo (3 enteros)
                kernels.append((kernel, numero, partir_contenedor(codigo)))
            for _ in range(2):
                for _ in range(r.i32()):
                    r.cadena()
        for _ in range(r.i32()):  # constant buffers
            r.cadena()
            r.crudo(4)
            for _ in range(r.i32()):
                r.cadena()
                r.crudo(20)
        r.crudo(4)
    if len(o) - r.p >= 4:
        raise ValueError('sobran %d bytes' % (len(o) - r.p))
    return nombre, kernels


def controles_sueltos(datos, base=0):
    """Secciones de control (con el código que las sigue) encontradas por su magia en datos sin estructura conocida:
    [(posición, control, código)]. El tamaño de la sección está en control+0x20 y el del código es el final de sus
    constantes (control+0x704)."""
    fuera = []
    for m in re.finditer(re.escape(MAGIA_CONTROL + b'\x01\0\0\0'), datos):
        p = m.start()
        if p + 0x760 > len(datos):
            continue
        tam = struct.unpack_from('<I', datos, p + 0x20)[0]
        inicio, fin = struct.unpack_from('<II', datos, p + 0x700)
        ncodigo = max(inicio, fin)
        if not 0x760 <= tam <= 0x4000 or not 0 < ncodigo <= 0x100000 or p + tam + ncodigo > len(datos):
            continue
        fuera.append((base + p, bytes(datos[p:p + tam]), bytes(datos[p + tam:p + tam + ncodigo])))
    return fuera


def segmentos_nso(b):
    """Segmentos de un NSO (texto, solo lectura, datos) descomprimidos: [(dirección, bytes)]."""
    if b[:4] != b'NSO0':
        raise ValueError('no es un NSO')
    flags = struct.unpack_from('<I', b, 0x0C)[0]
    fuera = []
    for k in range(3):
        off, mem, tam = struct.unpack_from('<III', b, 0x10 + 0x10 * k)
        ctam = struct.unpack_from('<I', b, 0x60 + 4 * k)[0]
        fuera.append((mem, lz4(b[off:off + ctam], tam) if flags >> k & 1 else bytes(b[off:off + tam])))
    return fuera


# --------------------------------------------------------------------------------------------------------------------
# Extracción


def _registro(origen, objeto, shader, pase, variante, keywords, etapa_nvn, control, codigo):
    inicio, fin = struct.unpack_from('<II', control, 0x700)
    etapa = etapa_de(codigo, control)
    return {
        'origen': origen, 'objeto': objeto, 'shader': shader, 'pase': pase, 'variante': variante, 'keywords': keywords,
        'etapa': etapa, 'huella': '%016x' % huella_de(codigo, control),
        'codigo': len(codigo), 'control': len(control), 'constantes': max(0, fin - inicio),
        # Lo que decide la traducción: el código entero (con sus constantes) y los campos de la sección de control que
        # lee program.cpp (0x700 inicio y 0x704 fin de constantes, 0x708 inicio del código, 0x714 etapa, 0x748 grupo,
        # 0x754 memoria compartida).
        'clave': hashlib.sha1(codigo + control[0x700:0x760]).hexdigest()[:16],
        'sha_control': hashlib.sha1(control).hexdigest()[:12],
        'coherente': etapa == ETAPAS[etapa_nvn] if etapa_nvn is not None else True,
        'nota': '',
    }


def _de_serializado(b, origen, arboles):
    """Programas de un fichero serializado. arboles: {hash de tipo: nodos} (el type tree de Shader sale de un bundle)."""
    sf = abrir_serializado(b)
    registros, blobs, avisos, reflexiones = [], {}, [], []
    cuenta = collections.Counter()
    rangos = []  # [inicio, fin) de lo ya atribuido a un Shader o un ComputeShader

    def anotar(ident, nombre, pase, indice, keywords, etapas, nota):
        for nvn, control, codigo, tabla0 in etapas:
            reg = _registro(origen, ident, nombre, pase, indice, keywords, nvn, control, codigo)
            reg['tabla0'], reg['nota'] = tabla0, nota
            registros.append(reg)
            blobs.setdefault(reg['clave'], (codigo, control))

    def un_shader(nodos, pos, tam, limite, ident, nota):
        r = Lector(b, pos)
        v = leer_arbol(nodos, r)
        if tam is not None and not 0 <= tam - (r.p - pos) < 4:
            raise ValueError('el type tree leyó %d bytes de %d' % (r.p - pos, tam))
        nombre = v['m_ParsedForm']['m_Name']
        if tam is None and (r.p > limite or not nombre or not v['platforms'] or len(v['platforms']) > 8):
            raise ValueError('no parece un Shader')
        variantes, mas = programas_de_shader(v)
        avisos.extend('%s (%s #%s): %s' % (nombre, origen, ident, a) for a in mas)
        cuenta['shaders_huerfanos' if nota else 'shaders'] += 1
        cuenta['variantes_huerfanas' if nota else 'variantes'] += len(variantes)
        for indice, usos, keywords, etapas, reflexion in variantes:
            pase = '; '.join(sorted({'SS%d/P%d%s%s' % (s, p, ' ' + n if n else '', ' [%s]' % lm if lm else '')
                                     for s, p, n, lm, _ in usos})) or 'sin pase'
            anotar(ident, nombre, pase, indice, ' '.join(keywords), etapas, nota)
            if not nota:
                reflexiones.append(dict(reflexion, origen=origen, objeto=str(ident), variante=indice))
        return r.p

    for ident, pos, tam, clase, huella_tipo in sf['objetos']:
        if clase not in (CLASE_SHADER, CLASE_COMPUTE):
            continue
        rangos.append((pos, pos + tam))
        try:
            if clase == CLASE_SHADER:
                if huella_tipo not in arboles:
                    raise ValueError('sin type tree para el tipo %s' % huella_tipo.hex())
                un_shader(arboles[huella_tipo], pos, tam, pos + tam, ident, '')
            else:
                o = b[pos:pos + tam]
                try:
                    nombre, kernels = programas_de_compute(o)
                except (ValueError, struct.error, IndexError) as e:
                    # Plan B: por la magia de la sección de control (sin nombres de kernel).
                    nombre = bytes(o[4:4 + struct.unpack_from('<I', o, 0)[0]]).decode('utf8', 'replace')
                    avisos.append('ComputeShader %s (%s #%d): disposición inesperada (%s), kernels por su magia' % (nombre, origen, ident, e))
                    kernels = [('@0x%x' % p, k, [(5, c, d, 0)]) for k, (p, c, d) in enumerate(controles_sueltos(o))]
                if sum(len(e) for _, _, e in kernels) != o.count(MAGIA_CONTROL + b'\x01\0\0\0'):
                    avisos.append('ComputeShader %s (%s #%d): no cuadran los kernels con las secciones de control' % (nombre, origen, ident))
                cuenta['compute_shaders'] += 1
                cuenta['variantes'] += len(kernels)
                for kernel, numero, etapas in kernels:
                    anotar(ident, nombre + ' (ComputeShader)', 'kernel %s #%d' % (kernel, numero), numero, '', etapas, '')
        except (ValueError, struct.error, IndexError, KeyError) as e:
            avisos.append('%s #%d (clase %d): NO SE PUDO LEER: %r' % (origen, ident, clase, e))
            cuenta['objetos_ilegibles'] += 1
    # Huérfanos: datos entre dos objetos que no son de ninguno. unity_builtin_extra trae así 533 KB con 11 objetos Shader
    # enteros (los "always included", que el build copia a globalgamemanagers.assets y borra de la tabla de objetos sin
    # quitar sus bytes): Unity no puede cargarlos (no tienen identificador), pero se leen igual, marcados, para que el
    # barrido de abajo no deje nada sin explicar.
    arbol = next((arboles[h] for c, h, _ in sf['tipos'] if c == CLASE_SHADER and h in arboles), None)
    objetos = sorted(sf['objetos'], key=lambda o: o[1])
    fin = objetos[0][1] if objetos else 0
    for _, pos, tam, _, _ in objetos:
        p = fin
        while arbol and pos - p >= 64:
            p = (p + 7) // 8 * 8
            try:  # lo que no se lee como un Shader que quepa en el hueco se deja (el barrido lo dirá si importa)
                siguiente = un_shader(arbol, p, None, pos, 'huérfano@0x%x' % p, 'huérfano')
            except (ValueError, struct.error, IndexError, KeyError, UnicodeDecodeError):
                break
            rangos.append((p, siguiente))
            p = siguiente
        fin = max(fin, pos + tam)
    # Barrido: secciones de control fuera de los objetos Shader/ComputeShader (no debería quedar ninguna).
    for m in re.finditer(re.escape(MAGIA_CONTROL + b'\x01\0\0\0'), b):
        if not any(a <= m.start() < z for a, z in rangos):
            cuenta['controles_sueltos'] += 1
            avisos.append('%s: sección de control suelta en 0x%x (fuera de objetos Shader/ComputeShader)' % (origen, m.start()))
    return registros, blobs, avisos, cuenta, reflexiones


def _arboles_de(ruta):
    """Type trees de Shader que trae un bundle: {hash: nodos}."""
    fuera = {}
    with open(ruta, 'rb') as f:
        datos = f.read()
    if datos[:8] != b'UnityFS\0':
        return fuera
    for _, serializado, nodo in abrir_bundle(datos):
        if serializado:
            for clase, huella_tipo, nodos in abrir_serializado(nodo)['tipos']:
                if clase == CLASE_SHADER and nodos:
                    fuera[huella_tipo] = nodos
    return fuera


# Las etiquetas que el propio motor pone a sus shaders internos, por identificador de build del NSO (bytes 0x40..0x50) y
# dirección del código. Disco Elysium 1.0.9: la función de main+0x9465e4..0x9468ec crea cada programa con
# bl main+0x98bde0 (x3 = la salida de GLSLC, cargada de la GOT main+0x4d52b18…b98; w4 = su tamaño; w5 = 1 vertex / 2
# pixel; x6 = la etiqueta, una cadena de .rodata) y el de compute con bl main+0x98baa8 (etiqueta en x5).
ETIQUETAS_EJECUTABLE = {
    'eaa1edbeaef508545ce51e3a39ad367d': {
        0x3f5e698: 'msaa_resolve_2d_vs', 0x3f5f258: 'msaa_resolve_2darray_vs', 0x3f5ff18: 'msaa_resolve_2d_fs[2x]',
        0x3f60bd8: 'msaa_resolve_2d_fs[4x]', 0x3f61998: 'msaa_resolve_2d_fs[8x]',
        0x3f62858: 'msaa_resolve_2darray_fs[2x]', 0x3f63518: 'msaa_resolve_2darray_fs[4x]',
        0x3f642d8: 'msaa_resolve_2darray_fs[8x]', 0x3f65198: 'default_uv_vs', 0x3f65d58: 'copy_2d_fs',
        0x3f66918: 'gen_mip_3d',
    },
}


def _extraer_fichero(args):
    """Un fichero del romfs o del exefs (en un proceso del pool)."""
    ruta, origen, arboles, barrer = args
    registros, blobs, avisos, reflexiones = [], {}, [], []
    cuenta = collections.Counter()
    try:
        tam = os.path.getsize(ruta)
        with open(ruta, 'rb') as f:
            cabeza = f.read(64)
            if cabeza[:8] == b'UnityFS\0':
                cuenta['bundles'] += 1
                f.seek(0)
                for nombre, serializado, nodo in abrir_bundle(f.read()):
                    if serializado:
                        r, b, a, c, x = _de_serializado(nodo, origen + ':' + nombre, arboles)
                        registros += r
                        blobs.update(b)
                        avisos += a
                        cuenta.update(c)
                        reflexiones += x
                    elif barrer and nodo.find(MAGIA_CONTROL + b'\x01\0\0\0') >= 0:
                        cuenta['controles_sueltos'] += 1
                        avisos.append('%s:%s: sección de control suelta' % (origen, nombre))
            elif es_serializado(cabeza):
                cuenta['serializados'] += 1
                f.seek(0)
                registros, blobs, avisos, c, reflexiones = _de_serializado(f.read(), origen, arboles)
                cuenta.update(c)
            elif cabeza[:4] == b'NSO0':
                # El ejecutable: shaders internos del motor, salidas de GLSLC enteras en .rodata.
                cuenta['ejecutables'] += 1
                f.seek(0)
                nso = f.read()
                etiquetas = ETIQUETAS_EJECUTABLE.get(nso[0x40:0x50].hex(), {})
                for mem, seg in segmentos_nso(nso):
                    for pos, control, codigo in controles_sueltos(seg, mem):
                        glslc = seg[pos - mem - 0x240:pos - mem - 0x23C] == MAGIA_GLSLC
                        nombre = '%s+0x%x' % (os.path.basename(ruta), pos + len(control))
                        if pos + len(control) in etiquetas:
                            nombre += ' ' + etiquetas[pos + len(control)]
                        reg = _registro(origen, 'control en +0x%x' % pos, '<ejecutable> ' + nombre,
                                        'GLSLC' if glslc else 'suelto', 0, '', None, control, codigo)
                        registros.append(reg)
                        blobs.setdefault(reg['clave'], (codigo, control))
                        cuenta['variantes'] += 1
                cuenta['shaders_ejecutable'] += len(registros)
            elif barrer and tam:
                cuenta['otros'] += 1
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                    for pos, control, codigo in controles_sueltos(m):
                        cuenta['controles_sueltos'] += 1
                        avisos.append('%s: sección de control suelta en 0x%x (fichero sin formato de Unity)' % (origen, pos))
                        reg = _registro(origen, pos, '<suelto> %s+0x%x' % (os.path.basename(ruta), pos), 'suelto', 0, '',
                                        None, control, codigo)
                        registros.append(reg)
                        blobs.setdefault(reg['clave'], (codigo, control))
            else:
                cuenta['otros'] += 1
        cuenta['bytes'] += tam
    except (ValueError, struct.error, IndexError, OSError, lzma.LZMAError) as e:
        avisos.append('%s: NO SE PUDO LEER: %r' % (origen, e))
        cuenta['ficheros_ilegibles'] += 1
    return registros, blobs, avisos, cuenta, reflexiones


CAMPOS = ['huella', 'etapa', 'shader', 'pase', 'keywords', 'variante', 'origen', 'objeto', 'codigo', 'constantes',
          'control', 'clave', 'sha_control', 'nota']


def extraer(op):
    t0 = time.time()
    ficheros = []
    for carpeta, prefijo in ((op.romfs, 'romfs'), (op.exefs, 'exefs')):
        for d, _, nombres in os.walk(carpeta):
            for n in sorted(nombres):
                ruta = os.path.join(d, n)
                if os.path.isfile(ruta) and not os.path.islink(ruta):
                    ficheros.append((ruta, prefijo + '/' + os.path.relpath(ruta, carpeta)))
    if op.solo:
        ficheros = [f for f in ficheros if op.solo in f[1]]
    # El type tree de Shader: los ficheros del player no lo traen (enableTypeTree = 0), los bundles sí, y es el mismo
    # tipo (mismo hash). Se toma de los primeros bundles que lo tengan.
    arboles = {}
    for ruta, origen in sorted(ficheros, key=lambda f: ('shared/' not in f[1] and 'defaultlocalgroup' not in f[1], f[1])):
        with open(ruta, 'rb') as f:
            if f.read(8) != b'UnityFS\0':
                continue
        try:
            arboles.update(_arboles_de(ruta))
        except (ValueError, struct.error, IndexError):
            continue
        if arboles:
            break
    print('%d ficheros; type tree de Shader: %s' % (len(ficheros), ', '.join(h.hex() for h in arboles) or 'NINGUNO'))
    registros, blobs, avisos, reflexiones = [], {}, [], []
    cuenta = collections.Counter()
    with concurrent.futures.ProcessPoolExecutor(op.hilos) as pool:
        trabajos = [(ruta, origen, arboles, not op.sin_barrido) for ruta, origen in ficheros]
        for r, b, a, c, x in pool.map(_extraer_fichero, trabajos, chunksize=16):
            registros += r
            for k, v in b.items():
                blobs.setdefault(k, v)
            avisos += a
            cuenta.update(c)
            reflexiones += x
    os.makedirs(os.path.join(op.salida, 'shaders'), exist_ok=True)
    # Lo que Unity declara de cada variante (texturas con su dimensión, constant buffers con sus miembros): para
    # contrastarlo con lo que saca el traductor del código y para poner nombre a los recursos.
    with open(os.path.join(op.salida, 'reflexion.jsonl'), 'w') as f:
        for x in reflexiones:
            f.write(json.dumps(x, ensure_ascii=False) + '\n')
    # Un fichero por clave de traducción (código + campos de control que la deciden), con la huella en el nombre.
    por_clave = {}
    for reg in registros:
        por_clave.setdefault(reg['clave'], reg)
    huellas = collections.defaultdict(set)
    for clave, reg in por_clave.items():
        huellas[reg['huella']].add(clave)
    nombres = {}
    for huella, claves in huellas.items():
        for k, clave in enumerate(sorted(claves)):
            nombres[clave] = huella if len(claves) == 1 and huella != '0' * 16 else '%s_%s' % (huella, clave[:8])
    for clave, (codigo, control) in blobs.items():
        base = os.path.join(op.salida, 'shaders', nombres[clave])
        for ruta, datos in ((base + '.code', codigo), (base + '_ctrl.code', control)):
            if not os.path.exists(ruta) or os.path.getsize(ruta) != len(datos):
                with open(ruta, 'wb') as f:
                    f.write(datos)
    for reg in registros:
        reg['fichero'] = nombres[reg['clave']]
    registros.sort(key=lambda r: (r['origen'], str(r['objeto']), r['variante'], r['etapa']))
    with open(os.path.join(op.salida, 'programas.tsv'), 'w') as f:
        f.write('\t'.join(CAMPOS + ['fichero']) + '\n')
        for reg in registros:
            f.write('\t'.join(str(reg[c]) for c in CAMPOS + ['fichero']) + '\n')
    cuenta['programas'] = len(registros)
    cuenta['claves'] = len(por_clave)
    cuenta['huellas'] = len(huellas)
    cuenta['ficheros'] = len(ficheros)
    cuenta['etapa_incoherente'] = sum(1 for r in registros if not r['coherente'])
    resumen = {'cuenta': dict(cuenta), 'avisos': avisos, 'romfs': op.romfs, 'exefs': op.exefs, 'solo': op.solo,
               'barrido': not op.sin_barrido, 'segundos': round(time.time() - t0, 1),
               'tabla0': dict(collections.Counter('%s:%d' % (r['etapa'], r.get('tabla0', 0)) for r in registros if 'tabla0' in r))}
    with open(os.path.join(op.salida, 'extraccion.json'), 'w') as f:
        json.dump(resumen, f, indent=1, ensure_ascii=False)
    print('extraídos %d programas (%d variantes de %d Shader + %d ComputeShader + %d del ejecutable), %d huellas distintas, '
          '%d avisos, %.1f s' % (len(registros), cuenta['variantes'], cuenta['shaders'], cuenta['compute_shaders'],
                                 cuenta['shaders_ejecutable'], len(huellas), len(avisos), time.time() - t0))
    for a in avisos[:20]:
        print('  aviso:', a)
    return 0


def leer_programas(salida):
    ruta = os.path.join(salida, 'programas.tsv')
    if not os.path.exists(ruta):
        sys.exit('falta %s: ejecuta antes "extraer"' % ruta)
    with open(ruta) as f:
        campos = f.readline().rstrip('\n').split('\t')
        return [dict(zip(campos, linea.rstrip('\n').split('\t'))) for linea in f]


# --------------------------------------------------------------------------------------------------------------------
# Código de Maxwell: histograma de instrucciones y cabecera (SPH)

_TABLA_MAXWELL = None


def tabla_maxwell():
    """Los 16 bits altos de una instrucción -> su nombre, con la tabla del propio traductor (maxwell.inc de Eden: el
    primer patrón que encaja, en su orden). None si no está third_party/eden."""
    global _TABLA_MAXWELL
    if _TABLA_MAXWELL is None:
        ruta = os.path.join(RAIZ, 'third_party', 'eden', 'src', 'shader_recompiler', 'frontend', 'maxwell', 'maxwell.inc')
        tabla = [None] * 65536
        try:
            with open(ruta) as f:
                patrones = re.findall(r'INST\((\w+),\s*"[^"]*",\s*"([01\- ]+)"\)', f.read())
        except OSError:
            patrones = []
        for nombre, patron in patrones:
            bits = patron.replace(' ', '')
            valor = int(bits.replace('-', '0'), 2)
            libres = int(''.join('1' if c == '-' else '0' for c in bits), 2)
            s = libres
            while True:  # todos los subconjuntos de los bits libres
                if tabla[valor | s] is None:
                    tabla[valor | s] = nombre
                if s == 0:
                    break
                s = (s - 1) & libres
        _TABLA_MAXWELL = (tabla, bool(patrones))
    return _TABLA_MAXWELL


def analizar_maxwell(codigo, control):
    """Instrucciones del código (barrido lineal desde su inicio hasta sus constantes; una de cada cuatro palabras, las
    de offset múltiplo de 32, es de planificación y no cuenta) y los datos de la cabecera SPH."""
    inicio_constantes = struct.unpack_from('<I', control, 0x700)[0]
    graficos = codigo[:4] == MAGIA_CODIGO
    inicio = 0x80 if graficos else struct.unpack_from('<I', control, 0x708)[0]
    fin = min(inicio_constantes, len(codigo)) if inicio_constantes else len(codigo)
    tabla, hay = tabla_maxwell()
    ops = collections.Counter()
    if hay:
        for o in range(inicio, fin - 7, 8):
            if o % 32 == 0:
                continue
            nombre = tabla[codigo[o + 7] << 8 | codigo[o + 6]]
            if nombre is None:
                nombre = 'relleno' if codigo[o:o + 8] == b'\0' * 8 else 'desconocida'
            ops[nombre.split('_')[0] if not nombre.startswith(('TEX', 'TLD', 'TXD', 'TXQ', 'TMML')) else nombre] += 1
    sph = {}
    if graficos and len(codigo) >= 0x80:
        c0, _, _, c3, c4 = struct.unpack_from('<5I', codigo, 0x30)
        tipo = c0 >> 10 & 0xF
        sph = {'tipo': tipo, 'mrt': c0 >> 14 & 1, 'kil': c0 >> 15 & 1, 'global_store': c0 >> 16 & 1,
               'load_store': c0 >> 26 & 1, 'fp64': c0 >> 27 & 1}
        if tipo == 5:  # pixel: imap de genéricos (un byte por genérico) y omap (targets, sample mask, profundidad)
            target, marcas = struct.unpack_from('<II', codigo, 0x30 + 0x48)
            sph['entradas'] = sum(1 << k for k in range(32) if codigo[0x30 + 0x18 + k])
            sph['targets'] = sum(1 << k for k in range(8) if target >> (4 * k) & 0xF)
            sph['sample_mask'], sph['profundidad'] = marcas & 1, marcas >> 1 & 1
        else:  # vertex, teselación, geometry: omap de genéricos (4 bits por genérico) y valores de sistema
            sph['salidas'] = sum(1 << k for k in range(32) if codigo[0x30 + 0x36 + k // 2] >> (k % 2 * 4) & 0xF)
            sph['entradas'] = sum(1 << k for k in range(32) if codigo[0x30 + 0x18 + k // 2] >> (k % 2 * 4) & 0xF)
            sistema = codigo[0x30 + 0x35]
            sph['capa'], sph['viewport'], sph['point_size'] = sistema >> 1 & 1, sistema >> 2 & 1, sistema >> 3 & 1
            sph['clip'] = struct.unpack_from('<H', codigo, 0x30 + 0x48)[0] & 0xFF
            if tipo == 4:
                sph['topologia_salida'], sph['max_vertices'] = c3 >> 24 & 0xF, c4 & 0xFFF
    return {'ops': dict(ops), 'n': sum(ops.values()), 'sph': sph}


# --------------------------------------------------------------------------------------------------------------------
# SPIR-V: lo que declara y usa un módulo

_OPS_SPV = {252: 'OpKill', 4416: 'OpTerminateInvocation', 5380: 'OpDemoteToHelperInvocation', 207: 'OpDPdx',
            208: 'OpDPdy', 209: 'OpFwidth', 210: 'OpDPdxFine', 211: 'OpDPdyFine', 212: 'OpFwidthFine',
            213: 'OpDPdxCoarse', 214: 'OpDPdyCoarse', 215: 'OpFwidthCoarse', 218: 'OpEmitVertex', 219: 'OpEndPrimitive',
            220: 'OpEmitStreamVertex', 221: 'OpEndStreamPrimitive', 224: 'OpControlBarrier', 225: 'OpMemoryBarrier',
            251: 'OpSwitch', 255: 'OpUnreachable', 87: 'OpImageSampleImplicitLod', 88: 'OpImageSampleExplicitLod',
            89: 'OpImageSampleDrefImplicitLod', 90: 'OpImageSampleDrefExplicitLod', 91: 'OpImageSampleProjImplicitLod',
            92: 'OpImageSampleProjExplicitLod', 93: 'OpImageSampleProjDrefImplicitLod',
            94: 'OpImageSampleProjDrefExplicitLod', 95: 'OpImageFetch', 96: 'OpImageGather', 97: 'OpImageDrefGather',
            98: 'OpImageRead', 99: 'OpImageWrite', 103: 'OpImageQuerySizeLod', 104: 'OpImageQuerySize',
            105: 'OpImageQueryLod', 106: 'OpImageQueryLevels', 107: 'OpImageQuerySamples', 60: 'OpImageTexelPointer',
            5381: 'OpIsHelperInvocation'}
_CAPACIDADES = {0: 'Matrix', 1: 'Shader', 2: 'Geometry', 3: 'Tessellation', 9: 'Float16', 10: 'Float64', 11: 'Int64',
                12: 'Int64Atomics', 21: 'AtomicStorage', 22: 'Int16', 23: 'TessellationPointSize',
                24: 'GeometryPointSize', 25: 'ImageGatherExtended', 27: 'StorageImageMultisample',
                28: 'UniformBufferArrayDynamicIndexing', 29: 'SampledImageArrayDynamicIndexing',
                30: 'StorageBufferArrayDynamicIndexing', 31: 'StorageImageArrayDynamicIndexing', 32: 'ClipDistance',
                33: 'CullDistance', 34: 'ImageCubeArray', 35: 'SampleRateShading', 36: 'ImageRect', 37: 'SampledRect',
                39: 'Int8', 40: 'InputAttachment', 41: 'SparseResidency', 42: 'MinLod', 43: 'Sampled1D', 44: 'Image1D',
                45: 'SampledCubeArray', 46: 'SampledBuffer', 47: 'ImageBuffer', 48: 'ImageMSArray',
                49: 'StorageImageExtendedFormats', 50: 'ImageQuery', 51: 'DerivativeControl',
                52: 'InterpolationFunction', 53: 'TransformFeedback', 54: 'GeometryStreams',
                55: 'StorageImageReadWithoutFormat', 56: 'StorageImageWriteWithoutFormat', 57: 'MultiViewport',
                61: 'GroupNonUniform', 62: 'GroupNonUniformVote', 63: 'GroupNonUniformArithmetic',
                64: 'GroupNonUniformBallot', 65: 'GroupNonUniformShuffle', 66: 'GroupNonUniformShuffleRelative',
                67: 'GroupNonUniformClustered', 68: 'GroupNonUniformQuad', 69: 'ShaderLayer', 70: 'ShaderViewportIndex',
                4423: 'SubgroupBallotKHR', 4427: 'DrawParameters', 4431: 'SubgroupVoteKHR',
                4433: 'StorageBuffer16BitAccess', 4439: 'MultiView', 4441: 'VariablePointersStorageBuffer',
                4442: 'VariablePointers', 4445: 'AtomicStorageOps', 4447: 'SampleMaskPostDepthCoverage',
                4448: 'StorageBuffer8BitAccess', 4464: 'DenormPreserve', 4465: 'DenormFlushToZero',
                4466: 'SignedZeroInfNanPreserve', 4467: 'RoundingModeRTE', 4468: 'RoundingModeRTZ',
                5013: 'StencilExportEXT', 5254: 'ShaderViewportIndexLayerEXT', 5301: 'ShaderNonUniform',
                5302: 'RuntimeDescriptorArray', 5306: 'UniformBufferArrayNonUniformIndexing',
                5307: 'SampledImageArrayNonUniformIndexing', 5308: 'StorageBufferArrayNonUniformIndexing',
                5309: 'StorageImageArrayNonUniformIndexing', 5363: 'FragmentShaderSampleInterlockEXT',
                5378: 'FragmentShaderPixelInterlockEXT', 5379: 'DemoteToHelperInvocation',
                6033: 'AtomicFloat32AddEXT', 6034: 'AtomicFloat64AddEXT'}
_BUILTINS = {0: 'Position', 1: 'PointSize', 3: 'ClipDistance', 4: 'CullDistance', 5: 'VertexId', 6: 'InstanceId',
             7: 'PrimitiveId', 8: 'InvocationId', 9: 'Layer', 10: 'ViewportIndex', 11: 'TessLevelOuter',
             12: 'TessLevelInner', 13: 'TessCoord', 14: 'PatchVertices', 15: 'FragCoord', 16: 'PointCoord',
             17: 'FrontFacing', 18: 'SampleId', 19: 'SamplePosition', 20: 'SampleMask', 22: 'FragDepth',
             23: 'HelperInvocation', 24: 'NumWorkgroups', 25: 'WorkgroupSize', 26: 'WorkgroupId',
             27: 'LocalInvocationId', 28: 'GlobalInvocationId', 29: 'LocalInvocationIndex', 36: 'SubgroupSize',
             37: 'SubgroupMaxSize', 38: 'NumSubgroups', 40: 'SubgroupId', 41: 'SubgroupLocalInvocationId',
             42: 'VertexIndex', 43: 'InstanceIndex', 4424: 'BaseVertex', 4425: 'BaseInstance', 4426: 'DrawIndex',
             5014: 'FragStencilRefEXT'}
_MODOS = {0: 'Invocations', 7: 'OriginUpperLeft', 8: 'OriginLowerLeft', 9: 'EarlyFragmentTests', 11: 'Xfb',
          12: 'DepthReplacing', 14: 'DepthGreater', 15: 'DepthLess', 16: 'DepthUnchanged', 17: 'LocalSize',
          19: 'InputPoints', 20: 'InputLines', 21: 'InputLinesAdjacency', 22: 'Triangles', 23: 'InputTrianglesAdjacency',
          24: 'Quads', 25: 'Isolines', 26: 'OutputVertices', 27: 'OutputPoints', 28: 'OutputLineStrip',
          29: 'OutputTriangleStrip'}
_DIMENSIONES = {0: '1D', 1: '2D', 2: '3D', 3: 'Cube', 4: 'Rect', 5: 'Buffer', 6: 'SubpassData'}


def analizar_spirv(ruta):
    """Capacidades, extensiones, modos, interfaz (locations y builtins), tipos de imagen de las variables y las
    instrucciones que importan de un módulo SPIR-V. None si no lo es."""
    with open(ruta, 'rb') as f:
        d = f.read()
    n = len(d) // 4
    if n < 5:
        return None
    w = struct.unpack('<%dI' % n, d[:n * 4])
    if w[0] != 0x07230203:
        return None
    caps, exts, modos, ops = [], [], [], collections.Counter()
    deco = collections.defaultdict(dict)   # id -> {decoración: operando}
    miembros = collections.defaultdict(set)  # struct -> builtins de sus miembros
    tipos, constantes, variables = {}, {}, []
    anchos = set()
    i = 5
    while i < n:
        cuenta, op = w[i] >> 16, w[i] & 0xFFFF
        if cuenta == 0:
            break
        a = w[i + 1:i + cuenta]
        if op == 17:
            caps.append(a[0])
        elif op == 10:
            exts.append(struct.pack('<%dI' % len(a), *a).split(b'\0')[0].decode())
        elif op == 16:
            modos.append(list(a[1:]))
        elif op == 71:
            deco[a[0]][a[1]] = a[2] if len(a) > 2 else 1
        elif op == 72 and a[2] == 11:
            miembros[a[0]].add(a[3])
        elif op in (21, 22):
            tipos[a[0]] = (op, a[1:])
            anchos.add(('int' if op == 21 else 'float') + str(a[1]))
        elif op in (23, 24, 25, 26, 27, 28, 29, 30, 32):
            tipos[a[0]] = (op, a[1:])
        elif op == 43:
            constantes[a[1]] = a[2]
        elif op == 59:
            variables.append((a[1], a[0], a[2]))
        elif op in _OPS_SPV:
            ops[_OPS_SPV[op]] += 1
        elif 333 <= op <= 366:
            ops['OpGroupNonUniform'] += 1
        elif 227 <= op <= 242:
            ops['OpAtomic'] += 1
        i += cuenta

    def componentes(t):
        op, a = tipos.get(t, (0, ()))
        if op == 23:
            return a[1]
        if op == 24:
            return a[1] * componentes(a[0])
        if op in (28, 29):
            return componentes(a[0])
        return 1 if op in (21, 22) else 0

    info = {'version': '%d.%d' % (w[1] >> 16 & 0xFF, w[1] >> 8 & 0xFF), 'caps': caps, 'exts': exts, 'modos': modos,
            'ops': dict(ops), 'anchos': sorted(anchos), 'palabras': n, 'loc_in': [], 'loc_out': [], 'comp_in': 0,
            'comp_out': 0, 'builtins_in': [], 'builtins_out': [], 'imagenes': [], 'ubos': 0, 'ssbos': 0}
    for ident, tipo, clase in variables:
        apuntado = tipos.get(tipo, (0, (0, 0)))[1][1]
        if clase in (1, 3):  # Input / Output
            lado = 'in' if clase == 1 else 'out'
            if 11 in deco[ident]:
                info['builtins_' + lado].append(deco[ident][11])
            elif 30 in deco[ident]:
                info['loc_' + lado].append(deco[ident][30])
                op, a = tipos.get(apuntado, (0, ()))
                # Las entradas por vértice de geometry y teselación son arrays: cuenta un elemento.
                info['comp_' + lado] += componentes(apuntado)
            else:  # bloque gl_PerVertex
                base = apuntado
                while tipos.get(base, (0, ()))[0] in (28, 29):
                    base = tipos[base][1][0]
                info['builtins_' + lado] += sorted(miembros.get(base, ()))
        elif clase == 0:  # UniformConstant: texturas e imágenes
            cuantas, base = 1, apuntado
            while tipos.get(base, (0, ()))[0] in (28, 29):
                cuantas = constantes.get(tipos[base][1][1], 0) if tipos[base][0] == 28 else 0
                base = tipos[base][1][0]
            if tipos.get(base, (0, ()))[0] == 27:
                base = tipos[base][1][0]
            op, a = tipos.get(base, (0, ()))
            if op == 25:  # tipo muestreado, dimensión, profundidad, array, multisample, muestreada, formato
                info['imagenes'].append([a[1], a[2], a[3], a[4], a[5], a[6], cuantas,
                                         tipos.get(a[0], (0, ()))[0] == 21])
        elif clase == 2:
            base = apuntado
            while tipos.get(base, (0, ()))[0] in (28, 29):
                base = tipos[base][1][0]
            info['ssbos' if 3 in deco[base] else 'ubos'] += 1
        elif clase == 12:
            info['ssbos'] += 1
    for k in ('loc_in', 'loc_out', 'builtins_in', 'builtins_out'):
        info[k] = sorted(set(info[k]))
    return info


def tipo_de_imagen(img):
    """Nombre legible de una entrada de 'imagenes' de analizar_spirv."""
    dim, sombra, array, ms, muestreada, _, cuantas, entera = img
    nombre = _DIMENSIONES.get(dim, 'dim%d' % dim) + ('Array' if array else '') + ('MS' if ms else '')
    if muestreada == 2:
        nombre = 'imagen ' + nombre
    if sombra == 1:
        nombre += ' sombra'
    if entera:
        nombre += ' entera'
    if cuantas != 1:
        nombre += ' [array de descriptores]'
    return nombre


# --------------------------------------------------------------------------------------------------------------------
# Traducción (shadertool) y validación (spirv-val)

# Las opciones con las que traduce la Flip (program.cpp, translate_stage): arreglos del driver de Qualcomm, compute por
# spirv-opt, subgrupos del Adreno 650 (log: "subgrupos: tamaño 64, etapas 0x20, operaciones 0x3f"), c1 de la sección de
# control (CTRL). El DepthMode del juego es 1 (log: "DepthMode 1"): sin conversión de profundidad, como shadertool.
ENTORNO_FLIP = {'QUALCOMM': '1', 'SPIRV_OPT': '1', 'SUBGRUPOS': '64:0x20:0x3f', 'AUDITORIA': '1', 'IR': '1'}
_RE_RESUMEN = re.compile(r': (vertex|tess-control|tess-eval|geometry|pixel|compute), (\d+) palabras de SPIR-V, '
                         r'entradas 0x([0-9a-f]+), colores 0x([0-9a-f]+)')
_RE_IR = re.compile(r'^\[[0-9a-f]{16}\]\s+(?:%\d+\s*=\s*)?([A-Za-z]\w*)', re.M)
_RE_RECURSO = re.compile(r'^  (set 1 )?binding (\d+): (ubo|ssbo|texbuf|imgbuf|textura|imagen)', re.M)


def _traducir(trabajo):
    """Una traducción, en un proceso del pool: shadertool, lectura de su salida, SPIR-V, spirv-val y Maxwell."""
    salida, shadertool, spirv_val, fichero, sufijo, extra, limite, guardar_ir = trabajo
    codigo = os.path.join(salida, 'shaders', fichero + '.code')
    control = os.path.join(salida, 'shaders', fichero + '_ctrl.code')
    spv = os.path.join(salida, 'spv', fichero + sufijo + '.spv')
    if os.path.exists(spv):
        os.remove(spv)
    entorno = dict(os.environ, CTRL=control, **ENTORNO_FLIP)
    entorno.update(extra)
    res = {'fichero': fichero, 'sufijo': sufijo, 'extra': extra}
    t0 = time.time()
    try:
        p = subprocess.run([shadertool, codigo, spv], env=entorno, capture_output=True, timeout=limite)
        rc, out, err = p.returncode, p.stdout.decode('utf8', 'replace'), p.stderr.decode('utf8', 'replace')
    except subprocess.TimeoutExpired as e:
        rc, out, err = None, '', (e.stderr or b'').decode('utf8', 'replace')
    res['ms'] = round((time.time() - t0) * 1000, 1)
    res['rc'] = rc
    # Los LOG_* del recompilador van a stderr (shim/common/logging.h): también los de las traducciones que salen bien.
    res['avisos'] = sorted(set(re.findall(r'^\[recompilador [^\]]+\] .*$', err, re.M)))[:20]
    resto = '\n'.join(l for l in err.splitlines() if not l.startswith('[recompilador ')).strip()
    if rc is None:
        res['estado'], res['error'] = 'cuelgue', 'sin terminar en %d s' % limite
    elif rc == 1:
        res['estado'], res['error'] = 'fallo', resto.replace(codigo + ': ', '')[:2000]
    elif rc != 0:
        res['estado'], res['error'] = 'caída', ('señal %d' % -rc if rc < 0 else 'código %d' % rc) + ': ' + resto[:1500]
    else:
        res['estado'] = 'ok'
    if rc == 0:
        corte = out.find('\nBlock $')
        cabeza, ir = (out[:corte], out[corte:]) if corte >= 0 else (out, '')
        m = _RE_RESUMEN.search(cabeza)
        if m:
            res['etapa'], res['palabras'] = m.group(1), int(m.group(2))
            res['entradas'], res['colores'] = int(m.group(3), 16), int(m.group(4), 16)
        for linea in cabeza.splitlines():
            if linea.startswith('auditoria: '):
                aud = dict(par.split('=', 1) for par in linea[11:].split())
                res['aud'] = {k: (int(v, 0) if k != 'etapa' else v) for k, v in aud.items()}
            elif linea.startswith('leido:'):
                res['leido'] = {par.split('=')[0][1:]: int(par.split('=')[1]) for par in linea[6:].split()}
            elif linea.startswith('spirv-opt'):
                res['opt'] = linea
            elif linea.startswith('memoria compartida'):
                res['compartida'] = linea
        recursos = [dict(par.split('=', 1) for par in l[9:].split()) for l in cabeza.splitlines() if l.startswith('recurso: ')]
        if recursos:
            res['recursos'] = [[r['clase'], int(r['set']), int(r['binding']), int(r['banco']), int(r['offset'], 16),
                                int(r['tipo']), int(r['cuenta']), int(r['sombra']), int(r['entera']), int(r['escrita']),
                                int(r.get('banco2', -1)), int(r.get('offset2', '0'), 16)]
                               for r in recursos]
        else:  # shadertool sin AUDITORIA: clase, set y binding del listado de siempre
            res['recursos'] = [[clase, 1 if s else 0, int(b)] for s, b, clase in _RE_RECURSO.findall(cabeza)]
        ops = collections.Counter(_RE_IR.findall(ir))
        ops.pop('descriptor', None)
        res['ir'] = dict(ops)
        if guardar_ir and ir:
            with open(os.path.join(salida, 'ir', fichero + sufijo + '.txt'), 'w') as f:
                f.write(ir)
        try:
            res['spv'] = analizar_spirv(spv)
        except (OSError, struct.error, IndexError, KeyError) as e:
            res['spv'] = None
            res['error'] = 'SPIR-V ilegible: %r' % e
        if spirv_val:
            v = subprocess.run([spirv_val, '--target-env', 'vulkan1.1', spv], capture_output=True)
            res['val'] = 'ok' if v.returncode == 0 else 'fallo'
            if v.returncode:
                res['val_error'] = (v.stderr.decode('utf8', 'replace') + v.stdout.decode('utf8', 'replace')).strip()[:1500]
        else:
            res['val'] = 'sin validar'
    if not sufijo:
        with open(codigo, 'rb') as f:
            c = f.read()
        with open(control, 'rb') as f:
            k = f.read()
        res['maxwell'] = analizar_maxwell(c, k)
        res['grupo'] = list(struct.unpack_from('<3I', k, 0x748)) + [struct.unpack_from('<I', k, 0x754)[0]]
    return res


def _sha1_fichero(ruta):
    h = hashlib.sha1()
    with open(ruta, 'rb') as f:
        for trozo in iter(lambda: f.read(1 << 20), b''):
            h.update(trozo)
    return h.hexdigest()


def leer_jsonl(ruta):
    if not os.path.exists(ruta):
        return []
    with open(ruta) as f:
        return [json.loads(l) for l in f if l.strip()]


def huella_traductor(carpeta):
    """NVN_TRADUCTOR_HUELLA de un build (la genera runtime/recompiler/CMakeLists.txt con el contenido de todo lo que
    decide una traducción): dos builds con la misma traducen igual. '' si no está."""
    for ruta in (os.path.join(carpeta, 'generado', 'nvn_traductor_huella.h'), os.path.join(carpeta, 'nvn_traductor_huella.h')):
        try:
            with open(ruta) as f:
                m = re.search(r'NVN_TRADUCTOR_HUELLA 0x([0-9a-f]+)', f.read())
                if m:
                    return m.group(1)
        except OSError:
            pass
    return ''


def parejas(programas):
    """Las variantes de Unity con sus etapas: {(origen, objeto, variante): {etapa: fichero}} (un blob = un programa
    completo, el mismo par vertex/pixel que el juego enlaza)."""
    grupos = collections.defaultdict(dict)
    for p in programas:
        if p['shader'].startswith('<'):  # los del ejecutable van sueltos: no se sabe con cuál se enlaza cada uno
            continue
        grupos[(p['origen'], p['objeto'], p['variante'])][p['etapa']] = p['fichero']
    return grupos


def traducir(op):
    t0 = time.time()
    programas = leer_programas(op.salida)
    if not os.access(op.shadertool, os.X_OK):
        sys.exit('no está shadertool en %s (--shadertool, o cmake --build build/shadertool)' % op.shadertool)
    val = op.spirv_val if os.access(op.spirv_val, os.X_OK) else None
    if not val:
        print('AVISO: sin spirv-val en %s: no se valida el SPIR-V' % op.spirv_val)
    for d in ('spv', 'ir'):
        os.makedirs(os.path.join(op.salida, d), exist_ok=True)
    ficheros = sorted({p['fichero'] for p in programas})
    if not tabla_maxwell()[1]:
        print('AVISO: sin third_party/eden (maxwell.inc): no hay histograma de instrucciones de Maxwell')

    def lote(trabajos, nombre):
        resultados = []
        with concurrent.futures.ProcessPoolExecutor(op.hilos) as pool:
            for k, r in enumerate(pool.map(_traducir, trabajos, chunksize=4)):
                resultados.append(r)
                if (k + 1) % 500 == 0:
                    print('  %s: %d de %d' % (nombre, k + 1, len(trabajos)))
        return resultados

    base = lote([(op.salida, op.shadertool, val, f, '', {}, op.limite, op.guardar_ir) for f in ficheros], 'etapas')
    with open(os.path.join(op.salida, 'resultados.jsonl'), 'w') as f:
        for r in base:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    por_fichero = {r['fichero']: r for r in base}
    con_auditoria = any('aud' in r for r in base)
    # Variantes del runtime, las que hace program.cpp con lo que hay enlazado en el draw:
    # - generics_variant: un pixel shader que lee genéricos que su vertex (o su geometry) no escribe se traduce otra
    #   vez declarando solo las entradas que le llegan (GENERICOS).
    # - geometry_variant: el geometry, con las salidas de su vertex y la primitiva del draw (TOPOLOGIA).
    trabajos = {}
    if con_auditoria:
        for etapas in parejas(programas).values():
            vs, gs, ps = (por_fichero.get(etapas.get(e)) for e in ('vertex', 'geometry', 'pixel'))
            if vs and gs and vs['estado'] == 'ok':
                for topologia in (0, 1, 3):
                    extra = {'GENERICOS': hex(vs['aud']['salidas']), 'TOPOLOGIA': str(topologia)}
                    trabajos[(gs['fichero'], '_g%x_t%d' % (vs['aud']['salidas'], topologia))] = extra
            previa = gs if gs else vs
            if ps and previa and ps['estado'] == 'ok' and previa['estado'] == 'ok':
                salidas = previa['aud']['salidas']
                if ps['aud']['entradas'] & ~salidas:
                    trabajos[(ps['fichero'], '_g%x' % salidas)] = {'GENERICOS': hex(salidas)}
    variantes = lote([(op.salida, op.shadertool, val, f, s, e, op.limite, op.guardar_ir)
                      for (f, s), e in sorted(trabajos.items())], 'variantes')
    with open(os.path.join(op.salida, 'variantes.jsonl'), 'w') as f:
        for r in variantes:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    # El interruptor <datos>/spirv_opt_todas (program.cpp, spirv_opt_stages) pasa también las etapas gráficas por
    # spirv-opt: ¿aguanta con todas? Y de las que tienen un switch (BRX), cuyo flujo con banderas el driver de Qualcomm
    # ya compiló mal una vez (el skinning de MH Rise), queda el módulo optimizado listo para
    # <datos>/spirv_reemplazo/<huella>.spv por si alguna sale mal en la consola.
    optimizadas = []
    if not op.sin_opt_todas:
        graficas = [f for f in ficheros if por_fichero[f]['estado'] == 'ok' and por_fichero[f].get('etapa') != 'compute']
        optimizadas = lote([(op.salida, op.shadertool, val, f, '_opt', {'SPIRV_OPT': 'todas'}, op.limite, False)
                            for f in graficas], 'spirv-opt en gráficas')
        os.makedirs(os.path.join(op.salida, 'spirv_reemplazo'), exist_ok=True)
        for r in optimizadas:
            spv = os.path.join(op.salida, 'spv', r['fichero'] + '_opt.spv')
            base_r = por_fichero[r['fichero']]
            con_brx = base_r.get('aud', {}).get('brx') or 'BRX' in base_r.get('maxwell', {}).get('ops', {})
            if con_brx and r['estado'] == 'ok' and r.get('val') == 'ok' and r.get('opt', '').startswith('spirv-opt:'):
                os.replace(spv, os.path.join(op.salida, 'spirv_reemplazo', r['fichero'][:16] + '.spv'))
            elif os.path.exists(spv):
                os.remove(spv)
            for k in ('ir', 'spv', 'recursos', 'avisos', 'leido'):  # solo importa si pudo y si valida
                r.pop(k, None)
    with open(os.path.join(op.salida, 'optimizadas.jsonl'), 'w') as f:
        for r in optimizadas:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    estados = collections.Counter(r['estado'] for r in base)
    resumen = {'shadertool': op.shadertool, 'sha1': _sha1_fichero(op.shadertool),
               'fecha_shadertool': time.strftime('%Y-%m-%d %H:%M', time.localtime(os.path.getmtime(op.shadertool))),
               'traductor': huella_traductor(os.path.dirname(op.shadertool)),
               'traductor_android': huella_traductor(os.path.join(RAIZ, 'build', 'android')),
               'spirv_val': val, 'entorno': ENTORNO_FLIP, 'limite': op.limite, 'auditoria': con_auditoria,
               'maxwell': tabla_maxwell()[1], 'segundos': round(time.time() - t0, 1), 'estados': dict(estados)}
    with open(os.path.join(op.salida, 'traduccion.json'), 'w') as f:
        json.dump(resumen, f, indent=1, ensure_ascii=False)
    print('traducidas %d etapas (%s) y %d variantes del runtime (%s) en %.1f s; spirv-val: %s' % (
        len(base), ', '.join('%s %d' % e for e in sorted(estados.items())), len(variantes),
        ', '.join('%s %d' % e for e in sorted(collections.Counter(r['estado'] for r in variantes).items())) or '-',
        time.time() - t0,
        ', '.join('%s %d' % e for e in sorted(collections.Counter(r.get('val', '-') for r in base + variantes).items()))))
    if not con_auditoria:
        print('AVISO: este shadertool no entiende AUDITORIA/GENERICOS (es anterior a tools/shadertool/main.cpp de esta '
              'rama): sin variantes del runtime. Recompílalo: cmake --build build/shadertool')
    return 0


# --------------------------------------------------------------------------------------------------------------------
# Tabla de huellas, contraste con lo que declara Unity, volcados y logs


class Auditoria:
    """Todo lo que dejaron extraer y traducir en <salida>, cruzado."""

    def __init__(self, salida):
        self.salida = salida
        self.programas = leer_programas(salida)
        self.res = {r['fichero']: r for r in leer_jsonl(os.path.join(salida, 'resultados.jsonl'))}
        self.variantes = leer_jsonl(os.path.join(salida, 'variantes.jsonl'))
        self.optimizadas = leer_jsonl(os.path.join(salida, 'optimizadas.jsonl'))
        self.reflexion = {(x['origen'], x['objeto'], str(x['variante'])): x
                          for x in leer_jsonl(os.path.join(salida, 'reflexion.jsonl'))}
        self.usos = collections.defaultdict(list)  # fichero -> sus programas
        for p in self.programas:
            self.usos[p['fichero']].append(p)
        self.por_huella = collections.defaultdict(set)
        for p in self.programas:
            self.por_huella[p['huella']].add(p['fichero'])

    def principal(self, fichero):
        """El programa que da nombre a un código: el del Shader que más lo usa (los huérfanos y los del ejecutable, al
        final) y cuántos Shader distintos lo comparten."""
        ps = self.usos[fichero]
        cuenta = collections.Counter(p['shader'] for p in ps if not p['nota'])
        orden = sorted(ps, key=lambda p: (bool(p['nota']), p['shader'].startswith('<'), -cuenta[p['shader']], p['shader'],
                                          p['origen'], int(p['variante'])))
        return orden[0], sorted({p['shader'] for p in ps} - {orden[0]['shader']})

    def nombre(self, fichero):
        p, otros = self.principal(fichero)
        partes = [p['shader']]
        if p['pase'] not in ('sin pase', 'GLSLC'):
            partes.append(p['pase'])
        if p['keywords']:
            partes.append(p['keywords'])
        return ' | '.join(partes) + (' (+%d shaders)' % len(otros) if otros else '')

    def recursos_con_nombre(self, fichero):
        """Las texturas y los uniform blocks de un código con los nombres que les da Unity en la variante principal:
        ('t0=_MainTex:2D t1=…', 'c3=PGlobals:96 …')."""
        p, _ = self.principal(fichero)
        ref = self.reflexion.get((p['origen'], p['objeto'], p['variante']))
        r = self.res.get(fichero)
        if not ref or not r or r['estado'] != 'ok' or p['etapa'] not in ETAPAS:
            return '', ''
        bit = 1 << ETAPAS.index(p['etapa'])
        texturas = {t[2]: t for t in ref.get('texturas', []) if t[1] & bit}
        bloques = {b[2]: b for b in ref.get('bloques', []) if b[1] & bit}
        tex, blo = [], []
        for rec in r.get('recursos', []):
            if rec[0] == 'textura' and len(rec) > 4 and rec[3] == 2 and rec[4] >= 0x168:
                unidad = (rec[4] - 0x168) // 8
                t = texturas.get(unidad)
                tex.append('t%d=%s:%s' % (unidad, t[0] if t else '?', _DIM_UNITY.get(t[4], t[4]) if t else '?'))
        for banco in sorted(int(b) for b in r.get('leido', {})):
            if banco >= 3 and banco - 3 in bloques:
                nombre = bloques[banco - 3][0]
                blo.append('c%d=%s:%d' % (banco, nombre, ref['cbs'].get(nombre, [0])[0]))
        return ' '.join(tex), ' '.join(blo)


_DIM_UNITY = {2: '2D', 3: '3D', 4: 'Cube', 5: '2DArray', 6: 'CubeArray'}  # TextureDimension de Unity
_DIM_EDEN = {2: 2, 3: 5, 4: 3, 5: 4, 6: 6}  # Shader::TextureType -> TextureDimension de Unity


def contrastar(a):
    """Lo que el traductor saca del código de cada etapa frente a lo que Unity declara de su variante: cada textura que
    el código lee tiene que estar declarada en esa unidad y con esa dimensión, y cada banco de constantes, ser un
    uniform block de la variante del que no se lee más de lo que mide. Devuelve (comprobaciones, {tipo: [casos]})."""
    hechas = collections.Counter()
    raros = collections.defaultdict(list)
    vistos = set()
    for p in a.programas:
        ref = a.reflexion.get((p['origen'], p['objeto'], p['variante']))
        r = a.res.get(p['fichero'])
        if p['nota'] or not ref or 'error' in ref or not r or r['estado'] != 'ok' or p['etapa'] not in ETAPAS:
            continue
        bit = 1 << ETAPAS.index(p['etapa'])
        texturas = {t[2]: t for t in ref['texturas'] if t[1] & bit}
        bloques = {b[2]: b for b in ref['bloques'] if b[1] & bit}
        firma = (p['fichero'], json.dumps([sorted(texturas.items()), sorted(bloques.items()),
                                           sorted((k, v[0]) for k, v in ref['cbs'].items())]))
        if firma in vistos:
            continue
        vistos.add(firma)
        donde = '%s %s [%s]' % (p['huella'], p['etapa'], a.nombre(p['fichero']))
        usadas = set()
        for rec in r.get('recursos', []):
            if rec[0] not in ('textura', 'imagen', 'texbuf', 'imgbuf') or len(rec) < 12:
                continue
            hechas['texturas'] += 1
            clase, _, _, banco, offset, tipo, _, _, _, _, banco2, offset2 = rec
            if clase != 'textura' or banco != 2 or offset < 0x168 or offset >= 0x568 or (offset - 0x168) % 8:
                raros['handle fuera de la tabla de texturas separadas (c2[0x168 + 8·i])'].append(
                    '%s: %s en c%d[0x%x]' % (donde, clase, banco, offset))
                continue
            unidad = (offset - 0x168) // 8
            usadas.add(unidad)
            t = texturas.get(unidad)
            if not t:
                raros['el código lee una unidad de textura que Unity no declara en esa etapa'].append(
                    '%s: unidad %d' % (donde, unidad))
                continue
            if _DIM_EDEN.get(tipo) != t[4]:
                raros['dimensión distinta de la que declara Unity'].append(
                    '%s: %s (unidad %d) es %s y el traductor la declara de tipo %d' % (
                        donde, t[0], unidad, _DIM_UNITY.get(t[4], t[4]), tipo))
            if banco2 == 2 and (offset2 < 0x568 or (offset2 - 0x568) % 8):
                raros['sampler fuera de la tabla de samplers separados (c2[0x568 + 8·i])'].append(
                    '%s: %s con sampler en c2[0x%x]' % (donde, t[0], offset2))
        for unidad, t in texturas.items():
            if unidad not in usadas:
                raros['textura declarada por Unity que el código traducido no lee'].append(
                    '%s: %s (unidad %d)' % (donde, t[0], unidad))
        for banco, leido in sorted((int(k), v) for k, v in r.get('leido', {}).items()):
            if banco < 3:
                continue
            hechas['bloques'] += 1
            b = bloques.get(banco - 3)
            if not b:
                raros['el código lee un banco de constantes que Unity no declara en esa etapa'].append(
                    '%s: c%d (%d bytes)' % (donde, banco, leido))
            elif leido > ref['cbs'].get(b[0], [1 << 30])[0]:
                raros['el código lee más bytes de los que mide el uniform block'].append(
                    '%s: c%d = %s, lee %d de %d' % (donde, banco, b[0], leido, ref['cbs'][b[0]][0]))
        for binding, b in bloques.items():
            if str(binding + 3) not in r.get('leido', {}):
                raros['uniform block declarado por Unity que el código traducido no lee'].append(
                    '%s: %s (c%d)' % (donde, b[0], binding + 3))
    return hechas, raros


CONTROL_DEL_RUNTIME = 0x760  # kControlBytes de program.cpp: lo que snapshot_program guarda de la sección de control


def comparar_volcados(a, carpetas):
    """Volcados de la consola (<nombre>.code y <nombre>_ctrl.code: 64 KB desde el puntero del código y desde el de su
    control, lo que tiene el runtime) frente a lo extraído: [(volcado, huella del volcado, veredicto)]. Del control solo
    se comparan los 0x760 bytes que guarda el runtime (lo de detrás en el volcado ya es otra memoria)."""
    codigos = collections.defaultdict(list)  # primeros bytes del código -> ficheros, para reconocerlo sin su control
    cache = {}

    def leer(fichero):
        if fichero not in cache:
            with open(os.path.join(a.salida, 'shaders', fichero + '.code'), 'rb') as f:
                codigo = f.read()
            with open(os.path.join(a.salida, 'shaders', fichero + '_ctrl.code'), 'rb') as f:
                cache[fichero] = (codigo, f.read())
        return cache[fichero]

    for fichero in a.usos:
        codigos[leer(fichero)[0][:0x100]].append(fichero)
    filas = []
    for carpeta in carpetas:
        if not os.path.isdir(carpeta):
            continue
        for n in sorted(os.listdir(carpeta)):
            if not n.endswith('.code') or n.endswith('_ctrl.code'):
                continue
            ruta_control = os.path.join(carpeta, n[:-5] + '_ctrl.code')
            if not os.path.exists(ruta_control):
                continue
            with open(os.path.join(carpeta, n), 'rb') as f:
                codigo = f.read()
            with open(ruta_control, 'rb') as f:
                control = f.read()
            donde = os.path.join(os.path.basename(carpeta), n)
            huella = '%016x' % huella_de(codigo, control) if control[:4] == MAGIA_CONTROL else '-'
            # El código manda: ¿qué programa extraído es este? (todo su código, constantes incluidas)
            mio = next((f for f in codigos.get(codigo[:0x100], []) if codigo[:len(leer(f)[0])] == leer(f)[0]), None)
            if not mio:
                filas.append((donde, huella, 'su código NO está en lo extraído'))
                continue
            mi_codigo, mi_control = leer(mio)
            real = a.usos[mio][0]['huella']
            if control[:CONTROL_DEL_RUNTIME] == mi_control[:CONTROL_DEL_RUNTIME]:
                detalle = 'control idéntico (los 0x%x bytes que guarda el runtime)' % CONTROL_DEL_RUNTIME
            elif control[:4] != MAGIA_CONTROL or control[0x700:0x760] != mi_control[0x700:0x760]:
                detalle = ('el control del volcado NO es el suyo (memoria ya reutilizada por el juego: de ahí la huella %s '
                           'del volcado)' % huella)
            else:
                distintos = [k for k in range(CONTROL_DEL_RUNTIME) if control[k] != mi_control[k]]
                detalle = 'control con %d bytes distintos (0x%x..0x%x), iguales los que deciden la traducción' % (
                    len(distintos), distintos[0], distintos[-1])
            filas.append((donde, huella, 'código idéntico (0x%x bytes, constantes incluidas) a %s; %s -> %s' % (
                len(mi_codigo), real, detalle, a.nombre(mio))))
    return filas


_RE_HUELLA = re.compile(r'\b[0-9a-f]{16}\b')
_RE_HUELLA_SHADER = re.compile(r'\b(?:shader|pixel|vertex|geometry|compute|huella|variante de|fragment|vs|ps)[ _]([0-9a-f]{16})\b')


def huellas_de_log(a, ruta):
    """Huellas conocidas que aparecen en un log (con sus veces) y las que parecen de shader y no están en la tabla."""
    conocidas, desconocidas = collections.Counter(), collections.Counter()
    with open(ruta, errors='replace') as f:
        for linea in f:
            for h in _RE_HUELLA.findall(linea):
                if h in a.por_huella:
                    conocidas[h] += 1
            for h in _RE_HUELLA_SHADER.findall(linea):
                if h not in a.por_huella and h != '0' * 16:
                    desconocidas[h] += 1
    return conocidas, desconocidas


def _prefijos(trabajo):
    ruta, objetivos = trabajo
    with open(ruta, 'rb') as f:
        codigo = f.read()
    h, fuera = 0xcbf29ce484222325, []
    for k, x in enumerate(codigo):
        h = ((h ^ x) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
        if h in objetivos:
            fuera.append((h, k + 1))
    return os.path.basename(ruta)[:-5], fuera


def buscar_prefijos(a, huellas, hilos=None):
    """¿De qué son las huellas que no están en la tabla? El runtime hace el FNV del código hasta control+0x700: si leyó
    esa longitud de una sección de control que no era la del shader, la huella es la de un PREFIJO de su código (o del
    byte 0x78 solo, si leyó un 1). Prueba todas las longitudes de todos los códigos: {huella: [(fichero, bytes)]}."""
    objetivos = {int(h, 16) for h in huellas}
    hallado = collections.defaultdict(list)
    if not objetivos:
        return hallado
    trabajos = [(os.path.join(a.salida, 'shaders', f + '.code'), objetivos) for f in sorted(a.usos)]
    with concurrent.futures.ProcessPoolExecutor(hilos) as pool:
        for fichero, hs in pool.map(_prefijos, trabajos, chunksize=32):
            for h, n in hs:
                hallado['%016x' % h].append((fichero, n))
    return hallado


def explicar_prefijo(a, casos):
    """El veredicto de una huella sin nombre a partir de lo que dio buscar_prefijos."""
    if not casos:
        return 'no es prefijo de ningún código extraído (¿código también pisado, o longitud mayor que el código?)'
    fichero, n = casos[0]
    if len(casos) > 1:
        return ('FNV-1a de los primeros %d bytes de %d códigos (todos empiezan igual): el runtime leyó control+0x700 = %d '
                'de una sección de control que no era la del shader' % (n, len(casos), n))
    with open(os.path.join(a.salida, 'shaders', fichero + '_ctrl.code'), 'rb') as f:
        inicio = struct.unpack_from('<I', f.read(), 0x700)[0]
    return ('FNV-1a de los primeros 0x%x bytes de `%s` (%s), cuyas constantes empiezan en 0x%x: el runtime leyó su longitud '
            'de una sección de control que no era la suya' % (n, a.usos[fichero][0]['huella'], a.nombre(fichero), inicio))


def escribir_huellas(a):
    """huellas.tsv: una fila por código distinto, con su nombre de Unity, para poner nombre a las huellas de los logs."""
    filas = []
    for fichero in sorted(a.usos):
        p, otros = a.principal(fichero)
        r = a.res.get(fichero, {})
        tex, blo = a.recursos_con_nombre(fichero)
        ps = a.usos[fichero]
        filas.append([p['huella'], p['etapa'], r.get('estado', 'sin traducir'), r.get('val', '-'),
                      str(sum(1 for x in ps if not x['nota'])), str(len({x['shader'] for x in ps})), p['shader'], p['pase'],
                      p['keywords'], '; '.join(otros[:6]) + (' …(+%d)' % (len(otros) - 6) if len(otros) > 6 else ''),
                      tex, blo, p['origen']])
    with open(os.path.join(a.salida, 'huellas.tsv'), 'w') as f:
        f.write('huella\tetapa\ttraduccion\tspirv_val\tprogramas\tshaders\tshader\tpase\tkeywords\totros_shaders\ttexturas\t'
                'bloques\torigen\n')
        for fila in filas:
            f.write('\t'.join(fila) + '\n')
    return len(filas)


# --------------------------------------------------------------------------------------------------------------------
# Informe

# Lo que la Flip admite de cada capacidad de SPIR-V que declaran los shaders traducidos. Del vkjson del Adreno 650 (driver
# 512.746.0, Vulkan 1.1.128: xenoblade-recomp/work/analisis_lote5/auditoria_formatos_runtime/vkjson_flip2.json) y de
# vk.cpp, que crea el dispositivo con todas las features del núcleo que da el driver (menos robustBufferAccess) y, por
# extensión, solo shaderDrawParameters, shaderFloat16, el índice no uniforme de texturas y los bordes de color.
CAPACIDADES_FLIP = {
    'Matrix': (True, 'siempre en Vulkan'), 'Shader': (True, 'siempre en Vulkan'),
    'ImageQuery': (True, 'siempre en Vulkan'), 'SampledBuffer': (True, 'siempre en Vulkan'),
    'ImageBuffer': (True, 'siempre en Vulkan'), 'DerivativeControl': (True, 'siempre en Vulkan'),
    'Sampled1D': (True, 'siempre en Vulkan'), 'Image1D': (True, 'siempre en Vulkan'),
    'ImageGatherExtended': (True, 'shaderImageGatherExtended = 1'), 'Geometry': (True, 'geometryShader = 1'),
    'Tessellation': (True, 'tessellationShader = 1'), 'ClipDistance': (True, 'shaderClipDistance = 1'),
    'CullDistance': (True, 'shaderCullDistance = 1'), 'ImageCubeArray': (True, 'imageCubeArray = 1'),
    'SampledCubeArray': (True, 'imageCubeArray = 1'), 'SampleRateShading': (True, 'sampleRateShading = 1'),
    'InterpolationFunction': (True, 'sampleRateShading = 1'), 'MultiViewport': (True, 'multiViewport = 1'),
    'Int16': (True, 'shaderInt16 = 1'), 'Float16': (True, 'shaderFloat16 = 1, activada por vk.cpp'),
    'StorageImageExtendedFormats': (True, 'shaderStorageImageExtendedFormats = 1'),
    'StorageImageReadWithoutFormat': (True, 'shaderStorageImageReadWithoutFormat = 1'),
    'StorageImageWriteWithoutFormat': (True, 'shaderStorageImageWriteWithoutFormat = 1'),
    'GeometryPointSize': (True, 'shaderTessellationAndGeometryPointSize = 1'),
    'TessellationPointSize': (True, 'shaderTessellationAndGeometryPointSize = 1'),
    'DrawParameters': (True, 'shaderDrawParameters, activada por vk.cpp (log: "shaderDrawParameters: sí")'),
    'ShaderNonUniform': (True, 'VK_EXT_descriptor_indexing, activada por vk.cpp'),
    'SampledImageArrayNonUniformIndexing': (True, 'VK_EXT_descriptor_indexing, activada por vk.cpp'),
    'SampledImageArrayDynamicIndexing': (True, 'shaderSampledImageArrayDynamicIndexing = 1'),
    'UniformBufferArrayDynamicIndexing': (True, 'shaderUniformBufferArrayDynamicIndexing = 1'),
    'StorageBufferArrayDynamicIndexing': (True, 'shaderStorageBufferArrayDynamicIndexing = 1'),
    'StorageImageArrayDynamicIndexing': (True, 'shaderStorageImageArrayDynamicIndexing = 1'),
    'VariablePointersStorageBuffer': (None, 'el driver la tiene (variablePointersStorageBuffer = 1) pero vk.cpp NO la activa'),
    'VariablePointers': (None, 'el driver la tiene (variablePointers = 1) pero vk.cpp NO la activa'),
    'Int8': (None, 'el driver la tiene (shaderInt8 = 1) pero vk.cpp la deja apagada'),
    'DemoteToHelperInvocation': (None, 'el driver tiene VK_EXT_shader_demote_to_helper_invocation pero vk.cpp no la activa'),
    'Float64': (False, 'shaderFloat64 = 0'), 'Int64': (False, 'shaderInt64 = 0'), 'Int64Atomics': (False, 'shaderInt64 = 0'),
    'StorageImageMultisample': (False, 'shaderStorageImageMultisample = 0'),
    'ImageMSArray': (False, 'shaderStorageImageMultisample = 0'), 'MinLod': (False, 'shaderResourceMinLod = 0'),
    'SparseResidency': (False, 'shaderResourceResidency = 0'),
    'StencilExportEXT': (False, 'sin VK_EXT_shader_stencil_export'),
    'ShaderViewportIndexLayerEXT': (False, 'sin VK_EXT_shader_viewport_index_layer'),
    'ShaderLayer': (False, 'es de Vulkan 1.2'), 'ShaderViewportIndex': (False, 'es de Vulkan 1.2'),
    'TransformFeedback': (None, 'el driver lista VK_EXT_transform_feedback pero vk.cpp no la activa'),
    'GeometryStreams': (None, 'el driver lista VK_EXT_transform_feedback pero vk.cpp no la activa'),
}
for _c in ('GroupNonUniform', 'GroupNonUniformVote', 'GroupNonUniformArithmetic', 'GroupNonUniformBallot',
           'GroupNonUniformShuffle', 'GroupNonUniformShuffleRelative'):
    CAPACIDADES_FLIP[_c] = (None, 'subgrupos SOLO en compute (supportedStages = 0x20, operaciones 0x3f)')
for _c in ('GroupNonUniformClustered', 'GroupNonUniformQuad'):
    CAPACIDADES_FLIP[_c] = (False, 'operaciones de subgrupo 0x3f: sin clustered ni quad')
# Límites del Adreno 650 (el mismo vkjson) y del propio runtime.
LIMITES = {'entradas de pixel (componentes)': 112, 'salidas de vertex (componentes)': 128,
           'invocaciones por grupo de compute': 1024, 'memoria compartida de compute (bytes)': 32768,
           'bindings por etapa (kBindingsPerStage de nvn_shader.h)': 64,
           'unidades de textura (kMaxTextures del ejecutor)': 32, 'bancos de constantes (kMaxUniforms del ejecutor)': 18}


def _causa(texto):
    """Un mensaje de error sin lo que cambia de un shader a otro, para agrupar."""
    lineas = [l for l in (texto or '').strip().splitlines() if l.strip()]
    t = lineas[0] if lineas else '(sin mensaje)'
    t = re.sub(r'%\w+\[?\w*\]?', '%id', t)
    t = re.sub(r'0x[0-9a-fA-F]+', '0x…', t)
    t = re.sub(r'\b\d+\b', 'N', t)
    return t[:220]


def _tabla(cabeceras, filas):
    fuera = ['| ' + ' | '.join(cabeceras) + ' |', '|' + '|'.join('---' for _ in cabeceras) + '|']
    for fila in filas:
        fuera.append('| ' + ' | '.join(str(c).replace('|', '\\|') for c in fila) + ' |')
    return fuera


def rasgos_de(r):
    """Los rasgos de una etapa traducida que importan en Vulkan y en el Adreno."""
    mx = r.get('maxwell', {}).get('ops', {})
    sph = r.get('maxwell', {}).get('sph', {})
    ir, spv, rec = r.get('ir', {}), r.get('spv') or {}, r.get('recursos', [])
    return {
        'instrucciones': r.get('maxwell', {}).get('n', 0), 'palabras': r.get('palabras', 0),
        'brx': mx.get('BRX', 0) + mx.get('JMX', 0), 'shfl': mx.get('SHFL', 0), 'fswzadd': mx.get('FSWZADD', 0),
        'derivadas': sum(ir.get(k, 0) for k in ('DPdxFine', 'DPdyFine', 'DPdxCoarse', 'DPdyCoarse')),
        'sin_plegar': sum(ir.get(k, 0) for k in ('FSwizzleAdd', 'ShuffleIndex', 'ShuffleUp', 'ShuffleDown',
                                                 'ShuffleButterfly', 'QuadBroadcast')),
        'kil': mx.get('KIL', 0), 'descarte': ir.get('DemoteToHelperInvocation', 0),
        'profundidad': ir.get('SetFragDepth', 0), 'sph_kil': sph.get('kil', 0), 'sph_profundidad': sph.get('profundidad', 0),
        'colores': r.get('colores', 0), 'entradas': r.get('aud', {}).get('entradas', r.get('entradas', 0)),
        'salidas': r.get('aud', {}).get('salidas', 0),
        'ubos': sum(1 for x in rec if x[0] == 'ubo'), 'texturas': sum(1 for x in rec if x[0] == 'textura'),
        'ssbos': sum(1 for x in rec if x[0] == 'ssbo'), 'imagenes': sum(1 for x in rec if x[0] == 'imagen'),
        'tipos': sorted({tipo_de_imagen(i) for i in spv.get('imagenes', [])}),
    }


def informe(op):
    a = Auditoria(op.salida)
    with open(os.path.join(op.salida, 'extraccion.json')) as f:
        ext = json.load(f)
    with open(os.path.join(op.salida, 'traduccion.json')) as f:
        tra = json.load(f)
    cuenta = ext['cuenta']
    C = collections.Counter
    etapa_de_fichero = {f: ps[0]['etapa'] for f, ps in a.usos.items()}
    vivos = [p for p in a.programas if not p['nota']]
    huerfanos = [p for p in a.programas if p['nota']]
    solo_huerfanos = [f for f, ps in a.usos.items() if all(p['nota'] for p in ps)]
    n_huellas = escribir_huellas(a)
    ras = {f: rasgos_de(r) for f, r in a.res.items() if r['estado'] == 'ok'}
    with open(os.path.join(op.salida, 'rasgos.tsv'), 'w') as f:
        campos = ['instrucciones', 'palabras', 'brx', 'shfl', 'fswzadd', 'derivadas', 'sin_plegar', 'kil', 'profundidad',
                  'colores', 'entradas', 'salidas', 'ubos', 'texturas', 'ssbos', 'imagenes']
        f.write('huella\tetapa\t' + '\t'.join(campos) + '\ttipos_de_textura\tshader\n')
        for fichero in sorted(ras):
            x = ras[fichero]
            f.write('%s\t%s\t%s\t%s\t%s\n' % (a.usos[fichero][0]['huella'], etapa_de_fichero[fichero],
                                              '\t'.join('0x%x' % x[c] if c in ('colores', 'entradas', 'salidas') else str(x[c]) for c in campos),
                                              ', '.join(x['tipos']), a.nombre(fichero)))

    def ejemplos(ficheros, n=3):
        return '; '.join('`%s` %s' % (a.usos[f][0]['huella'], a.nombre(f)) for f in sorted(ficheros)[:n])

    def shaders_de(ficheros, n=6):
        nombres = C(p['shader'] for f in ficheros for p in a.usos[f] if not p['nota'])
        return ', '.join('%s (%d)' % (s, k) for s, k in nombres.most_common(n)) + (' …' if len(nombres) > n else '')

    L = ['# Auditoría de shaders: Disco Elysium (Switch) en la Flip 2', '']
    L.append('Generado por `tools/shader_audit.py` el %s. Todo offline: extracción de %s y %s, traducción con `%s` '
             '(sha1 %s, del %s) y validación con `%s`.' % (
                 time.strftime('%Y-%m-%d %H:%M'), ext['romfs'], ext['exefs'], tra['shadertool'], tra['sha1'][:12],
                 tra['fecha_shadertool'], tra['spirv_val'] or 'NADA (sin spirv-val)'))
    L.append('')

    # ------------------------------------------------------------------ 1. números
    estados = C(r['estado'] for r in a.res.values())
    vals = C(r.get('val', '-') for r in a.res.values() if r['estado'] == 'ok')
    por_etapa_p, por_etapa_u = C(p['etapa'] for p in vivos), C(etapa_de_fichero[f] for f in a.usos)
    L += ['## 1. Los números', '']
    L += _tabla(['', 'cuántos'], [
        ['Ficheros recorridos', '%d (%.2f GB): %d bundles UnityFS, %d ficheros serializados, %d ejecutables NSO, %d de otro tipo' % (
            cuenta['ficheros'], cuenta['bytes'] / 1e9, cuenta.get('bundles', 0), cuenta.get('serializados', 0),
            cuenta.get('ejecutables', 0), cuenta.get('otros', 0))],
        ['Objetos Shader de Unity', '%d (más %d huérfanos, ver 2)' % (cuenta.get('shaders', 0), cuenta.get('shaders_huerfanos', 0))],
        ['Objetos ComputeShader', '%d (%d kernels)' % (cuenta.get('compute_shaders', 0), sum(1 for p in vivos if '(ComputeShader)' in p['shader']))],
        ['Shaders internos del ejecutable', str(cuenta.get('shaders_ejecutable', 0))],
        ['Variantes (un blob = un programa completo: pase + keywords)', '%d (más %d en los huérfanos)' % (cuenta.get('variantes', 0), cuenta.get('variantes_huerfanas', 0))],
        ['Programas (etapas)', '%d: %s (más %d en los huérfanos)' % (len(vivos), ', '.join('%s %d' % e for e in por_etapa_p.most_common()), len(huerfanos))],
        ['**Código distinto (huellas del runtime)**', '**%d**: %s' % (len(a.usos), ', '.join('%s %d' % e for e in por_etapa_u.most_common()))],
        ['**Se traducen**', '**%d de %d** (%s)' % (estados['ok'], len(a.res), ', '.join('%s %d' % e for e in sorted(estados.items())))],
        ['**Validan (spirv-val, vulkan1.1)**', '**%d de %d** (%s)' % (vals['ok'], estados['ok'], ', '.join('%s %d' % e for e in sorted(vals.items())))],
    ])
    var_gen = [v for v in a.variantes if 'TOPOLOGIA' not in v['extra']]
    var_geo = [v for v in a.variantes if 'TOPOLOGIA' in v['extra']]
    grupos = parejas(a.programas)
    necesitan = 0
    for etapas in grupos.values():
        vs, gs, ps = (a.res.get(etapas.get(e)) for e in ('vertex', 'geometry', 'pixel'))
        previa = gs if gs else vs
        if ps and previa and 'aud' in ps and 'aud' in previa and ps['aud']['entradas'] & ~previa['aud']['salidas']:
            necesitan += 1
    L += _tabla(['variantes que hace el runtime al dibujar', 'cuántas'], [
        ['Pares vertex/pixel de Unity cuyo pixel lee genéricos que el vertex no escribe (generics_variant)',
         '%d pares de %d; %d traducciones distintas: %d se traducen, %d validan' % (
             necesitan, len(grupos), len(var_gen), sum(1 for v in var_gen if v['estado'] == 'ok'),
             sum(1 for v in var_gen if v.get('val') == 'ok'))],
        ['Geometry con las salidas de su vertex, para puntos, líneas y triángulos (geometry_variant)',
         '%d: %d se traducen, %d validan' % (len(var_geo), sum(1 for v in var_geo if v['estado'] == 'ok'),
                                             sum(1 for v in var_geo if v.get('val') == 'ok'))],
    ])
    L.append('')
    if tra.get('traductor') or tra.get('traductor_android'):
        igual = tra.get('traductor') and tra.get('traductor') == tra.get('traductor_android')
        L.append('Traductor: huella `%s` la del shadertool usado y `%s` la del último build de Android (`build/android`): %s.' % (
            tra.get('traductor') or '¿?', tra.get('traductor_android') or '¿?',
            'el mismo traductor que lleva el APK' if igual else '**NO coinciden**: recompila shadertool (`cmake --build build/shadertool`) y repite'))
        L.append('')
    if not tra.get('auditoria'):
        L += ['**AVISO:** el shadertool usado es anterior a esta rama (no entiende AUDITORIA/GENERICOS): faltan las variantes '
              'del runtime, el contraste con Unity y parte de los rasgos. Recompílalo y repite.', '']

    # ------------------------------------------------------------------ 2. cobertura
    L += ['## 2. Qué se ha cubierto y cómo', '']
    L.append('- **Todo el romfs y el exefs**%s, sin muestreo: %d ficheros. Cada fichero se reconoce por su cabecera (UnityFS, '
             'fichero serializado de Unity, NSO); los bundles se descomprimen enteros (LZ4/LZMA).' % (
                 ' (filtrado por "%s")' % ext['solo'] if ext.get('solo') else '', cuenta['ficheros']))
    L.append('- **Shader (clase 48)**: con su type tree (los ficheros del player no lo traen; se toma de un bundle, mismo hash '
             'de tipo). Cada subprograma del blob LZ4 lleva las etapas de la variante en un contenedor propio de Unity para '
             'Switch (4 tablas de 6 enteros + control 0x880 + código por etapa).')
    L.append('- **ComputeShader (clase 72)**: 4 objetos en `unity default resources`, sin type tree en ningún sitio; su '
             'disposición se ha leído de los bytes y cada objeto se comprueba (kernels = secciones de control, ni un byte de más).')
    L.append('- **Ejecutable**: `exefs/main` lleva en .rodata %d salidas de GLSLC (magia 0x19866891) con shaders internos '
             'del motor; el resto de NSO, ninguna.' % cuenta.get('shaders_ejecutable', 0))
    if ext.get('barrido'):
        L.append('- **Barrido de seguridad**: se busca la magia de la sección de control (0x98761234) en TODOS los bytes '
                 '(los bundles, ya descomprimidos). Fuera de los objetos Shader/ComputeShader y del ejecutable quedan '
                 '**%d** sin explicar%s.' % (cuenta.get('controles_sueltos', 0),
                                             '' if cuenta.get('controles_sueltos', 0) else ': no hay shaders de Switch en ningún otro sitio'))
    if cuenta.get('shaders_huerfanos'):
        L.append('- **Huérfanos**: `unity_builtin_extra` tiene %d objetos Shader enteros (%d variantes) que no están en su '
                 'tabla de objetos (el build los copió a `globalgamemanagers.assets` y dejó los bytes): Unity no puede '
                 'cargarlos. Se han leído igual: %s.' % (
                     cuenta['shaders_huerfanos'], cuenta.get('variantes_huerfanas', 0),
                     'no añaden ningún código nuevo (todas sus huellas están también en objetos vivos)' if not solo_huerfanos
                     else '**%d códigos solo existen ahí**' % len(solo_huerfanos)))
    L.append('- **Huella**: la de `program.cpp` (`code_print`): FNV-1a 64 del código hasta sus constantes (control+0x700). '
             'Los %d programas dan %d huellas; dos programas con la misma huella tienen el mismo código, las mismas constantes '
             'y los mismos campos de control que lee el traductor (%s).' % (
                 len(a.programas), len(a.por_huella),
                 'comprobado: ninguna huella con dos contenidos' if all(len(v) == 1 for v in a.por_huella.values())
                 else '**OJO: %d huellas con más de un contenido**' % sum(1 for v in a.por_huella.values() if len(v) > 1)))
    L.append('- **Traducción**: como la Flip (`translate_stage`): %s y `CTRL` (constantes c1, etapa, grupo de compute). '
             'DepthMode 1 del juego: sin conversión de profundidad.' % ', '.join('`%s=%s`' % e for e in sorted(tra['entorno'].items()) if e[0] not in ('IR', 'AUDITORIA')))
    if ext['avisos']:
        L += ['', '**Avisos de la extracción (%d):**' % len(ext['avisos']), ''] + ['- ' + x for x in ext['avisos'][:40]]
    L.append('')

    # ------------------------------------------------------------------ 3. fallos de traducción
    L += ['## 3. Fallos de traducción', '']
    malos = [f for f, r in a.res.items() if r['estado'] != 'ok']
    if not malos:
        L += ['**Ninguno.** Las %d etapas se traducen (ninguna excepción del recompilador, ningún cuelgue en %d s, ninguna '
              'caída). Tampoco hay instrucciones de Maxwell que el recompilador no conozca%s.' % (
                  len(a.res), tra['limite'],
                  '' if not any(r.get('maxwell', {}).get('ops', {}).get('desconocida') for r in a.res.values())
                  else ' salvo las "desconocida" de maxwell.tsv'), '']
    else:
        por_causa = collections.defaultdict(list)
        for f in malos:
            por_causa[(a.res[f]['estado'], _causa(a.res[f].get('error')))].append(f)
        L += _tabla(['estado', 'causa', 'huellas', 'programas', 'etapas', 'shaders de Unity', 'ejemplo'],
                    [[e, '`%s`' % c, len(fs), sum(len(a.usos[f]) for f in fs), ', '.join('%s %d' % x for x in C(etapa_de_fichero[f] for f in fs).items()),
                      shaders_de(fs), ejemplos(fs, 1)] for (e, c), fs in sorted(por_causa.items(), key=lambda x: -len(x[1]))])
        L.append('')
        with open(os.path.join(op.salida, 'fallos.tsv'), 'w') as f:
            f.write('huella\tetapa\testado\terror\tshader\n')
            for fichero in sorted(malos):
                f.write('%s\t%s\t%s\t%s\t%s\n' % (a.usos[fichero][0]['huella'], etapa_de_fichero[fichero], a.res[fichero]['estado'],
                                                  (a.res[fichero].get('error') or '').replace('\n', ' // ')[:600], a.nombre(fichero)))
        L += ['Lista completa en `fallos.tsv`.', '']
    avisos = collections.defaultdict(list)
    for f, r in a.res.items():
        for x in r.get('avisos', []):
            avisos[_causa(x)].append(f)
    L.append('Avisos del recompilador (sus `LOG_WARNING`/`LOG_ERROR`, que salen aunque la traducción acabe bien): %s' % (
        '**ninguno**.' if not avisos else ''))
    if avisos:
        L += [''] + _tabla(['aviso', 'huellas', 'shaders de Unity', 'ejemplo'],
                           [['`%s`' % c, len(fs), shaders_de(fs), ejemplos(fs, 1)] for c, fs in sorted(avisos.items(), key=lambda x: -len(x[1]))])
    L.append('')

    # ------------------------------------------------------------------ 4. validación
    L += ['## 4. Validación del SPIR-V', '']
    invalidos = [f for f, r in a.res.items() if r.get('val') == 'fallo']
    if not invalidos:
        L += ['**Todo valida** (%s): las %d etapas, las %d variantes del runtime%s.' % (
            'spirv-val --target-env vulkan1.1' if tra['spirv_val'] else 'SIN spirv-val: no se ha validado',
            vals['ok'], sum(1 for v in a.variantes if v.get('val') == 'ok'),
            ' y las %d etapas gráficas pasadas por spirv-opt' % sum(1 for v in a.optimizadas if v.get('val') == 'ok') if a.optimizadas else ''), '']
    else:
        por_causa = collections.defaultdict(list)
        for f in invalidos:
            por_causa[_causa(a.res[f].get('val_error'))].append(f)
        L += _tabla(['error de spirv-val', 'huellas', 'etapas', 'shaders de Unity', 'ejemplo'],
                    [['`%s`' % c, len(fs), ', '.join('%s %d' % x for x in C(etapa_de_fichero[f] for f in fs).items()),
                      shaders_de(fs), ejemplos(fs, 1)] for c, fs in sorted(por_causa.items(), key=lambda x: -len(x[1]))])
        L.append('')
    malas_var = [v for v in a.variantes if v['estado'] != 'ok' or v.get('val') == 'fallo']
    if malas_var:
        L += ['**Variantes del runtime que fallan:**', ''] + _tabla(
            ['huella', 'opciones', 'estado', 'error'],
            [[v['fichero'], ' '.join('%s=%s' % e for e in v['extra'].items()), v['estado'],
              _causa(v.get('error') or v.get('val_error'))] for v in malas_var]) + ['']
    if a.optimizadas:
        pudo = sum(1 for v in a.optimizadas if v.get('opt', '').startswith('spirv-opt:'))
        no_pudo = [v for v in a.optimizadas if not v.get('opt', '').startswith('spirv-opt:')]
        L.append('Con `<datos>/spirv_opt_todas` (las etapas gráficas también por spirv-opt): de %d, el optimizador puede con '
                 '**%d** y deja la de Eden en %d; validan %d. En el Mac, %.0f ms de media por etapa (máx. %.0f ms).' % (
                     len(a.optimizadas), pudo, len(no_pudo), sum(1 for v in a.optimizadas if v.get('val') == 'ok'),
                     sum(v['ms'] for v in a.optimizadas) / len(a.optimizadas), max(v['ms'] for v in a.optimizadas)))
        if no_pudo:
            L += [''] + _tabla(['motivo', 'huellas'], [[c, n] for c, n in C(_causa(v.get('opt')) for v in no_pudo).most_common()])
        L.append('')

    # ------------------------------------------------------------------ 5. contraste con Unity
    L += ['## 5. Lo que traduce el recompilador frente a lo que declara Unity', '']
    hechas, raros = contrastar(a)
    L.append('Cada subprograma lleva, tras el código, la reflexión de Unity (texturas con unidad y dimensión, uniform blocks '
             'con tamaño y miembros). Se ha contrastado con lo que el recompilador saca del código de Maxwell: %d usos de '
             'textura y %d de uniform block (pares código/declaración distintos).' % (hechas['texturas'], hechas['bloques']))
    L.append('')
    graves = {k: v for k, v in raros.items() if 'más bytes' not in k and 'no lee' not in k}
    dinamicos = [x for x in raros.get('el código lee más bytes de los que mide el uniform block', []) if 'lee 65536' in x]
    estaticos = [x for x in raros.get('el código lee más bytes de los que mide el uniform block', []) if 'lee 65536' not in x]
    filas = [['textura leída en una unidad que Unity no declara, fuera de la tabla c2[0x168 + 8·i] o con otra dimensión',
              sum(len(v) for v in graves.values())],
             ['lectura con offset fijo más allá del tamaño del uniform block', len(estaticos)],
             ['uniform block leído con índice dinámico (arrays: instancing, estéreo…; el traductor declara los 64 KB)', len(dinamicos)],
             ['textura o uniform block declarados por Unity que el código traducido no usa', sum(len(v) for k, v in raros.items() if 'no lee' in k)]]
    L += _tabla(['comprobación', 'casos'], filas)
    L.append('')
    for k, v in list(graves.items()) + ([('lectura fija más allá del uniform block', estaticos)] if estaticos else []):
        L += ['**%s** (%d):' % (k, len(v)), ''] + ['- ' + x for x in v[:12]] + ['']
    no_usa = [x for k, v in raros.items() if 'no lee' in k for x in v]
    if no_usa:
        L += ['Declarados y sin usar (primeros):', ''] + ['- ' + x for x in no_usa[:8]] + ['']
    bancos = C(b for r in a.res.values() for b in r.get('leido', {}))
    L.append('Bancos de constantes que leen las etapas traducidas: %s. c1 son las constantes del propio programa (y las '
             'tablas de salto de los BRX), c2 la tabla de handles leída como datos (el ejecutor la sintetiza), c0 la tabla del '
             'driver (en compute, las direcciones de los storage buffers) y c3 en adelante los uniform blocks (c3 + binding).' % (
                 ', '.join('c%s en %d' % (b, n) for b, n in sorted(bancos.items(), key=lambda x: int(x[0])))))
    L.append('')

    # ------------------------------------------------------------------ 6. rasgos
    L += ['## 6. Rasgos que importan en Vulkan y en el Adreno', '', '### 6.1 Etapas', '']
    L += _tabla(['etapa', 'programas', 'códigos distintos', 'de dónde'],
                [[e, por_etapa_p[e], por_etapa_u[e], shaders_de([f for f in a.usos if etapa_de_fichero[f] == e], 4)
                  if e not in ('vertex', 'pixel') else 'todos los Shader'] for e, _ in por_etapa_u.most_common()])
    faltan = [e for e in ETAPAS if e not in por_etapa_u]
    L += ['', 'No hay ninguna etapa de: %s.' % (', '.join(faltan) or '(están todas)'), '']

    def lista_rasgo(titulo, cond, extra=None, n=12):
        sel = sorted(f for f in ras if cond(ras[f]))
        fuera = ['**%s: %d códigos** (%s).' % (titulo, len(sel), ', '.join('%s %d' % x for x in C(etapa_de_fichero[f] for f in sel).most_common()) or '-')]
        if sel:
            fuera += [''] + _tabla(['huella', 'etapa', 'usos', 'shader de Unity'] + (['detalle'] if extra else []),
                                   [['`%s`' % a.usos[f][0]['huella'], etapa_de_fichero[f], sum(1 for p in a.usos[f] if not p['nota']),
                                     a.nombre(f)] + ([extra(f)] if extra else []) for f in sel[:n]])
            if len(sel) > n:
                fuera.append('')
                fuera.append('…y %d más (`rasgos.tsv`). Por shader: %s.' % (len(sel) - n, shaders_de(sel, 8)))
        return fuera + ['']

    L += ['### 6.2 Switch por tabla (BRX)', '']
    L += lista_rasgo('Con BRX/JMX', lambda x: x['brx'], lambda f: 'tablas de c1 leídas: %s; reemplazo optimizado: %s' % (
        'sí' if a.res[f].get('aud', {}).get('brx') else 'no',
        '`spirv_reemplazo/%s.spv`' % f[:16] if os.path.exists(os.path.join(op.salida, 'spirv_reemplazo', f[:16] + '.spv')) else 'no'))
    L += ['Son gráficos: se traducen con sus tablas de salto (c1) y **no** pasan por spirv-opt (en la Flip solo los compute). '
          'El flujo con banderas que deja Eden al deshacer un BRX es el que el driver de Qualcomm compiló mal en el skinning de '
          'MH Rise; si alguno de estos sale mal en la consola, su módulo optimizado ya está en `spirv_reemplazo/` (copiar a '
          '`<datos>/spirv_reemplazo/`), o `touch <datos>/spirv_opt_todas`.', '']
    L += ['### 6.3 Derivadas "a lo NVIDIA" (SHFL + FSWZADD)', '']
    con = [f for f in ras if ras[f]['shfl'] or ras[f]['fswzadd']]
    sin_plegar = [f for f in ras if ras[f]['sin_plegar']]
    L.append('**%d códigos** usan SHFL/FSWZADD (%s), con %d SHFL y %d FSWZADD en total. Tras la traducción: %d derivadas de '
             'Vulkan (%s) y **%d códigos con algún FSwizzleAdd/Shuffle/QuadBroadcast sin plegar** (los que en el Adreno, sin '
             'subgrupos en fragment, darían basura).' % (
                 len(con), ', '.join('%s %d' % x for x in C(etapa_de_fichero[f] for f in con).most_common()) or '-',
                 sum(ras[f]['shfl'] for f in con), sum(ras[f]['fswzadd'] for f in con),
                 sum(ras[f]['derivadas'] for f in ras),
                 ', '.join('%s %d' % (k, sum(a.res[f].get('ir', {}).get(k, 0) for f in ras)) for k in ('DPdxFine', 'DPdyFine', 'DPdxCoarse', 'DPdyCoarse')),
                 len(sin_plegar)))
    L.append('')
    L.append('Por shader: %s.' % shaders_de(con, 12))
    L.append('')
    if sin_plegar:
        L += lista_rasgo('Sin plegar', lambda x: x['sin_plegar'])
    L += ['### 6.4 discard, profundidad y salidas', '']
    kil = [f for f in ras if ras[f]['kil']]
    L.append('- **discard**: %d códigos de pixel con KIL (%d según su cabecera SPH); traducidos, %d con '
             'DemoteToHelperInvocation (OpKill en el SPIR-V).' % (len(kil), sum(1 for f in ras if ras[f]['sph_kil']),
                                                                 sum(1 for f in ras if ras[f]['descarte'])))
    prof = sorted(f for f in ras if ras[f]['profundidad'])
    L.append('- **escritura de profundidad** (gl_FragDepth): %d códigos (%d según la SPH): %s.' % (
        len(prof), sum(1 for f in ras if ras[f]['sph_profundidad']), shaders_de(prof, 10)))
    colores = C(bin(ras[f]['colores']).count('1') for f in ras if etapa_de_fichero[f] == 'pixel')
    L.append('- **render targets escritos por pixel shader**: %s.' % ', '.join(
        '%d con %d' % (n, k) for k, n in sorted(colores.items())))
    L.append('')
    L += ['### 6.5 Texturas', '']
    tipos = C(t for f in ras for t in ras[f]['tipos'])
    usos_tipo = C(tipo_de_imagen(i) for f in ras for i in (a.res[f].get('spv') or {}).get('imagenes', []))
    L += _tabla(['tipo (como lo declara el SPIR-V)', 'códigos que lo usan', 'declaraciones', 'shaders'],
                [[t, n, usos_tipo[t], shaders_de([f for f in ras if t in ras[f]['tipos']], 4)] for t, n in tipos.most_common()])
    L.append('')
    L += ['### 6.6 Recursos por etapa', '']
    filas = []
    for e, _ in por_etapa_u.most_common():
        fs = [f for f in ras if etapa_de_fichero[f] == e]
        if not fs:
            continue
        fila = [e]
        for campo in ('texturas', 'ubos', 'ssbos', 'imagenes'):
            mejor = max(fs, key=lambda f: ras[f][campo])
            fila.append('%d' % ras[mejor][campo] + (' (`%s`)' % a.usos[mejor][0]['huella'] if ras[mejor][campo] else ''))
        mejor = max(fs, key=lambda f: len(a.res[f].get('recursos', [])))
        fila.append('%d (`%s` %s)' % (len(a.res[mejor].get('recursos', [])), a.usos[mejor][0]['huella'], a.nombre(mejor)[:60]))
        filas.append(fila)
    L += _tabla(['etapa', 'máx. texturas', 'máx. UBO', 'máx. SSBO', 'máx. imágenes', 'máx. recursos en total'], filas)
    unidad = max([(x[4] - 0x168) // 8 for r in a.res.values() for x in r.get('recursos', []) if x[0] == 'textura' and len(x) > 4 and x[3] == 2 and x[4] >= 0x168] or [0])
    banco = max([int(b) for r in a.res.values() for b in r.get('leido', {})] or [0])
    L.append('')
    L.append('Unidad de textura más alta: %d; banco de constantes más alto: c%d. Arrays de descriptores (set 1, bindless): %d códigos.' % (
        unidad, banco, sum(1 for r in a.res.values() if any(len(x) > 6 and (x[1] or x[6] > 1) for x in r.get('recursos', [])))))
    L.append('')
    L += ['### 6.7 Capacidades de SPIR-V frente a la Flip', '']
    caps = collections.defaultdict(list)
    exts = C()
    for f, r in a.res.items():
        for c in (r.get('spv') or {}).get('caps', []):
            caps[_CAPACIDADES.get(c, 'capacidad %d' % c)].append(f)
        for x in (r.get('spv') or {}).get('exts', []):
            exts[x] += 1
    filas = []
    for c, fs in sorted(caps.items(), key=lambda x: -len(x[1])):
        ok, por_que = CAPACIDADES_FLIP.get(c, (None, 'sin clasificar: revisar'))
        etapas = C(etapa_de_fichero[f] for f in fs)
        if c.startswith('GroupNonUniform') and ok is None:
            ok = set(etapas) <= {'compute'}
        filas.append([c, len(fs), ', '.join('%s %d' % x for x in etapas.most_common()),
                      'sí' if ok else ('**NO**' if ok is False else '**a medias**'), por_que])
    L += _tabla(['capacidad', 'códigos', 'etapas', '¿la tiene el dispositivo que crea vk.cpp?', 'por qué'], filas)
    L += ['', 'Extensiones de SPIR-V declaradas: %s.' % (', '.join('%s (%d)' % x for x in exts.most_common()) or 'ninguna'), '']
    anchos = C(x for r in a.res.values() for x in (r.get('spv') or {}).get('anchos', []))
    L.append('Tipos numéricos: %s (ni float64 ni enteros de 64, 16 u 8 bits salvo los listados).' % ', '.join('%s en %d' % x for x in anchos.most_common()))
    L.append('')
    L += ['### 6.8 Límites', '']
    grupos_c = [r['grupo'] for f, r in a.res.items() if etapa_de_fichero[f] == 'compute' and 'grupo' in r]
    medido = {
        'entradas de pixel (componentes)': max([(r.get('spv') or {}).get('comp_in', 0) for f, r in a.res.items() if etapa_de_fichero[f] == 'pixel'] or [0]),
        'salidas de vertex (componentes)': max([(r.get('spv') or {}).get('comp_out', 0) for f, r in a.res.items() if etapa_de_fichero[f] == 'vertex'] or [0]),
        'invocaciones por grupo de compute': max([g[0] * g[1] * g[2] for g in grupos_c] or [0]),
        'memoria compartida de compute (bytes)': max([g[3] for g in grupos_c] or [0]),
        'bindings por etapa (kBindingsPerStage de nvn_shader.h)': max([len(r.get('recursos', [])) for r in a.res.values()] or [0]),
        'unidades de textura (kMaxTextures del ejecutor)': unidad + 1,
        'bancos de constantes (kMaxUniforms del ejecutor)': banco + 1,
    }
    L += _tabla(['límite', 'máximo del juego', 'tope', ''], [[k, medido[k], v, 'bien' if medido[k] <= v else '**SE PASA**'] for k, v in LIMITES.items()])
    L += ['', 'Grupos de compute: %s.' % ', '.join('%dx%dx%d en %d' % (g[0], g[1], g[2], n) for g, n in C(tuple(g) for g in grupos_c).most_common()), '']
    L += ['### 6.9 Otros', '']
    builtins = C()
    for f, r in a.res.items():
        s = r.get('spv') or {}
        for lado in ('in', 'out'):
            for b in s.get('builtins_' + lado, []):
                builtins[(etapa_de_fichero[f], 'lee' if lado == 'in' else 'escribe', _BUILTINS.get(b, 'builtin %d' % b))] += 1
    L.append('- Builtins: %s.' % ', '.join('%s %s %s (%d)' % (e, v, b, n) for (e, v, b), n in builtins.most_common()))
    modos = C(_MODOS.get(m[0], 'modo %d' % m[0]) for r in a.res.values() for m in (r.get('spv') or {}).get('modos', []))
    L.append('- Modos de ejecución: %s.' % ', '.join('%s (%d)' % x for x in modos.most_common()))
    L.append('- Instancing por gl_BaseInstance (DrawParameters): %d vertex. Vertex que leen texturas: %d. Pixel que leen '
             'gl_FragCoord: %d.' % (len(caps.get('DrawParameters', [])),
                                    sum(1 for f in ras if etapa_de_fichero[f] == 'vertex' and ras[f]['texturas']),
                                    builtins[('pixel', 'lee', 'FragCoord')]))
    op_mx = collections.defaultdict(lambda: [0, 0])
    op_ir = collections.defaultdict(lambda: [0, 0])
    for r in a.res.values():
        for k, v in r.get('maxwell', {}).get('ops', {}).items():
            op_mx[k][0] += 1
            op_mx[k][1] += v
        for k, v in r.get('ir', {}).items():
            op_ir[k][0] += 1
            op_ir[k][1] += v
    for nombre, tabla in (('maxwell.tsv', op_mx), ('ir.tsv', op_ir)):
        with open(os.path.join(op.salida, nombre), 'w') as f:
            f.write('instruccion\tcodigos\tveces\n')
            for k, (n, v) in sorted(tabla.items(), key=lambda x: -x[1][0]):
                f.write('%s\t%d\t%d\n' % (k, n, v))
    L.append('- Instrucciones de Maxwell distintas en todo el juego: %d (`maxwell.tsv`); opcodes del IR de Eden: %d (`ir.tsv`).' % (
        len([k for k in op_mx if k not in ('relleno', 'desconocida')]), len(op_ir)))
    L.append('')

    # ------------------------------------------------------------------ 7. volcados y huellas conocidas
    L += ['## 7. Contraste con la consola', '', '### 7.1 Volcados', '']
    carpetas = [os.path.join(RAIZ, 'work', d) for d in ('at', 'pares')]
    filas = comparar_volcados(a, carpetas)
    if filas:
        L += _tabla(['volcado', 'huella del volcado', 'veredicto'], [[d, '`%s`' % h, v] for d, h, v in filas])
    else:
        L.append('(sin volcados en work/at ni work/pares)')
    L.append('')
    L += ['### 7.2 Huellas de los logs (`work/runs/*.log`)', '']
    carpeta_logs = os.path.join(RAIZ, 'work', 'runs')
    vistas, raras = C(), C()
    logs = sorted(os.listdir(carpeta_logs)) if os.path.isdir(carpeta_logs) else []
    for n in logs:
        if n.endswith('.log'):
            c, d = huellas_de_log(a, os.path.join(carpeta_logs, n))
            vistas.update(c.keys())
            for h in d:
                raras[h] += 1
    L.append('En %d logs aparecen **%d huellas con nombre** (de %d) y %d que parecen de shader y no están en la tabla%s.' % (
        len([n for n in logs if n.endswith('.log')]), len(vistas), len(a.por_huella), len(raras),
        '' if not raras else ': ' + ', '.join('`%s` (%d logs)' % x for x in raras.most_common(12))))
    L.append('')
    L.append('Para ponerle nombre a las de un log: `python3 tools/shader_audit.py log <fichero.log>`; a una suelta: '
             '`python3 tools/shader_audit.py huella <huella>`.')
    L.append('')

    # ------------------------------------------------------------------ 8. ficheros
    L += ['## 8. Ficheros de esta carpeta', '']
    L += _tabla(['fichero', 'qué es'], [
        ['`huellas.tsv`', '%d filas: huella -> etapa, estado, Shader de Unity, pase, keywords, otros Shader con el mismo código, '
                          'texturas (unidad=nombre:dimensión) y uniform blocks (banco=nombre:bytes)' % n_huellas],
        ['`programas.tsv`', 'los %d programas uno a uno (fichero de origen, objeto, variante, etapa, huella)' % len(a.programas)],
        ['`rasgos.tsv`', 'los rasgos de cada código (BRX, SHFL, FSWZADD, derivadas, KIL, profundidad, recursos, tipos de textura)'],
        ['`maxwell.tsv`, `ir.tsv`', 'histograma de instrucciones de Maxwell y de opcodes del IR de Eden'],
        ['`shaders/<huella>.code`, `_ctrl.code`', 'cada código y su sección de control, listos para shadertool'],
        ['`spv/<huella>.spv`', 'su SPIR-V (y `<huella>_g<máscara>.spv`, las variantes de genéricos)'],
        ['`spirv_reemplazo/<huella>.spv`', 'los que tienen BRX, pasados por spirv-opt (para `<datos>/spirv_reemplazo/`)'],
        ['`reflexion.jsonl`', 'lo que declara Unity de cada variante (texturas, uniform blocks con sus miembros y offsets)'],
        ['`resultados.jsonl`, `variantes.jsonl`, `optimizadas.jsonl`, `extraccion.json`, `traduccion.json`', 'los datos crudos de este informe'],
    ])
    L += ['', 'Repetir todo: `python3 tools/shader_audit.py` (%.0f s la extracción, %.0f s la traducción).' % (
        ext['segundos'], tra['segundos']), '']
    with open(os.path.join(op.salida, 'informe.md'), 'w') as f:
        f.write('\n'.join(L))
    print('informe: %s (%d huellas en huellas.tsv)' % (os.path.join(op.salida, 'informe.md'), n_huellas))
    return 0


def orden_huella(a, argumentos):
    for h in argumentos:
        h = h.lower().lstrip('0x').rjust(16, '0') if len(h) <= 18 else h
        ficheros = a.por_huella.get(h)
        if not ficheros:
            print('%s: no está en la tabla (¿variante del runtime o shader de fuera del romfs?)' % h)
            continue
        for fichero in sorted(ficheros):
            p, otros = a.principal(fichero)
            r = a.res.get(fichero, {})
            tex, blo = a.recursos_con_nombre(fichero)
            print('%s %s: %s' % (h, p['etapa'], a.nombre(fichero)))
            print('    %d programas en %d shaders; traducción %s, spirv-val %s; %s' % (
                len(a.usos[fichero]), len(otros) + 1, r.get('estado', '-'), r.get('val', '-'), p['origen']))
            if otros:
                print('    también: ' + '; '.join(otros[:8]))
            if tex or blo:
                print('    recursos: ' + ' '.join(x for x in (tex, blo) if x))
            print('    código: %s' % os.path.join(a.salida, 'shaders', fichero + '.code'))
    return 0


def orden_log(a, argumentos):
    for ruta in argumentos:
        conocidas, desconocidas = huellas_de_log(a, ruta)
        print('%s: %d huellas con nombre, %d de shader sin nombre' % (ruta, len(conocidas), len(desconocidas)))
        for h, n in conocidas.most_common():
            fichero = sorted(a.por_huella[h])[0]
            print('  %s x%-4d %-8s %s' % (h, n, a.usos[fichero][0]['etapa'], a.nombre(fichero)))
        prefijos = buscar_prefijos(a, desconocidas)
        for h, n in desconocidas.most_common():
            print('  %s x%-4d SIN NOMBRE: %s' % (h, n, explicar_prefijo(a, prefijos.get(h))))
    return 0


def orden_volcados(a, argumentos):
    for donde, huella, veredicto in comparar_volcados(a, argumentos):
        print('%s  %s  %s' % (donde, huella, veredicto))
    return 0


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('accion', nargs='?', default='todo')
    p.add_argument('argumentos', nargs='*')
    p.add_argument('--romfs', default=os.path.join(RAIZ, 'work', 'romfs'))
    p.add_argument('--exefs', default=os.path.join(RAIZ, 'work', 'exefs'))
    p.add_argument('--salida', default=os.path.join(RAIZ, 'work', 'shader_audit'))
    p.add_argument('--shadertool', default=os.path.join(RAIZ, 'build', 'shadertool', 'shadertool'))
    p.add_argument('--spirv-val', default=os.path.join(NDK, 'shader-tools', 'darwin-x86_64', 'spirv-val'))
    p.add_argument('--hilos', type=int, default=os.cpu_count() or 4)
    p.add_argument('--limite', type=int, default=60, help='segundos por traducción antes de darla por colgada')
    p.add_argument('--solo', default='', help='solo los ficheros cuya ruta contenga este texto (muestreo)')
    p.add_argument('--sin-barrido', action='store_true', help='no buscar secciones de control sueltas en el resto del romfs')
    p.add_argument('--sin-opt-todas', action='store_true', help='no probar spirv-opt con las etapas gráficas')
    p.add_argument('--guardar-ir', action='store_true', help='deja el IR de Eden de cada traducción en <salida>/ir/')
    op = p.parse_args()
    os.makedirs(op.salida, exist_ok=True)
    if op.accion == 'todo':
        sys.exit(extraer(op) or traducir(op) or informe(op))
    if op.accion == 'extraer':
        sys.exit(extraer(op))
    if op.accion == 'traducir':
        sys.exit(traducir(op))
    if op.accion == 'informe':
        sys.exit(informe(op))
    if op.accion == 'huella':
        sys.exit(orden_huella(Auditoria(op.salida), op.argumentos))
    if op.accion == 'log':
        sys.exit(orden_log(Auditoria(op.salida), op.argumentos))
    if op.accion == 'volcados':
        sys.exit(orden_volcados(Auditoria(op.salida), op.argumentos))
    sys.exit('acción desconocida: %s' % op.accion)
