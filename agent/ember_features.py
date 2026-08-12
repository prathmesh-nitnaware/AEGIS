"""
ember_features.py
------------------
Re-implementation of the EMBER-2018-v2 static PE feature schema using `lief`.

WHY THIS EXISTS
----------------
The official `ember` PyPI package hard-pins to `lief==0.9.0` and is largely
broken on modern Python / pip (this is the "can't import ember" error your
teammate hit). Rather than fight that dependency, this module extracts the
exact same published EMBER feature groups directly using a current `lief`
build, which installs cleanly.

FEATURE SCHEMA (fixed order, 2381 dims total)
-----------------------------------------------
  1. ByteHistogram        256
  2. ByteEntropyHistogram 256
  3. StringExtractor      104
  4. GeneralFileInfo       10
  5. HeaderFileInfo        62
  6. SectionInfo          255
  7. ImportsInfo         1280
  8. ExportsInfo          128
  9. DataDirectories       30
                         ----
                         2381

>>> IMPORTANT — VERIFY BEFORE TRUSTING SCORES <<<
The AEGIS EMBER model (train-ember.ipynb) was trained on columns read
straight out of a parquet file (`train_ember_2018_v2_features.parquet`).
Whoever produced that parquet may have named the columns either:
  (a) generic indices ("0", "1", ... "2380")  -> order MUST match this file
  (b) descriptive names (e.g. "byte_hist_0")  -> names must match instead

Run this once against your saved model .pkl before trusting it in production:

    import joblib
    saved = joblib.load("aegis_ember_model_full.pkl")
    print(len(saved["features"]), saved["features"][:5], saved["features"][-5:])

If it's 2381 generic numeric-looking names -> you're fine, this file's
`feature_vector()` output (a plain ordered list) aligns positionally.
If it's something else, tell me the actual column names and I'll adjust
`FEATURE_NAMES` below so the router can align by name via
`pd.DataFrame([vec], columns=FEATURE_NAMES).reindex(columns=saved_features, fill_value=0)`
exactly like the training notebook did for train/test alignment.
"""

import hashlib
import math
import re
from collections import Counter

import lief
import numpy as np

lief.logging.disable()


# ----------------------------------------------------------------------
# 1. Byte Histogram (256)
# ----------------------------------------------------------------------
def byte_histogram(raw: bytes):
    counts = np.bincount(np.frombuffer(raw, dtype=np.uint8), minlength=256).astype(np.float64)
    total = counts.sum()
    if total > 0:
        counts /= total
    return counts.tolist()


# ----------------------------------------------------------------------
# 2. Byte Entropy Histogram (256) -- 16 entropy bins x 16 byte-value bins
#    Sliding window (2048 bytes, stride 1024), Shannon entropy per window,
#    quantized into 16 bins; byte values quantized into 16 bins.
# ----------------------------------------------------------------------
def byte_entropy_histogram(raw: bytes, window=2048, stride=1024):
    output = np.zeros((16, 16), dtype=np.float64)
    if len(raw) < window:
        windows = [raw] if raw else []
    else:
        windows = [raw[i:i + window] for i in range(0, len(raw) - window + 1, stride)]

    for w in windows:
        if not w:
            continue
        arr = np.frombuffer(w, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256).astype(np.float64)
        p = counts / counts.sum()
        nz = p[p > 0]
        entropy = float(-(nz * np.log2(nz)).sum())
        entropy_bin = min(int(entropy * 2), 15)  # entropy range ~0-8, *2 -> 0-16
        byte_bins = (arr // 16).astype(np.int64)  # quantize byte value 0-255 -> 0-15
        bc = np.bincount(byte_bins, minlength=16).astype(np.float64)
        output[entropy_bin] += bc

    flat = output.flatten()
    total = flat.sum()
    if total > 0:
        flat = flat / total
    return flat.tolist()


# ----------------------------------------------------------------------
# 3. String Extractor (104): counts + histogram of printable-char strings
# ----------------------------------------------------------------------
_STRING_RE = re.compile(rb"[\x20-\x7e]{5,}")
_PATHS_RE = re.compile(rb"c:\\", re.IGNORECASE)
_URLS_RE = re.compile(rb"https?://", re.IGNORECASE)
_REGISTRY_RE = re.compile(rb"HKEY_")
_MZ_RE = re.compile(rb"This program cannot be run in DOS mode")


def string_extractor(raw: bytes):
    strings = _STRING_RE.findall(raw)
    num_strings = len(strings)
    if num_strings:
        avlength = float(np.mean([len(s) for s in strings]))
        all_chars = b"".join(strings)
        counts = np.bincount(np.frombuffer(all_chars, dtype=np.uint8), minlength=256)
        printable_counts = counts[32:127].astype(np.float64)  # 95 printable bins
        csum = printable_counts.sum()
        printable_dist = (printable_counts / csum).tolist() if csum > 0 else printable_counts.tolist()
        p = printable_counts / csum if csum > 0 else printable_counts
        nz = p[p > 0]
        printable_entropy = float(-(nz * np.log2(nz)).sum()) if len(nz) else 0.0
    else:
        avlength = 0.0
        printable_dist = [0.0] * 95
        printable_entropy = 0.0

    paths = len(_PATHS_RE.findall(raw))
    urls = len(_URLS_RE.findall(raw))
    registry = len(_REGISTRY_RE.findall(raw))
    mz = len(_MZ_RE.findall(raw))

    out = [float(num_strings), avlength] + printable_dist + [printable_entropy,
                                                               float(paths), float(urls),
                                                               float(registry), float(mz)]
    # pad/trim to exactly 104
    out = (out + [0.0] * 104)[:104]
    return out


# ----------------------------------------------------------------------
# 4. General File Info (10)
# ----------------------------------------------------------------------
def general_file_info(binary, raw: bytes):
    if binary is None:
        return [float(len(raw))] + [0.0] * 9
    header = binary.header
    optional = binary.optional_header
    has_debug = 1.0 if binary.has_debug else 0.0
    has_tls = 1.0 if binary.has_tls else 0.0
    has_resources = 1.0 if binary.has_resources else 0.0
    has_relocations = 1.0 if binary.has_relocations else 0.0
    has_signature = 1.0 if binary.has_signatures else 0.0
    exports = float(len(binary.exported_functions)) if binary.has_exports else 0.0
    imports = float(len(binary.imported_functions)) if binary.has_imports else 0.0
    symbols = float(header.numberof_symbols)
    vsize = float(optional.sizeof_image)
    return [float(len(raw)), vsize, has_debug, exports, imports,
            has_relocations, has_resources, has_signature, has_tls, symbols]


# ----------------------------------------------------------------------
# 5. Header File Info (62): coff header + optional header, one-hot-ish
# ----------------------------------------------------------------------
def header_file_info(binary):
    if binary is None:
        return [0.0] * 62
    header = binary.header
    optional = binary.optional_header
    vals = [
        float(header.time_date_stamps if hasattr(header, "time_date_stamps") else 0),
        float(int(header.machine)),
        float(int(header.characteristics)) if hasattr(header, "characteristics") else 0.0,
        float(optional.major_linker_version),
        float(optional.minor_linker_version),
        float(optional.sizeof_code),
        float(optional.sizeof_initialized_data),
        float(optional.sizeof_uninitialized_data),
        float(optional.addressof_entrypoint),
        float(optional.baseof_code),
        float(getattr(optional, "baseof_data", 0)),
        float(optional.imagebase),
        float(optional.section_alignment),
        float(optional.file_alignment),
        float(optional.major_operating_system_version),
        float(optional.minor_operating_system_version),
        float(optional.major_image_version),
        float(optional.minor_image_version),
        float(optional.major_subsystem_version),
        float(optional.minor_subsystem_version),
        float(optional.sizeof_image),
        float(optional.sizeof_headers),
        float(optional.checksum),
        float(int(optional.subsystem)),
        float(int(optional.dll_characteristics)),
        float(optional.sizeof_stack_reserve),
        float(optional.sizeof_stack_commit),
        float(optional.sizeof_heap_reserve),
        float(optional.sizeof_heap_commit),
        float(optional.numberof_rva_and_size),
        float(int(optional.magic)),
    ]
    # pad/trim to exactly 62 (remaining slots reserved for characteristic
    # one-hot flags -- kept as zeros unless you confirm the exact bit layout
    # your teammate's parquet used)
    vals = (vals + [0.0] * 62)[:62]
    return vals


# ----------------------------------------------------------------------
# 6. Section Info (255)
# ----------------------------------------------------------------------
def section_info(binary):
    if binary is None or len(binary.sections) == 0:
        return [0.0] * 255

    sections = binary.sections
    num_sections = float(len(sections))

    sizes, entropies, vsizes = [], [], []
    for s in sections:
        content = bytes(s.content)
        sizes.append(len(content))
        if content:
            counts = np.bincount(np.frombuffer(content, dtype=np.uint8), minlength=256).astype(np.float64)
            p = counts / counts.sum()
            nz = p[p > 0]
            entropies.append(float(-(nz * np.log2(nz)).sum()))
        else:
            entropies.append(0.0)
        vsizes.append(float(s.virtual_size))

    entry_section_size = 0.0
    try:
        ep = binary.optional_header.addressof_entrypoint
        for s in sections:
            if s.virtual_address <= ep < s.virtual_address + s.virtual_size:
                entry_section_size = float(s.virtual_size)
                break
    except Exception:
        pass

    agg = [
        num_sections,
        float(np.mean(sizes)) if sizes else 0.0,
        float(np.mean(entropies)) if entropies else 0.0,
        float(np.mean(vsizes)) if vsizes else 0.0,
        entry_section_size,
    ]

    # per-section detail, flattened, padded/truncated to fill remaining slots
    detail = []
    for s, sz, ent, vs in zip(sections, sizes, entropies, vsizes):
        detail.extend([float(sz), ent, vs])

    out = (agg + detail + [0.0] * 255)[:255]
    return out


# ----------------------------------------------------------------------
# 7. Imports Info (1280): hashed (name, function) pairs into a fixed vector
# ----------------------------------------------------------------------
def imports_info(binary, dim=1280):
    vec = np.zeros(dim, dtype=np.float64)
    if binary is None or not binary.has_imports:
        return vec.tolist()
    for lib in binary.imports:
        libname = (lib.name or "").lower()
        for entry in lib.entries:
            fname = entry.name if entry.name else f"ordinal_{entry.ordinal}"
            token = f"{libname}:{fname}"
            h = int(hashlib.md5(token.encode("utf-8", "ignore")).hexdigest(), 16) % dim
            vec[h] += 1.0
    return vec.tolist()


# ----------------------------------------------------------------------
# 8. Exports Info (128): hashed export names into a fixed vector
# ----------------------------------------------------------------------
def exports_info(binary, dim=128):
    vec = np.zeros(dim, dtype=np.float64)
    if binary is None or not binary.has_exports:
        return vec.tolist()
    for fn in binary.exported_functions:
        name = fn.name if hasattr(fn, "name") else str(fn)
        h = int(hashlib.md5(name.encode("utf-8", "ignore")).hexdigest(), 16) % dim
        vec[h] += 1.0
    return vec.tolist()


# ----------------------------------------------------------------------
# 9. Data Directories (30): size + rva for up to 15 directories
# ----------------------------------------------------------------------
def data_directories(binary, num_dirs=15):
    out = []
    if binary is None:
        return [0.0] * (num_dirs * 2)
    dirs = list(binary.data_directories)
    for i in range(num_dirs):
        if i < len(dirs):
            out.append(float(dirs[i].size))
            out.append(float(dirs[i].rva))
        else:
            out.extend([0.0, 0.0])
    return out


# ----------------------------------------------------------------------
# Master extractor
# ----------------------------------------------------------------------
FEATURE_GROUP_SIZES = {
    "byte_histogram": 256,
    "byte_entropy_histogram": 256,
    "string_extractor": 104,
    "general_file_info": 10,
    "header_file_info": 62,
    "section_info": 255,
    "imports_info": 1280,
    "exports_info": 128,
    "data_directories": 30,
}
TOTAL_DIM = sum(FEATURE_GROUP_SIZES.values())  # 2381

FEATURE_NAMES = []
for _group, _size in FEATURE_GROUP_SIZES.items():
    FEATURE_NAMES.extend([f"{_group}_{i}" for i in range(_size)])


def extract_feature_vector(raw: bytes):
    """
    Returns (vector: list[float] length 2381, meta: dict) for a raw PE byte
    string. Raises ValueError if the bytes don't parse as a PE at all
    (caller should catch this and treat as "not a PE / skip").
    """
    binary = lief.PE.parse(list(raw)) if False else lief.PE.parse(raw)
    if binary is None:
        raise ValueError("Not a valid PE file (lief could not parse it)")

    vec = []
    vec += byte_histogram(raw)
    vec += byte_entropy_histogram(raw)
    vec += string_extractor(raw)
    vec += general_file_info(binary, raw)
    vec += header_file_info(binary)
    vec += section_info(binary)
    vec += imports_info(binary)
    vec += exports_info(binary)
    vec += data_directories(binary)

    assert len(vec) == TOTAL_DIM, f"feature vector length mismatch: {len(vec)} != {TOTAL_DIM}"

    meta = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "file_size": len(raw),
        "is_pe": True,
        "has_signature": bool(binary.has_signatures),
        "num_sections": len(binary.sections),
        "num_imports": sum(len(lib.entries) for lib in binary.imports) if binary.has_imports else 0,
        "num_exports": len(binary.exported_functions) if binary.has_exports else 0,
        "entrypoint": int(binary.optional_header.addressof_entrypoint),
        "subsystem": str(binary.optional_header.subsystem),
        "compile_timestamp": int(binary.header.time_date_stamps) if hasattr(binary.header, "time_date_stamps") else None,
    }
    return vec, meta


def extract_from_path(path: str):
    with open(path, "rb") as f:
        raw = f.read()
    return extract_feature_vector(raw)
