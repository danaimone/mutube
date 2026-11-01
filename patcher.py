#!/usr/bin/env python3
# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "capstone>=5.0.6",
#     "lief>=0.17.3",
# ]
# ///
import argparse
import plistlib
import re
import subprocess
import struct
import tempfile
import zipfile
from pathlib import Path

import lief
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

YTTV_NEEDLE = b"yttv"
CSP_PREFIX = b"sponsorblock.inf.re sponsor.ajay.app dearrow-thumb.ajay.app cdn.jsdelivr.net "
LOG_HTML_ENTRY = b"MUTUBE_HTMLSCRIPT ra=%p\n"
LOG_HTML_INJECT = b"MUTUBE_HTMLSCRIPT injected\n"
LOG_CSP_ENTRY = b"MUTUBE_CSP ra=%p\n"
LOG_CSP_INJECT = b"MUTUBE_CSP injected\n"
# Registers saved/restored by stubs, listed in the pairs they are spilled in.
# Index defines the stack slot, 8 bytes each.
SAVED_REGS = [*range(20), 29, 30]
# The frame probe calls dlsym, libc and Objective-C, so it spills a wider set.
# Every successor of the hook site writes x0-x15 before reading them, so x3-x7
# and x10-x15 need no save.
FRAME_REGS = [0, 1, 2, 8, 9, 16, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30]
# Stub frame: saved registers first, then a scratch buffer at FRAME_BUF_OFF.
FRAME_BUF_OFF = 0x80
FRAME_BUF_SIZE = 0x1A0
FRAME_SAVE_SIZE = FRAME_BUF_OFF + FRAME_BUF_SIZE

# 4.54.01 only. Store function entry VAs and derive patch sites by skipping
# the stack/frame prologue at runtime.
# We do not patch entry directly: our BL->stub->ret flow must run after prologue.
PATCHES = [
    {
        "name": "htmlscript",
        "kind": "html",
        "entry_va": 0x100EBD830,
        "expect": ("ldrb", "w8, [x0, #0x4b0]"),
    },
    {
        "name": "csp",
        "kind": "csp",
        "entry_va": 0x101515AC8,
        "expect": ("mov", "x21, x2"),
    },
]

COBALT_HOOKS = [
    {
        "name": "cobalt_vp9_profile2_support",
        "kind": "media_support",
        "entry_va": 0x101180894,
        "expect": ("mov", "x20, x1"),
    },
]

# Diagnostic-only hook: writes one fixed record per copied frame, holding the
# source plane, a centre luma sample, the destination stride and pixel format,
# the decoder's range field, and the 10-bit flag that selects the x420 pool.
# Only built with --diag-frames.
COBALT_DIAG_PATCHES = [
    {
        "name": "cobalt_frame_copy_probe",
        "kind": "frame_copy",
        "entry_va": 0x10112A86C,
        "exact": True,
        "expect": ("cmp", "x9, #0"),
    },
]

# YouTube 4.54.01 Cobalt gates used by the tvOS HDR output path. The patches
# keep the app's existing AVDisplayCriteria and VP9 Profile 2 flow active after
# the IPA is re-signed.
COBALT_HDR_PATCHES = [
    {
        "name": "cobalt_display_criteria_gate",
        "va": 0x101142BE4,
        "expect": ("cbz", "w0, #0x101142d0c"),
        "replacement": 0xD503201F,  # nop
    },
    {
        "name": "cobalt_vp9_hdr_hw_gate",
        "va": 0x10114F840,
        "expect": ("cbz", "w0, #0x10114f874"),
        "replacement": 0xD503201F,  # nop
    },
    {
        "name": "cobalt_vp9_hdr_4k60_gate",
        "va": 0x10114F870,
        "expect": ("b", "#0x10114f730"),
        "replacement": 0x14000009,  # b 0x10114f894 (supported)
    },
]

# YouTube 4.54.01 Cobalt VP9 and tvOS renderer tuning. These changes keep the
# existing decoder and renderer paths, but adjust queue sizing, preroll, and
# late-frame handling for high-resolution playback.
COBALT_PLAYBACK_PATCHES = [
    {
        "name": "cobalt_vpx_4k_sdr_frame_pool_gate",
        "va": 0x101129830,
        "expect": ("cbz", "w9, #0x101129858"),
        "replacement": 0xD503201F,  # nop
    },
    {
        "name": "cobalt_vpx_4k_preroll_8_frames",
        "va": 0x101129844,
        "expect": ("mov", "w13, #0x30"),
        "replacement": 0x5280010D,  # mov w13, #8
    },
    {
        "name": "cobalt_vpx_4k_sdr_loop_filter_opt_gate",
        "va": 0x101129E60,
        "expect": ("cbz", "w8, #0x101129e90"),
        "replacement": 0xD503201F,  # nop
    },
    {
        "name": "tvos_renderer_cap_frames_in_flight",
        "va": 0x101144290,
        "expect": ("add", "x20, x8, x20"),
        "replacement": 0x8B140914,  # add x20, x8, x20, lsl #2
    },
]

# The 8-bit VP9 renderer only builds its CVBuffer colour attachments when the
# 10-bit flag (+0x51) is set, so SDR buffers reach the compositor untagged. On an
# HDR-configured output the compositor then reads them in the display's space,
# which blows out highlights. Build the dictionary unconditionally, and skip only
# the HDR metadata block when the flag is clear: its two CFData values are zero for
# SDR and a zero ContentLightLevelInfo/MasteringDisplayColorVolume misleads the
# display. The colour defaults on the way in are all kCVImageBuffer*_ITU_R_709_2.
#
# The guard has to fit inside the block, so the two rev+lsr #16 pairs at
# 0x101128c18 and 0x101128c24 become rev16, which is identical for the
# zero-extended halfwords loaded here and frees the two slots the guard needs.
COBALT_COLOR_TAG_PATCHES = [
    {
        "name": "cobalt_vpx_tag_unconditional",
        "va": 0x101128A38,
        "expect": ("cbz", "w8, #0x101128d68"),
        "replacement": 0xD503201F,  # nop
    },
    {
        "name": "cobalt_vpx_tag_sdr_gate",
        "va": 0x101128C10,
        "expect": ("ldrh", "w8, [x20, #0x84]"),
        "replacement": 0x39414749,  # ldrb w9, [x26, #0x51]
    },
    {
        "name": "cobalt_vpx_tag_sdr_skip_metadata",
        "va": 0x101128C14,
        "expect": ("ldrh", "w9, [x20, #0x88]"),
        "replacement": 0x34000A89,  # cbz w9, 0x101128d64
    },
    {
        "name": "cobalt_vpx_tag_cll_load",
        "va": 0x101128C18,
        "expect": ("rev", "w8, w8"),
        "replacement": 0x79410A88,  # ldrh w8, [x20, #0x84]
    },
    {
        "name": "cobalt_vpx_tag_cll_swap",
        "va": 0x101128C1C,
        "expect": ("lsr", "w8, w8, #0x10"),
        "replacement": 0x5AC00508,  # rev16 w8, w8
    },
    {
        "name": "cobalt_vpx_tag_cll_store",
        "va": 0x101128C20,
        "expect": ("strh", "w8, [sp, #0x18]"),
        "replacement": 0x790033E8,  # unchanged
    },
    {
        "name": "cobalt_vpx_tag_cll_maxfall_load",
        "va": 0x101128C24,
        "expect": ("rev", "w8, w9"),
        "replacement": 0x79411288,  # ldrh w8, [x20, #0x88]
    },
    {
        "name": "cobalt_vpx_tag_cll_maxfall_swap",
        "va": 0x101128C28,
        "expect": ("lsr", "w8, w8, #0x10"),
        "replacement": 0x5AC00508,  # rev16 w8, w8
    },
    {
        "name": "cobalt_vpx_tag_cll_maxfall_store",
        "va": 0x101128C2C,
        "expect": ("strh", "w8, [sp, #0x1a]"),
        "replacement": 0x790037E8,  # unchanged
    },
]

# Late frames: the stock renderer bumps its dropped-frame counter (read back by
# GetDroppedFrames at 0x101145054) and then enqueues the frame anyway. Skip the
# enqueue so late frames are discarded, refund their budget slot (w23), and keep
# counting them so YouTube still sees the drops and can lower the quality. That
# takes five instructions in a three-instruction slot, so branch out to a stub.
COBALT_LATE_FRAME_TRAMPOLINES = [
    {
        "name": "tvos_renderer_drop_late_frames",
        "va": 0x101144C90,
        "expect": [
            ("ldr", "x8, [x19, #0x1e0]"),
            ("add", "x8, x8, #1"),
            ("str", "x8, [x19, #0x1e0]"),
        ],
        "extra": [0x110006F7],  # add w23, w23, #1
        "resume_va": 0x101144CAC,
    },
]

# Raise decoder and VP9 worker thread priorities. This requests higher
# scheduling priority; it does not set CPU affinity or guarantee P-core pinning.
COBALT_THREAD_PRIORITY_PATCHES = [
    {
        "name": "cobalt_vpx_decoder_thread_priority",
        "va": 0x101129488,
        "expect": ("mov", "w3, #2"),
        "replacement": 0x52800063,  # mov w3, #3
    },
    {
        "name": "cobalt_vpx_output_thread_priority",
        "va": 0x101129EA8,
        "expect": ("mov", "w3, #2"),
        "replacement": 0x52800063,  # mov w3, #3
    },
    {
        "name": "cobalt_vpx_worker_thread_priority_arg",
        "va": 0x101302AC4,
        "expect": ("ldr", "x0, [x0]"),
        "replacement": 0x52800060,  # mov w0, #3
    },
    {
        "name": "cobalt_vpx_worker_thread_set_priority",
        "va": 0x101302AC8,
        "expect": ("bl", "#0x101c3d264"),
        "replacement": 0x97F94A29,  # bl SbThreadSetPriority
    },
    {
        "name": "cobalt_vpx_worker_thread_resume_loop",
        "va": 0x101302ACC,
        "expect": ("ldr", "w8, [x19, #8]"),
        "replacement": 0x1400000A,  # b 0x101302af4
    },
]

MD = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = False


def encode_bl(src_pc, dst):
    # Encode a direct ARM64 BL from src_pc to dst.
    off = dst - src_pc
    if off % 4:
        raise ValueError("bl target must be 4-byte aligned")
    imm26 = off >> 2
    if not (-(1 << 25) <= imm26 < (1 << 25)):
        raise ValueError("bl target out of range")
    return 0x94000000 | (imm26 & 0x03FFFFFF)


def encode_b(src_pc, dst):
    # Encode a direct ARM64 B from src_pc to dst.
    return encode_bl(src_pc, dst) & ~0x80000000


def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def disasm_one(code, va):
    ins = next(MD.disasm(code, va), None)
    if ins is None:
        raise ValueError("failed to disassemble instruction")
    return ins


def asm_lines(lines):
    # Assemble ARM64 source with Apple's assembler and return __text bytes only.
    asm_text = ".text\n.align 2\n" + "\n".join(lines) + "\n"
    with tempfile.TemporaryDirectory() as tmpdir:
        asm_path = Path(tmpdir) / "stub.s"
        obj_path = Path(tmpdir) / "stub.o"
        asm_path.write_text(asm_text)
        cmd = [
            "xcrun",
            "--sdk",
            "appletvos",
            "clang",
            "-c",
            "-target",
            "arm64-apple-tvos",
            "-x",
            "assembler",
            "-o",
            str(obj_path),
            str(asm_path),
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        obj = lief.parse(str(obj_path))
        text = obj.get_section("__text")
        if not text:
            raise ValueError("assembled object has no __text section")
        return bytes(text.content)


def mov64(reg, value):
    # Materialize a 64-bit immediate in a register.
    return [
        f"movz {reg}, #0x{value & 0xFFFF:x}",
        f"movk {reg}, #0x{(value >> 16) & 0xFFFF:x}, lsl #16",
        f"movk {reg}, #0x{(value >> 32) & 0xFFFF:x}, lsl #32",
        f"movk {reg}, #0x{(value >> 48) & 0xFFFF:x}, lsl #48",
    ]


def load_addr(reg, value, slide_reg="x19"):
    # Load link-time VA and add ASLR slide stored in slide_reg.
    return [*mov64(reg, value), f"add {reg}, {reg}, {slide_reg}"]


def save_regs(regs=SAVED_REGS, size=None):
    # Save caller-visible GP state we might clobber in hook logic.
    out = [f"sub sp, sp, #0x{size or len(regs) * 8:x}"]
    for i in range(0, len(regs) - 1, 2):
        out.append(f"stp x{regs[i]}, x{regs[i + 1]}, [sp, #0x{i * 8:x}]")
    if len(regs) % 2:
        out.append(f"str x{regs[-1]}, [sp, #0x{(len(regs) - 1) * 8:x}]")
    return out


def restore_regs(regs=SAVED_REGS, size=None):
    # Restore in reverse order of save_regs(), then release stub stack frame.
    out = []
    if len(regs) % 2:
        out.append(f"ldr x{regs[-1]}, [sp, #0x{(len(regs) - 1) * 8:x}]")
    for i in reversed(range(0, len(regs) - 1, 2)):
        out.append(f"ldp x{regs[i]}, x{regs[i + 1]}, [sp, #0x{i * 8:x}]")
    out.append(f"add sp, sp, #0x{size or len(regs) * 8:x}")
    return out


def load_payload(path=None):
    # Payload is source-of-truth JS kept in a dedicated file (or a minified build of it).
    # Ignore full-line // comments so notes can live in inject.js without
    # being embedded into the runtime payload.
    if path is None:
        minified = Path(__file__).parent / "build" / "inject.min.js"
        path = minified if minified.exists() else Path(__file__).with_name("inject.js")
    text = Path(path).read_text(encoding="ascii")
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("//")]
    cleaned = "\n".join(lines).strip()
    if not cleaned:
        raise ValueError("inject.js is empty")
    return cleaned.encode("ascii")


def parse_macho_info(data):
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir) / "input.macho"
        tmp_path.write_bytes(data)
        binary = lief.parse(str(tmp_path))

    # We patch instructions in __text and store new data/stubs in header padding
    # inside __TEXT (between Mach-O load commands and __text start).
    text = binary.get_section("__text")
    stubs = binary.get_section("__stubs")
    text_seg = next((s for s in binary.segments if s.name == "__TEXT"), None)
    dysym = next((c for c in binary.commands if type(c).__name__ == "DynamicSymbolCommand"), None)
    if not text or not stubs or not text_seg or not dysym:
        raise ValueError("required Mach-O structures missing (__TEXT/__text/__stubs/dysymtab)")

    header_end = 32 + binary.header.sizeof_cmds
    return {
        "text_va": text.virtual_address,
        "text_off": text.offset,
        "text_size": text.size,
        "text_seg_va": text_seg.virtual_address,
        "text_seg_off": text_seg.file_offset,
        "header_end": header_end,
        "stubs": stubs,
        "dysym": dysym,
        "data_region": find_data_region(data, binary, text_seg, header_end, text.offset),
    }


def va_to_off(info, va):
    # Convert __text virtual address to file offset with bounds check.
    off = info["text_off"] + (va - info["text_va"])
    if off < info["text_off"] or off + 4 > info["text_off"] + info["text_size"]:
        raise ValueError(f"VA out of __text bounds: {hex(va)}")
    return off


def is_prologue_insn(ins):
    # Heuristic for common ARM64 function-prologue instructions.
    m, o = ins.mnemonic, ins.op_str
    if m in {"pacibsp", "bti", "nop", "hint"}:
        return True
    if m == "sub" and o.startswith("sp, sp, #"):
        return True
    if m == "stp" and "[sp" in o:
        return True
    if m == "add" and o.startswith("x29, sp, #"):
        return True
    if m == "mov" and o == "x29, sp":
        return True
    return False


def resolve_patch_site(data, info, entry_va, max_scan=24):
    # Starting at function entry, skip prologue and return first body instruction.
    entry_off = va_to_off(info, entry_va)
    first = disasm_one(data[entry_off:entry_off + 4], entry_va)
    if not is_prologue_insn(first):
        raise ValueError(f"entry {hex(entry_va)} is not a prologue start ({first.mnemonic} {first.op_str})")

    for i in range(1, max_scan + 1):
        site_va = entry_va + i * 4
        site_off = va_to_off(info, site_va)
        ins = disasm_one(data[site_off:site_off + 4], site_va)
        if not is_prologue_insn(ins):
            return site_va, site_off, read_u32(data, site_off), ins

    raise ValueError(f"failed to find first non-prologue instruction after {hex(entry_va)}")


def resolve_stub_va(info, symbol_name):
    # Resolve imported symbol trampoline VA from __stubs + indirect symbols.
    stubs = info["stubs"]
    dysym = info["dysym"]
    stub_size = stubs.reserved2
    if stub_size == 0:
        raise ValueError("__stubs has zero stub size")

    for i in range(stubs.size // stub_size):
        sym = dysym.indirect_symbols[stubs.reserved1 + i]
        if getattr(sym, "name", None) == symbol_name:
            return stubs.virtual_address + i * stub_size
    raise ValueError(f"stub not found for symbol {symbol_name}")


class Allocator:
    # Tiny bump allocator for header padding region.
    def __init__(self, start, end):
        self.cursor = start
        self.end = end

    def alloc(self, size, align=1):
        self.cursor = (self.cursor + align - 1) & ~(align - 1)
        off = self.cursor
        self.cursor += size
        if self.cursor > self.end:
            raise ValueError(f"patch region out of space (need {size} at {hex(off)}, end {hex(self.end)})")
        return off


def emit_log(addrs, key, include_ra, enabled):
    # Optional printf logging path, compiled out of stubs by default.
    if not enabled:
        return []
    lines = [*load_addr("x0", addrs[key])]
    if include_ra:
        lines.append("mov x1, x30")
    lines += [*load_addr("x16", addrs["printf"]), "blr x16"]
    return lines


def build_stub(kind, stub_va, addrs, orig_ins, enable_printf_logs):
    # Build one hook stub:
    # 1) save regs
    # 2) compute ASLR slide
    # 3) run hook logic
    # 4) restore regs + replay displaced instruction + ret
    label = f"stub_{kind}"
    stub_page = stub_va & ~0xFFF
    frame_regs = FRAME_REGS if kind == "frame_copy" else SAVED_REGS
    frame_size = FRAME_SAVE_SIZE if kind == "frame_copy" else (len(frame_regs) * 8 + 0xF) & ~0xF

    # Stub entry label + common prologue (alloc frame + spill GP state).
    lines = [f"{label}:", *save_regs(frame_regs, frame_size)]
    lines += [
        # Runtime page of this label (ADR resolves with current ASLR slide).
        f"adr x17, {label}",
        # Keep just the page address for slide math.
        "and x17, x17, #0xfffffffffffff000",
        # Link-time page where this stub was placed in the file.
        *mov64("x16", stub_page),
        # slide = runtime_page - linktime_page
        "sub x17, x17, x16",
        # Keep slide in a callee-saved register used by load_addr().
        "mov x19, x17",
    ]

    if kind == "html":
        # HTMLScriptElement::Execute:
        # - x1 (saved at [sp+0x08]) is std::string* content
        # - inject only if content contains "yttv"
        lines += [
            *emit_log(addrs, "log_html_entry", include_ra=True, enabled=enable_printf_logs),
            "ldr x0, [sp, #0x08]",
            *load_addr("x1", addrs["yttv"]),
            "mov x2, #0",
            *mov64("x3", addrs["yttv_len"]),
            *load_addr("x16", addrs["find"]),
            "blr x16",
            "cmn x0, #1",
            "b.eq html_skip",
            "ldr x0, [sp, #0x08]",
            "mov x1, #0",
            *load_addr("x2", addrs["inject"]),
            *mov64("x3", addrs["inject_len"]),
            *load_addr("x16", addrs["insert"]),
            "blr x16",
            *emit_log(addrs, "log_html_inject", include_ra=False, enabled=enable_printf_logs),
            "html_skip:",
        ]
    elif kind == "csp":
        # DirectiveList::AddDirective:
        # - x2 (saved at [sp+0x10]) is std::string* directive value
        # - always prepend CSP whitelist domains
        lines += [
            *emit_log(addrs, "log_csp_entry", include_ra=True, enabled=enable_printf_logs),
            "ldr x0, [sp, #0x10]",
            "mov x1, #0",
            *load_addr("x2", addrs["csp"]),
            *mov64("x3", addrs["csp_len"]),
            *load_addr("x16", addrs["insert"]),
            "blr x16",
            *emit_log(addrs, "log_csp_inject", include_ra=False, enabled=enable_printf_logs),
        ]
    elif kind == "frame_copy":
        # Renderer frame copy. save_regs() placed the caller frame 0x220 higher,
        # so caller [sp+0x10] is [sp+0x230] here. Saved x8 (descriptor) is at
        # 0x18, caller x19 (renderer) at 0x38.
        lines += [
            "ldr x0, [sp, #0x230]",
            "mov w1, #0",
            *load_addr("x16", addrs["bytes_per_row"]),
            "blr x16",
            "mov w21, w0",
            "movn x0, #1",
            *load_addr("x1", addrs["pixel_format_symbol"]),
            *load_addr("x16", addrs["dlsym"]),
            "blr x16",
            "mov w22, #0",
            "cbz x0, frame_copy_record",
            "mov x16, x0",
            "ldr x0, [sp, #0x230]",
            "blr x16",
            "mov w22, w0",
            "frame_copy_record:",
            # One fixed 0x40-byte record per frame: magic, the source plane, a
            # 16-byte luma sample at the centre of the frame, the destination
            # stride and format, the decoder's range field, the 10-bit flag.
            "add x25, sp, #0x80",
            "mov x1, #0x5455",
            "movk x1, #0x4d55, lsl #16",
            "movk x1, #0x0001, lsl #32",
            "str x1, [x25]",
            "ldr x1, [sp, #0x18]",
            "cbz x1, frame_copy_after_log",
            "ldr x2, [x1, #0x38]",
            "str x2, [x25, #8]",
            "ldr w3, [x1, #0x24]",
            "ldr w4, [x1, #0x20]",
            # The original skips the copy for an empty frame, so the sample
            # read must too.
            "cbz x2, frame_copy_after_log",
            "cbz w3, frame_copy_after_log",
            "cbz w4, frame_copy_after_log",
            "ldrsw x5, [x1, #0x58]",
            "lsr w3, w3, #1",
            # Saved x20 is the copy-path code; 0x102 is the 8-bit path, and
            # every other code takes the 10-bit path, two bytes per sample.
            "ldr w6, [sp, #0x40]",
            "cmp w6, #0x102",
            "and w6, w4, #0xfffffffe",
            "lsr w4, w4, #1",
            "csel w4, w4, w6, eq",
            "madd x2, x3, x5, x2",
            "add x2, x2, x4",
            "ldr x3, [x2]",
            "str x3, [x25, #0x10]",
            "ldr x3, [x2, #8]",
            "str x3, [x25, #0x18]",
            "mov w3, w21",
            "str x3, [x25, #0x20]",
            "mov w3, w22",
            "str x3, [x25, #0x28]",
            "ldr w3, [x1, #0x10]",
            "str x3, [x25, #0x30]",
            "ldr x1, [sp, #0x38]",
            "cbz x1, frame_copy_after_log",
            "ldrb w3, [x1, #0x51]",
            "str x3, [x25, #0x38]",
            # <home>/Documents, falling back to <home>/Library/Caches: the
            # sandbox refuses Documents writes.
            "movn x0, #1",
            *load_addr("x1", addrs["home_dir_symbol"]),
            *load_addr("x16", addrs["dlsym"]),
            "blr x16",
            "cbz x0, frame_copy_after_log",
            "mov x16, x0",
            "blr x16",
            "cbz x0, frame_copy_after_log",
            "mov x24, x0",
            "movn x0, #1",
            *load_addr("x1", addrs["sel_register_name_symbol"]),
            *load_addr("x16", addrs["dlsym"]),
            "blr x16",
            "cbz x0, frame_copy_after_log",
            "mov x16, x0",
            *load_addr("x0", addrs["utf8_selector"]),
            "blr x16",
            "mov x1, x0",
            "mov x0, x24",
            *load_addr("x16", addrs["objc_msg_send"]),
            "blr x16",
            "cbz x0, frame_copy_after_log",
            # The path buffer runs from sp+0xd0 to the end of the frame. This
            # binary imports strlcpy but not strlcat, so append with strlcpy at
            # the end of the home path.
            "mov x1, x0",
            "add x0, sp, #0xd0",
            "mov x2, #0x150",
            *load_addr("x16", addrs["strlcpy"]),
            "blr x16",
            "cmp x0, #0x150",
            "b.hs frame_copy_after_log",
            "mov x23, x0",
            "add x0, sp, #0xd0",
            "add x0, x0, x23",
            *load_addr("x1", addrs["log_path"]),
            "mov x2, #0x150",
            "sub x2, x2, x23",
            *load_addr("x16", addrs["strlcpy"]),
            "blr x16",
            "add x0, x0, x23",
            "cmp x0, #0x150",
            "b.hs frame_copy_after_log",
            "add x0, sp, #0xd0",
            *load_addr("x1", addrs["append_mode"]),
            *load_addr("x16", addrs["fopen"]),
            "blr x16",
            "cbnz x0, frame_copy_have_file",
            "add x0, sp, #0xd0",
            "add x0, x0, x23",
            *load_addr("x1", addrs["log_path2"]),
            "mov x2, #0x150",
            "sub x2, x2, x23",
            *load_addr("x16", addrs["strlcpy"]),
            "blr x16",
            "add x0, x0, x23",
            "cmp x0, #0x150",
            "b.hs frame_copy_after_log",
            "add x0, sp, #0xd0",
            *load_addr("x1", addrs["append_mode"]),
            *load_addr("x16", addrs["fopen"]),
            "blr x16",
            "cbz x0, frame_copy_after_log",
            "frame_copy_have_file:",
            "mov x24, x0",
            "add x0, sp, #0x80",
            "mov w1, #0x40",
            "mov w2, #1",
            "mov x3, x24",
            *load_addr("x16", addrs["fwrite"]),
            "blr x16",
            "mov x0, x24",
            *load_addr("x16", addrs["fclose"]),
            "blr x16",
            "frame_copy_after_log:",
        ]
    elif kind == "media_support":
        # Re-signed builds can reject VP9 Profile 2 before YouTube exposes HDR
        # formats. Report probable support only for Profile 2 MIME strings when
        # AVPlayer confirms HDR playback eligibility. Missing APIs, SDR-only
        # hardware, and every other codec fall through to Cobalt unchanged.
        lines += [
            "ldr x0, [sp]",
            "cbz x0, media_profile2_continue",
            *load_addr("x1", addrs["vp9_profile2_full"]),
            *load_addr("x16", addrs["strstr"]),
            "blr x16",
            "cbnz x0, media_profile2_check_hdr",
            "ldr x0, [sp]",
            *load_addr("x1", addrs["vp9_profile2_short"]),
            *load_addr("x16", addrs["strstr"]),
            "blr x16",
            "cbz x0, media_profile2_continue",
            "media_profile2_check_hdr:",
            *load_addr("x0", addrs["avplayer_class_name"]),
            *load_addr("x16", addrs["objc_get_class"]),
            "blr x16",
            "cbz x0, media_profile2_continue",
            "mov x20, x0",
            "movn x0, #1",
            *load_addr("x1", addrs["sel_register_name_symbol"]),
            *load_addr("x16", addrs["dlsym"]),
            "blr x16",
            "cbz x0, media_profile2_continue",
            "mov x16, x0",
            *load_addr("x0", addrs["hdr_eligible_selector"]),
            "blr x16",
            "cbz x0, media_profile2_continue",
            "mov x21, x0",
            "movn x0, #1",
            *load_addr("x1", addrs["class_get_method_symbol"]),
            *load_addr("x16", addrs["dlsym"]),
            "blr x16",
            "cbz x0, media_profile2_continue",
            "mov x16, x0",
            "mov x0, x20",
            "mov x1, x21",
            "blr x16",
            "cbz x0, media_profile2_continue",
            "mov x0, x20",
            "mov x1, x21",
            *load_addr("x16", addrs["objc_msg_send"]),
            "blr x16",
            "tbz w0, #0, media_profile2_continue",
            "media_profile2_supported:",
            *restore_regs(frame_regs, frame_size),
            "mov w0, #2",
            "ldp x29, x30, [sp, #0x130]",
            "ldp x20, x19, [sp, #0x120]",
            "ldp x22, x21, [sp, #0x110]",
            "ldp x28, x27, [sp, #0x100]",
            "add sp, sp, #0x140",
            "ret",
            "media_profile2_continue:",
        ]
    else:
        raise ValueError(f"unknown stub kind: {kind}")

    lines += [*restore_regs(frame_regs, frame_size), f".word 0x{orig_ins:08x}", "ret"]
    return asm_lines(lines)


def find_data_region(data, binary, text_seg, lo, text_off):
    # Largest unused zero gap inside __TEXT, for blobs that outgrow the header
    # padding. Gap bytes are inside the executable segment but belong to no
    # section, so nothing references them. Start at __text: the padding before it
    # is already taken by the stubs, so it must not be a candidate.
    lo = max(lo, text_off)
    hi = text_seg.file_offset + text_seg.file_size
    used = sorted((s.offset, s.offset + s.size) for s in binary.sections if s.size and s.offset >= lo)
    best, cursor = None, lo
    for start, stop in used:
        if start - cursor >= 0x1000 and not any(data[cursor:start]):
            if best is None or start - cursor > best[1] - best[0]:
                best = (cursor, start)
        cursor = max(cursor, stop)
    if best is None:
        return None
    return min(best[0], hi), min(best[1], hi)


def patch_binary(data, enable_printf_logs=False, inject_path=None, diag_frames=False):
    info = parse_macho_info(data)
    start, end = info["header_end"], info["text_off"]
    if start >= end:
        raise ValueError("no __TEXT padding available for stubs")
    alloc = Allocator(start, end)
    # Diagnostic builds embed a far larger blob set, so park the data in a free
    # __TEXT gap and keep the padding for code.
    dalloc = Allocator(*info["data_region"]) if diag_frames and info["data_region"] else None

    def put(blob, align=4):
        off = (dalloc or alloc).alloc(len(blob), align)
        data[off:off + len(blob)] = blob
        return off

    js = load_payload(inject_path)
    # Embed runtime strings and payload in __TEXT header padding.
    offs = {
        "yttv": put(YTTV_NEEDLE + b"\0"),
        "inject": put(js + b"\0"),
        "csp": put(CSP_PREFIX + b"\0"),
        "vp9_profile2_full": put(b"vp09.02\0"),
        "vp9_profile2_short": put(b"vp9.2\0"),
        "avplayer_class_name": put(b"AVPlayer\0"),
        "sel_register_name_symbol": put(b"sel_registerName\0"),
        "class_get_method_symbol": put(b"class_getClassMethod\0"),
        "hdr_eligible_selector": put(b"eligibleForHDRPlayback\0"),
    }
    if enable_printf_logs:
        offs |= {
            "log_html_entry": put(LOG_HTML_ENTRY + b"\0"),
            "log_html_inject": put(LOG_HTML_INJECT + b"\0"),
            "log_csp_entry": put(LOG_CSP_ENTRY + b"\0"),
            "log_csp_inject": put(LOG_CSP_INJECT + b"\0"),
        }
    if diag_frames:
        offs |= {
            "log_path": put(b"/Documents/mutube_frames.bin\0"),
            "home_dir_symbol": put(b"NSHomeDirectory\0"),
            "log_path2": put(b"/Library/Caches/mutube_frames.bin\0"),
            "utf8_selector": put(b"UTF8String\0"),
            "append_mode": put(b"a\0"),
            "pixel_format_symbol": put(b"CVPixelBufferGetPixelFormatType\0"),
        }
    alloc.alloc(0, 16)

    f2v = lambda off: info["text_seg_va"] + (off - info["text_seg_off"])
    addrs = {k: f2v(v) for k, v in offs.items()}
    addrs |= {
        "yttv_len": len(YTTV_NEEDLE),
        "inject_len": len(js),
        "csp_len": len(CSP_PREFIX),
        "find": resolve_stub_va(info, "__ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEPKcmm"),
        "insert": resolve_stub_va(info, "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKcm"),
        "strstr": resolve_stub_va(info, "_strstr"),
        "objc_get_class": resolve_stub_va(info, "_objc_getClass"),
        "objc_msg_send": resolve_stub_va(info, "_objc_msgSend"),
        "dlsym": resolve_stub_va(info, "_dlsym"),
    }
    if enable_printf_logs:
        addrs["printf"] = resolve_stub_va(info, "_printf")
    if diag_frames:
        addrs["bytes_per_row"] = resolve_stub_va(info, "_CVPixelBufferGetBytesPerRowOfPlane")
        addrs["fopen"] = resolve_stub_va(info, "_fopen")
        addrs["fclose"] = resolve_stub_va(info, "_fclose")
        addrs["fwrite"] = resolve_stub_va(info, "_fwrite")
        addrs["strlcpy"] = resolve_stub_va(info, "_strlcpy")

    # Resolve final patch sites dynamically from function entry + prologue scan.
    resolved = []
    for p in PATCHES + COBALT_HOOKS + (COBALT_DIAG_PATCHES if diag_frames else []):
        if p.get("exact"):
            site_va = p["entry_va"]
            site_off = va_to_off(info, site_va)
            orig_ins = read_u32(data, site_off)
            insn = disasm_one(data[site_off:site_off + 4], site_va)
        else:
            site_va, site_off, orig_ins, insn = resolve_patch_site(data, info, p["entry_va"])
        if (insn.mnemonic, insn.op_str) != p["expect"]:
            raise ValueError(
                f"{p['name']}: at {hex(site_va)} expected {p['expect'][0]} {p['expect'][1]}, got {insn.mnemonic} {insn.op_str}"
            )
        resolved.append({**p, "site_va": site_va, "site_off": site_off, "orig": orig_ins})

    # Two-pass stub build:
    # pass 1 determines byte lengths; pass 2 assembles with final VAs.
    stubs = {}
    for p in resolved:
        stubs[p["name"]] = {"len": len(build_stub(p["kind"], 0, addrs, p["orig"], enable_printf_logs))}
    for p in resolved:
        off = alloc.alloc(stubs[p["name"]]["len"], 4)
        stubs[p["name"]] |= {"off": off, "va": f2v(off)}
    for p in resolved:
        stubs[p["name"]]["blob"] = build_stub(p["kind"], stubs[p["name"]]["va"], addrs, p["orig"], enable_printf_logs)

    out = []
    for p in resolved:
        s = stubs[p["name"]]
        data[s["off"]:s["off"] + len(s["blob"])] = s["blob"]
        # Overwrite target instruction with BL to stub.
        data[p["site_off"]:p["site_off"] + 4] = struct.pack("<I", encode_bl(p["site_va"], s["va"]))
        out.append(
            {
                "name": p["name"],
                "entry_va": p["entry_va"],
                "patch_site_va": p["site_va"],
                "stub_va": s["va"],
                "stub_len": len(s["blob"]),
            }
        )

    for t in COBALT_LATE_FRAME_TRAMPOLINES:
        site_off = va_to_off(info, t["va"])
        orig = []
        for i, expect in enumerate(t["expect"]):
            insn = disasm_one(data[site_off + 4 * i:site_off + 4 * i + 4], t["va"] + 4 * i)
            if (insn.mnemonic, insn.op_str) != expect:
                raise ValueError(
                    f"{t['name']}: at {hex(t['va'] + 4 * i)} expected {expect[0]} {expect[1]}, "
                    f"got {insn.mnemonic} {insn.op_str}"
                )
            orig.append(read_u32(data, site_off + 4 * i))
        words = orig + t["extra"]
        stub_off = alloc.alloc(4 * (len(words) + 1), 4)
        stub_va = f2v(stub_off)
        words.append(encode_b(stub_va + 4 * len(words), t["resume_va"]))
        data[stub_off:stub_off + 4 * len(words)] = struct.pack(f"<{len(words)}I", *words)
        data[site_off:site_off + 4] = struct.pack("<I", encode_b(t["va"], stub_va))
        out.append(
            {
                "name": t["name"],
                "entry_va": t["va"],
                "patch_site_va": t["va"],
                "stub_va": stub_va,
                "stub_len": 4 * len(words),
            }
        )

    for patch in COBALT_HDR_PATCHES + COBALT_PLAYBACK_PATCHES + COBALT_COLOR_TAG_PATCHES + COBALT_THREAD_PRIORITY_PATCHES:
        patch_off = va_to_off(info, patch["va"])
        insn = disasm_one(data[patch_off:patch_off + 4], patch["va"])
        if (insn.mnemonic, insn.op_str) != patch["expect"]:
            raise ValueError(
                f"{patch['name']}: at {hex(patch['va'])} expected "
                f"{patch['expect'][0]} {patch['expect'][1]}, got "
                f"{insn.mnemonic} {insn.op_str}"
            )
        data[patch_off:patch_off + 4] = struct.pack("<I", patch["replacement"])
        out.append(
            {
                "name": patch["name"],
                "entry_va": patch["va"],
                "patch_site_va": patch["va"],
                "stub_va": 0,
                "stub_len": 0,
            }
        )

    return out


def strip_supported_devices(raw):
    """Drop UISupportedDevices from Info.plist so the IPA installs on any tvOS device
    (the stock app only lists the Apple TV 4K 1st/2nd gen, which blocks Apple TV HD).
    Returns (new_bytes, removed_value_or_None). Everything else in the plist is kept."""
    before = plistlib.loads(raw)
    if "UISupportedDevices" not in before:
        return raw, None
    removed = before["UISupportedDevices"]
    if raw.lstrip().startswith(b"<?xml"):
        # Textual edit keeps the rest of the XML byte-identical.
        out = re.sub(
            rb"[ \t]*<key>UISupportedDevices</key>\s*<array>.*?</array>[ \t]*\r?\n?",
            b"",
            raw,
            count=1,
            flags=re.S,
        )
    else:
        stripped = dict(before)
        stripped.pop("UISupportedDevices")
        out = plistlib.dumps(stripped, fmt=plistlib.FMT_BINARY)
    expected = dict(before)
    expected.pop("UISupportedDevices")
    if plistlib.loads(out) != expected:
        raise ValueError("Info.plist edit changed more than UISupportedDevices")
    return out, removed


def patch_ipa(in_path, out_path, enable_printf_logs=False, keep_supported_devices=False, inject_path=None, diag_frames=False):
    # Replace the app binary (and strip UISupportedDevices from Info.plist); preserve all other entries.
    with zipfile.ZipFile(in_path, "r") as zin:
        infos = zin.infolist()
        bin_info = next((i for i in infos if i.filename.endswith("/YouTubeUnstable")), None)
        if not bin_info:
            raise ValueError("YouTubeUnstable binary not found in IPA")
        plist_info = next((i for i in infos if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", i.filename)), None)

        binary = bytearray(zin.read(bin_info.filename))
        meta = patch_binary(binary, enable_printf_logs=enable_printf_logs, inject_path=inject_path, diag_frames=diag_frames)

        new_plist = None
        if plist_info and not keep_supported_devices:
            new_plist, removed = strip_supported_devices(zin.read(plist_info.filename))
            if removed is not None:
                print("Info.plist: removed UISupportedDevices", removed)

        with zipfile.ZipFile(out_path, "w") as zout:
            for info in infos:
                if info.filename == bin_info.filename:
                    payload = binary
                elif new_plist is not None and info.filename == plist_info.filename:
                    payload = new_plist
                else:
                    payload = zin.read(info.filename)
                zout.writestr(info, payload)
    return meta


def main():
    ap = argparse.ArgumentParser(description="MuTube patcher (YouTube 4.54.01)")
    ap.add_argument("--in", dest="inp", required=True, help="input IPA path")
    ap.add_argument("--out", dest="outp", required=True, help="output IPA path")
    ap.add_argument("--inject", dest="inject", help="JS payload to embed (default: build/inject.min.js if built, else inject.js)")
    ap.add_argument(
        "--enable-printf-logs",
        action="store_true",
        help="enable MUTUBE_* printf logs in hook stubs (disabled by default)",
    )
    ap.add_argument(
        "--keep-supported-devices",
        action="store_true",
        help="leave UISupportedDevices in Info.plist (by default it is removed so Apple TV HD can install)",
    )
    ap.add_argument(
        "--diag-frames",
        action="store_true",
        help="write a per-frame decode record to the app container",
    )
    args = ap.parse_args()

    meta = patch_ipa(
        args.inp,
        args.outp,
        enable_printf_logs=args.enable_printf_logs,
        keep_supported_devices=args.keep_supported_devices,
        inject_path=args.inject,
        diag_frames=args.diag_frames,
    )
    print("Patched IPA written to:", args.outp)
    for entry in meta:
        print("Patch:", entry["name"])
        print("  Entry VA:", hex(entry["entry_va"]))
        print("  Patch site VA:", hex(entry["patch_site_va"]))
        print("  Stub VA:", hex(entry["stub_va"]), "len", entry["stub_len"])


if __name__ == "__main__":
    main()
