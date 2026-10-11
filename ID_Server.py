import socket, threading, traceback, json, re, os
import ida_kernwin, ida_funcs, ida_name, ida_bytes, ida_idaapi, ida_segment, ida_xref
import ida_typeinf, ida_nalt, idautils, idc

try:
    import ida_struct
except ImportError:
    ida_struct = None

try:
    import ida_hexrays
    _HAS_HR = ida_hexrays.init_hexrays_plugin()
except Exception:
    _HAS_HR = False

BASE_PORT = 5073
PORT = None
_running = True
_srv = None
MAX_RESULTS = 200
SCAN_CAP = 4000

_DUMMY = ("sub_", "loc_", "locret_", "byte_", "word_", "dword_", "qword_",
          "unk_", "off_", "asc_", "stru_", "flt_", "dbl_", "jpt_", "def_",
          "nullsub_", "j_", "unknown_", "algn_", "xmmword_")

def _ok(data):
    data["ok"] = True
    return data

def _err(msg, **extra):
    out = {"ok": False, "error": str(msg)}
    out.update(extra)
    return out

def _demangle(name):
    try:
        d = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
        return d if d else name
    except Exception:
        return name

def _addr_of(s):
    s = s.strip()
    if not s:
        raise ValueError("Empty address")
    if s.upper() == "CURRENT":
        ea = ida_kernwin.get_screen_ea()
        if ea == ida_idaapi.BADADDR:
            raise ValueError("No current address selected")
        return ea
    return int(s, 16)

def _get_func(ea):
    f = ida_funcs.get_func(ea)
    if f is None:
        f = ida_funcs.get_func(ea)
    return f

def _decompile_func(f):
    if not _HAS_HR:
        return None
    try:
        cf = ida_hexrays.decompile(f.start_ea)
        return str(cf) if cf else None
    except Exception:
        return None

def _function_info(addr_text):
    try:
        ea = _addr_of(addr_text)
    except Exception as e:
        return _err(str(e), requested=addr_text)
    f = _get_func(ea)
    if f is None:
        return _err("No function found", requested=addr_text, resolved="%08X" % ea)

    code = _decompile_func(f)
    asm = []
    cur = f.start_ea
    while cur < f.end_ea and len(asm) < 500:
        asm.append("%08X  %s" % (cur, idc.generate_disasm_line(cur, 0)))
        nxt = idc.next_head(cur, f.end_ea)
        if nxt <= cur or nxt == ida_idaapi.BADADDR:
            break
        cur = nxt

    return _ok({
        "address": "%08X" % f.start_ea,
        "function_entry": "%08X" % f.start_ea,
        "function_name": ida_funcs.get_func_name(f.start_ea) or "",
        "size": f.end_ea - f.start_ea,
        "code": code,
        "asm": asm
    })

def _refs_to(addr_text):
    try:
        ea = _addr_of(addr_text)
    except Exception as e:
        return _err(str(e), requested=addr_text)
    refs = []
    total = 0
    capped = False
    for x in idautils.XrefsTo(ea):
        total += 1
        if len(refs) < MAX_RESULTS:
            f = _get_func(x.frm)
            refs.append({
                "from": "%08X" % x.frm,
                "to": "%08X" % ea,
                "type": str(x.type),
                "function": ida_funcs.get_func_name(f.start_ea) if f else None,
                "function_entry": ("%08X" % f.start_ea) if f else None
            })
        if total >= SCAN_CAP:
            capped = True
            break
    return _ok({"address": "%08X" % ea, "refs": refs, "count": total, "capped": capped})

def _refs_from(addr_text):
    try:
        ea = _addr_of(addr_text)
    except Exception as e:
        return _err(str(e), requested=addr_text)
    refs = []
    for x in idautils.XrefsFrom(ea):
        f = _get_func(x.to)
        refs.append({
            "from": "%08X" % ea,
            "to": "%08X" % x.to,
            "type": str(x.type),
            "function": ida_funcs.get_func_name(f.start_ea) if f else None,
            "function_entry": ("%08X" % f.start_ea) if f else None
        })
    return _ok({"address": "%08X" % ea, "refs": refs[:MAX_RESULTS], "count": len(refs)})

def _read_c_string(ea, max_len=512):
    try:
        b = ida_bytes.get_bytes(ea, max_len)
        if not b:
            return None
        null_idx = b.find(b"\x00")
        if null_idx != -1:
            b = b[:null_idx]
        if len(b) < 1 or any(c < 0x20 and c not in (9, 10, 13) or c > 0x7e for c in b):
            return None
        return b.decode("ascii", "replace")
    except Exception:
        return None

def _read_utf16_string(ea, max_chars=512):
    try:
        b = ida_bytes.get_bytes(ea, max_chars * 2)
        if not b:
            return None
        chars = []
        for i in range(0, len(b) - 1, 2):
            val = b[i] | (b[i+1] << 8)
            if val == 0:
                break
            if val < 0x20 and val not in (9, 10, 13) or val > 0x7e:
                return None
            chars.append(chr(val))
        if not chars:
            return None
        return "".join(chars)
    except Exception:
        return None

def _classify(v):
    if v == 0 or v == 0xFFFFFFFF:
        return (None, None)
    f = _get_func(v)
    if f is not None:
        off = v - f.start_ea
        fn = ida_funcs.get_func_name(f.start_ea) or ("sub_%08X" % f.start_ea)
        return ("func", fn if off == 0 else "%s+0x%x" % (fn, off))
    s = _read_c_string(v, 64)
    if s and len(s) >= 3:
        return ("str", s)
    ws = _read_utf16_string(v, 64)
    if ws and len(ws) >= 3:
        return ("wstr", ws)
    seg = ida_segment.getseg(v)
    if seg is not None:
        return ("ptr", None)
    return (None, None)

def _find_bytes_ida(pattern_bytes, max_hits=MAX_RESULTS):
    results = []
    seg = ida_segment.get_first_seg()
    while seg:
        ea = seg.start_ea
        end_ea = seg.end_ea
        while ea < end_ea and len(results) < max_hits:
            try:
                hit = ida_bytes.bin_search(ea, end_ea, pattern_bytes, None, len(pattern_bytes), ida_bytes.BIN_SEARCH_FORWARD)
            except Exception:
                try:
                    hit = ida_bytes.bin_search(ea, end_ea, pattern_bytes, None, ida_bytes.BIN_SEARCH_FORWARD, ida_bytes.BIN_SEARCH_NOBREAK)
                except Exception:
                    break
            if hit == ida_idaapi.BADADDR:
                break
            f = _get_func(hit)
            results.append({
                "address": "%08X" % hit,
                "function": ida_funcs.get_func_name(f.start_ea) if f else None,
                "function_entry": ("%08X" % f.start_ea) if f else None
            })
            ea = hit + 1
        seg = ida_segment.get_next_seg(seg.start_ea)
    return results

def _search_bytes(hex_text):
    clean = hex_text.replace(" ", "").replace("\\x", "").replace(",", "").replace("0x", "")
    if len(clean) % 2 != 0:
        return _err("Odd hex length")
    b = bytes.fromhex(clean)
    hits = _find_bytes_ida(b)
    return _ok({"pattern": hex_text, "results": hits})

def _search_ascii(text):
    b = text.encode("ascii", "replace")
    raw = _find_bytes_ida(b)
    out = []
    for hit in raw:
        ea = int(hit["address"], 16)
        value = _read_c_string(ea)
        refs = []
        for x in idautils.XrefsTo(ea):
            f = _get_func(x.frm)
            refs.append({
                "from": "%08X" % x.frm,
                "function": ida_funcs.get_func_name(f.start_ea) if f else None,
                "function_entry": ("%08X" % f.start_ea) if f else None
            })
            if len(refs) >= 50:
                break
        hit["string"] = value
        hit["refs"] = refs
        hit["ref_count"] = len(refs)
        out.append(hit)
    return _ok({"text": text, "encoding": "ascii", "results": out})

def _search_utf16(text):
    b = text.encode("utf-16le")
    raw = _find_bytes_ida(b)
    out = []
    for hit in raw:
        ea = int(hit["address"], 16)
        value = _read_utf16_string(ea)
        refs = []
        for x in idautils.XrefsTo(ea):
            f = _get_func(x.frm)
            refs.append({
                "from": "%08X" % x.frm,
                "function": ida_funcs.get_func_name(f.start_ea) if f else None,
                "function_entry": ("%08X" % f.start_ea) if f else None
            })
            if len(refs) >= 50:
                break
        hit["string"] = value
        hit["refs"] = refs
        hit["ref_count"] = len(refs)
        out.append(hit)
    return _ok({"text": text, "encoding": "utf16le", "results": out})

def _decompile_xrefs(addr_text):
    try:
        ea = _addr_of(addr_text)
    except Exception as e:
        return _err(str(e))
    funcs = {}
    for x in idautils.XrefsTo(ea):
        f = _get_func(x.frm)
        if f is not None:
            funcs["%08X" % f.start_ea] = f
    out = []
    for entry, f in list(funcs.items())[:50]:
        out.append({
            "function_entry": entry,
            "function_name": ida_funcs.get_func_name(f.start_ea) or "",
            "code": _decompile_func(f)
        })
    return _ok({"address": "%08X" % ea, "functions": out, "count": len(out)})

def _make_func(addr_text):
    try:
        ea = _addr_of(addr_text)
    except Exception as e:
        return _err(str(e))
    ida_funcs.add_func(ea)
    return _function_info("%08X" % ea)

def _validate_name(name):
    name = name.strip()
    if not name:
        raise ValueError("Empty name")
    if not re.match(r"^[A-Za-z_?@][A-Za-z0-9_?@$:]*$", name):
        raise ValueError("Bad name: %s" % name)
    return name

def _rename_symbol(cmd_text, kind="symbol"):
    parts = cmd_text.split(None, 1)
    if len(parts) != 2:
        return _err("Usage: RENAME_%s <addr> <new_name>" % kind.upper())
    try:
        ea = _addr_of(parts[0])
        new_name = _validate_name(parts[1])
    except Exception as e:
        return _err(str(e))
    old_name = ida_name.get_name(ea) or ""
    ok = ida_name.set_name(ea, new_name, ida_name.SN_NOWARN | ida_name.SN_FORCE)
    return _ok({
        "kind": kind,
        "address": "%08X" % ea,
        "old_name": old_name,
        "new_name": new_name if ok else old_name,
        "success": bool(ok)
    })

def _rename_local(cmd_text):
    parts = cmd_text.split()
    if len(parts) != 3:
        return _err("Usage: RENAME_LOCAL <func_addr> <old_name> <new_name>")
    if not _HAS_HR:
        return _err("Hex-Rays decompiler not available")
    try:
        ea = _addr_of(parts[0])
        old_name = parts[1].strip()
        new_name = _validate_name(parts[2])
    except Exception as e:
        return _err(str(e))
    f = _get_func(ea)
    if f is None:
        return _err("No function found", address="%08X" % ea)
    try:
        cf = ida_hexrays.decompile(f.start_ea)
        if not cf:
            return _err("Decompilation failed", address="%08X" % f.start_ea)
        lvars = cf.get_lvars()
        found = False
        for v in lvars:
            if v.name == old_name:
                cf.set_lvar_name(v, new_name)
                cf.save_user_lvar_settings()
                found = True
                break
        if not found:
            return _err("Local variable not found: %s" % old_name)
        return _ok({"kind": "local", "function": "%08X" % f.start_ea, "old_name": old_name, "new_name": new_name})
    except Exception as e:
        return _err("RENAME_LOCAL failed: " + str(e))

def _read_pointers(cmd_text):
    parts = cmd_text.split()
    try:
        ea = _addr_of(parts[0])
    except Exception as e:
        return _err(str(e))
    count = int(parts[1], 0) if len(parts) > 1 else 1
    out = []
    for i in range(count):
        cur = ea + i * 4
        v = ida_bytes.get_dword(cur)
        f = _get_func(v)
        out.append({
            "slot": i,
            "at": "%08X" % cur,
            "value": "%08X" % v,
            "function": ida_funcs.get_func_name(f.start_ea) if f else None
        })
    return _ok({"address": "%08X" % ea, "count": count, "pointers": out})

def _strings_near(addr_text, before=128, after=128):
    try:
        ea = _addr_of(addr_text)
    except Exception as e:
        return _err(str(e))
    start_ea = ea - before
    end_ea = ea + after
    found = []
    cur = start_ea
    while cur <= end_ea and len(found) < 100:
        s = _read_c_string(cur, 200)
        if s and len(s) >= 3:
            found.append({"address": "%08X" % cur, "type": "ascii", "value": s})
            cur += len(s)
        else:
            ws = _read_utf16_string(cur, 200)
            if ws and len(ws) >= 3:
                found.append({"address": "%08X" % cur, "type": "utf16le", "value": ws})
                cur += len(ws) * 2
            else:
                cur += 1
    return _ok({"around": "%08X" % ea, "strings": found})

def _refs_filtered(addr_text, want):
    try:
        ea = _addr_of(addr_text)
    except Exception as e:
        return _err(str(e))
    out = []
    total = 0
    capped = False
    for x in idautils.XrefsTo(ea):
        total += 1
        keep = False
        if want == "write":
            keep = (x.type in (ida_xref.dr_W, ida_xref.dr_O))
        elif want == "read":
            keep = (x.type == ida_xref.dr_R)
        elif want == "call":
            keep = (x.type in (ida_xref.fl_CF, ida_xref.fl_CN))
        else:
            keep = True
        if keep and len(out) < MAX_RESULTS:
            f = _get_func(x.frm)
            out.append({
                "from": "%08X" % x.frm,
                "type": str(x.type),
                "function": ida_funcs.get_func_name(f.start_ea) if f else None,
                "function_entry": ("%08X" % f.start_ea) if f else None
            })
        if total >= SCAN_CAP:
            capped = True
            break
    return _ok({"address": "%08X" % ea, "filter": want, "refs": out, "scanned": total, "capped": capped})

def _find_pointers_to(addr_text):
    try:
        ea = _addr_of(addr_text)
    except Exception as e:
        return _err(str(e))
    le_bytes = (ea & 0xFFFFFFFF).to_bytes(4, "little")
    hits = _find_bytes_ida(le_bytes)
    out = []
    for h in hits:
        out.append({"at": h["address"], "in_function": h["function"]})
    return _ok({"target": "%08X" % ea, "pointer_locations": out, "count": len(out)})

def _dump_struct(cmd_text):
    parts = cmd_text.split()
    try:
        ea = _addr_of(parts[0])
    except Exception as e:
        return _err(str(e))
    count = int(parts[1], 0) if len(parts) > 1 else 16
    out = []
    for i in range(count):
        cur = ea + i * 4
        v = ida_bytes.get_dword(cur)
        sv = v if v < 0x80000000 else v - 0x100000000
        entry = {"off": "+0x%x" % (i * 4), "at": "%08X" % cur, "hex": "%08X" % v, "int": sv}
        kind, detail = _classify(v)
        if kind:
            entry["kind"] = kind
        if detail:
            entry["detail"] = detail
        out.append(entry)
    return _ok({"address": "%08X" % ea, "fields": out})

def _vtable_context(addr_text):
    try:
        ea = _addr_of(addr_text)
    except Exception as e:
        return _err(str(e))
    le_bytes = (ea & 0xFFFFFFFF).to_bytes(4, "little")
    hits = _find_bytes_ida(le_bytes)
    out = []
    for h in hits:
        loc = int(h["address"], 16)
        slots = []
        for k in range(-3, 6):
            cur = loc + k * 4
            v = ida_bytes.get_dword(cur)
            kind, detail = _classify(v)
            slots.append({
                "slot_off": "%+d" % (k * 4),
                "at": "%08X" % cur,
                "val": "%08X" % v,
                "func": detail if kind == "func" else None,
                "is_target": (k == 0)
            })
        writers = []
        for x in idautils.XrefsTo(loc):
            f = _get_func(x.frm)
            writers.append({
                "from": "%08X" % x.frm,
                "function": ida_funcs.get_func_name(f.start_ea) if f else None
            })
            if len(writers) >= 20:
                break
        out.append({"vtable_hit": "%08X" % loc, "slots": slots, "refs_to_slot": writers})
    return _ok({"target": "%08X" % ea, "vtables": out, "count": len(out)})

def _vtable_dump(cmd_text):
    parts = cmd_text.split()
    try:
        ea = _addr_of(parts[0])
    except Exception as e:
        return _err(str(e))
    count = int(parts[1], 0) if len(parts) > 1 else 128
    out = []
    junk = 0
    for i in range(count):
        cur = ea + i * 4
        v = ida_bytes.get_dword(cur)
        if v == 0:
            break
        kind, detail = _classify(v)
        if kind != "func":
            junk += 1
            if junk > 3:
                break
        else:
            junk = 0
        out.append({
            "idx": i,
            "off": "0x%x" % (i * 4),
            "at": "%08X" % cur,
            "val": "%08X" % v,
            "func": detail if kind == "func" else None,
            "kind": kind
        })
    while out and out[-1]["kind"] != "func":
        out.pop()
    return _ok({"vtable": "%08X" % ea, "slots": out, "count": len(out)})

def _make_pointers(cmd_text):
    parts = cmd_text.split()
    try:
        ea = _addr_of(parts[0])
    except Exception as e:
        return _err(str(e))
    count = int(parts[1], 0) if len(parts) > 1 else 1
    made = []
    for i in range(count):
        cur = ea + i * 4
        ida_bytes.del_items(cur, ida_bytes.DELIT_SIMPLE, 4)
        if idc.create_dword(cur):
            made.append("%08X" % cur)
    return _ok({"address": "%08X" % ea, "created": len(made), "at": made})

def _patch_bytes(cmd_text):
    parts = cmd_text.split()
    if len(parts) < 2:
        return _err("Usage: PATCH <addr> <hex bytes>")
    try:
        ea = _addr_of(parts[0])
    except Exception as e:
        return _err(str(e))
    raw = "".join(parts[1:]).replace(",", "").replace("0x", "")
    if len(raw) % 2 != 0:
        return _err("Hex bytes must be pairs")
    try:
        vals = bytes.fromhex(raw)
    except Exception as e:
        return _err("Bad hex: " + str(e))
    before = []
    for i in range(len(vals)):
        before.append("%02X" % ida_bytes.get_byte(ea + i))
    ok = ida_bytes.patch_bytes(ea, vals)
    after = []
    for i in range(len(vals)):
        after.append("%02X" % ida_bytes.get_byte(ea + i))
    return _ok({"address": "%08X" % ea, "before": before, "after": after, "count": len(vals), "success": bool(ok)})

def _rtti_walk(cmd_text):
    arg = cmd_text.strip()
    if arg.startswith(".?A"):
        needle = arg
    elif not re.match(r"^[0-9a-fA-F]{1,16}$", arg):
        cls = arg.split("::")
        needle = ".?AV" + cls[-1] + "@" + "".join(p + "@" for p in reversed(cls[:-1])) + "@"
    else:
        needle = None
    if needle is not None:
        hits = _find_bytes_ida(needle.encode("ascii", "replace"))
        if not hits:
            return _err("RTTI string not found for: %s (tried %s)" % (arg, needle))
        saddr = int(hits[0]["address"], 16)
    else:
        saddr = _addr_of(arg)
    name = _read_c_string(saddr, 512)
    td = saddr - 8
    td_bytes = (td & 0xFFFFFFFF).to_bytes(4, "little")
    out = []
    for h in _find_bytes_ida(td_bytes):
        colref = int(h["address"], 16)
        col = colref - 0x0C
        col_bytes = (col & 0xFFFFFFFF).to_bytes(4, "little")
        for h2 in _find_bytes_ida(col_bytes):
            vtm4 = int(h2["address"], 16)
            vt = vtm4 + 4
            v0 = ida_bytes.get_dword(vt)
            k, detail = _classify(v0)
            if k != "func":
                continue
            out.append({
                "col": "%08X" % col,
                "vtable": "%08X" % vt,
                "first_method": detail
            })
    return _ok({"type_descriptor": "%08X" % td, "name": name, "instances": out})

def _trace_addr(addr_text):
    try:
        ea = _addr_of(addr_text)
    except Exception as e:
        return _err(str(e))
    xref = _refs_to(addr_text)
    decomp = _decompile_xrefs(addr_text)
    near = _strings_near(addr_text)
    funcs = set()
    if xref.get("ok"):
        for ref in xref.get("refs", []):
            if ref.get("function_entry"):
                funcs.add(ref["function_entry"])
    if decomp.get("ok"):
        for fn in decomp.get("functions", []):
            if fn.get("function_entry"):
                funcs.add(fn["function_entry"])
    func_details = []
    for entry in sorted(funcs)[:20]:
        info = _function_info(entry)
        if info.get("ok"):
            func_details.append({
                "function_entry": entry,
                "function_name": info.get("function_name"),
                "code": info.get("code")
            })
    return _ok({
        "address": "%08X" % ea,
        "xref": xref,
        "decompile_xref": decomp,
        "nearstr": near,
        "functions": func_details,
        "function_count": len(func_details)
    })

def _import_xrefs(name):
    low = name.lower()
    symbols = []
    qty = ida_nalt.get_import_module_qty()
    for i in range(qty):
        mod_name = ida_nalt.get_import_module_name(i) or ""
        def cb(ea, sym_name, ord_val):
            if sym_name and low in sym_name.lower():
                refs = []
                for x in idautils.XrefsTo(ea):
                    f = _get_func(x.frm)
                    refs.append({
                        "from": "%08X" % x.frm,
                        "type": str(x.type),
                        "function": ida_funcs.get_func_name(f.start_ea) if f else None,
                        "function_entry": ("%08X" % f.start_ea) if f else None
                    })
                    if len(refs) >= MAX_RESULTS:
                        break
                symbols.append({
                    "symbol": f"{mod_name}!{sym_name}" if mod_name else sym_name,
                    "address": "%08X" % ea,
                    "refs": refs,
                    "ref_count": len(refs)
                })
            return 1
        ida_nalt.enum_import_names(i, cb)
    return _ok({"name": name, "symbols": symbols, "count": len(symbols)})

def _set_conv(cmd_text):
    parts = cmd_text.split()
    if len(parts) != 2:
        return _err("Usage: SETCONV <func_addr> <__thiscall|__fastcall|__cdecl|__stdcall>")
    try:
        ea = _addr_of(parts[0])
    except Exception as e:
        return _err(str(e))
    conv = parts[1].strip()
    f = _get_func(ea)
    if not f:
        return _err("No function found", address="%08X" % ea)
    t = idc.get_type(f.start_ea)
    if t:
        if re.search(r'__\w+', t):
            new_t = re.sub(r'__\w+', conv, t)
        else:
            new_t = re.sub(r'(\s*\()', ' ' + conv + r'\1', t, count=1)
        ok = idc.SetType(f.start_ea, new_t)
    else:
        new_t = f"int {conv} sub_{f.start_ea:08X}()"
        ok = idc.SetType(f.start_ea, new_t)
    return _ok({"function": "%08X" % f.start_ea, "convention": conv, "success": bool(ok)})

def _def_struct(cmd_text):
    parts = cmd_text.split()
    if len(parts) < 1:
        return _err("Usage: DEFSTRUCT <name> [size]")
    name = parts[0]
    size = int(parts[1], 0) if len(parts) > 1 else 0
    sid = idc.get_struc_id(name)
    if sid == -1 or sid == ida_idaapi.BADADDR:
        sid = idc.add_struc(-1, name, 0)
    if sid == -1 or sid == ida_idaapi.BADADDR:
        return _err("Failed to create struct: %s" % name)
    curr_size = idc.get_struc_size(sid)
    if size > curr_size:
        pad_len = size - curr_size
        idc.add_struc_member(sid, f"pad_{curr_size:X}", curr_size, ida_bytes.FF_BYTE | ida_bytes.FF_DATA, -1, pad_len)
    return _ok({"struct": name, "size": idc.get_struc_size(sid)})

def _set_field(cmd_text):
    parts = cmd_text.split(None, 3)
    if len(parts) < 3:
        return _err("Usage: SETFIELD <struct> <off> <type> [fieldname]")
    sname = parts[0]
    off = int(parts[1], 0)
    tstr = parts[2].strip()
    fname = parts[3].strip() if len(parts) > 3 else f"field_{off:X}"
    sid = idc.get_struc_id(sname)
    if sid == -1 or sid == ida_idaapi.BADADDR:
        return _err("Struct not found: %s (run DEFSTRUCT first)" % sname)
    tif = ida_typeinf.tinfo_t()
    if not ida_typeinf.parse_decl(tif, None, f"{tstr} dummy;", ida_typeinf.PT_SIL):
        sz = 4
    else:
        sz = tif.get_size()
        if sz <= 0:
            sz = 4
    idc.del_struc_member(sid, off)
    flag = ida_bytes.FF_DWORD if sz == 4 else (ida_bytes.FF_BYTE if sz == 1 else (ida_bytes.FF_WORD if sz == 2 else (ida_bytes.FF_QWORD if sz == 8 else ida_bytes.FF_DATA)))
    res = idc.add_struc_member(sid, fname, off, flag | ida_bytes.FF_DATA, -1, sz)
    if tif.is_correct():
        try:
            mid = idc.get_member_id(sid, off)
            if mid != -1:
                idc.SetType(mid, tstr)
        except Exception:
            pass
    return _ok({"struct": sname, "offset": "0x%x" % off, "type": tstr, "field": fname, "size": sz})

def _retype_var(cmd_text):
    parts = cmd_text.split(None, 2)
    if len(parts) != 3:
        return _err("Usage: RETYPE <func_addr> <var> <type>")
    if not _HAS_HR:
        return _err("Hex-Rays decompiler not available")
    try:
        ea = _addr_of(parts[0])
        vname = parts[1].strip()
        type_str = parts[2].strip()
    except Exception as e:
        return _err(str(e))
    f = _get_func(ea)
    if not f:
        return _err("No function found", address="%08X" % ea)
    try:
        cf = ida_hexrays.decompile(f.start_ea)
        if not cf:
            return _err("Decompilation failed", address="%08X" % f.start_ea)
        tif = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(tif, None, f"{type_str} dummy;", ida_typeinf.PT_SIL):
            return _err("Failed to parse type: %s" % type_str)
        lvars = cf.get_lvars()
        found = False
        for v in lvars:
            if v.name == vname:
                cf.set_lvar_type(v, tif)
                cf.save_user_lvar_settings()
                found = True
                break
        if not found:
            return _err("Variable not found: %s" % vname)
        return _ok({"function": "%08X" % f.start_ea, "var": vname, "type": str(tif)})
    except Exception as e:
        return _err("RETYPE failed: " + str(e))

def _dump_pcode(addr_text):
    try:
        ea = _addr_of(addr_text)
    except Exception as e:
        return _err(str(e))
    f = _get_func(ea)
    if not f:
        return _err("No function found", address="%08X" % ea)
    if not _HAS_HR:
        return _err("Hex-Rays not available for microcode/pcode")
    try:
        hf = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(f, hf, None, ida_hexrays.DECOMP_WARNINGS, ida_hexrays.MMAT_LVARS)
        if not mba:
            return _err("gen_microcode failed: %s" % (hf.desc() if hasattr(hf, "desc") else "error"))
        out = []
        for i in range(mba.qty):
            mblock = mba.get_mblock(i)
            minsn = mblock.head
            while minsn:
                out.append({
                    "at": "%08X" % minsn.ea if minsn.ea != ida_idaapi.BADADDR else "",
                    "op": minsn.dstr()
                })
                minsn = minsn.next
                if len(out) >= 3000:
                    break
            if len(out) >= 3000:
                break
        return _ok({"function": "%08X" % f.start_ea, "name": ida_funcs.get_func_name(f.start_ea) or "", "pcode": out, "count": len(out)})
    except Exception as e:
        return _err("PCODE/Microcode dump error: " + str(e))

def _help_text():
    return _ok({
        "commands": [
            "HELP", "PING", "CURRENT", "NAME <ea>", "FUNC <addr>", "DECOMP <addr>",
            "XREF <addr>", "XFROM <addr>", "STR <ascii>", "WSTR <utf16>", "BYTES <hex>",
            "DECOMP_XREF <addr>", "TRACE <addr>", "MAKEFUNC <addr>",
            "RENAME_FUNC <addr> <name>", "RENAME_SYMBOL <addr> <name>", "RENAME_LABEL <addr> <name>",
            "RENAME_LOCAL <func> <old> <new>", "IMPORTXREF <name>", "NEARSTR <addr>", "READPTR <addr> [n]",
            "WRITERS <addr>", "READERS <addr>", "CALLERS <addr>", "FINDPTR <addr>",
            "STRUCT <addr> [n]", "VTABLE <funcaddr>", "VTDUMP <addr> [n]", "MKPTRS <addr> [n]",
            "RTTI <addr|Name>", "PATCH <addr> <hex>", "PCODE <addr>", "RETYPE <func> <var> <type>",
            "DEFSTRUCT <name> [size]", "SETFIELD <struct> <off> <type> [field]", "SETCONV <func> <conv>",
            "FIND <substr>", "EXPORT [path]", "QUIT"
        ]
    })

def _do(cmd):
    parts = cmd.strip().split(" ", 1)
    op = parts[0].upper()
    arg = parts[1].strip() if len(parts) > 1 else ""

    # Legacy text-based IDA commands
    if op == "PING":
        return "pong"
    if op == "DECOMPILE":
        if not _HAS_HR:
            return "no hexrays"
        try:
            cf = ida_hexrays.decompile(int(arg, 16))
            return str(cf) if cf else "decompile failed"
        except Exception as e:
            return "decompile failed: " + str(e)
    if op == "DISASM":
        a = arg.split()
        ea = int(a[0], 16)
        n = int(a[1]) if len(a) > 1 else 40
        out = []
        for _ in range(n):
            out.append("%08X  %s" % (ea, idc.generate_disasm_line(ea, 0)))
            ea = idc.next_head(ea)
        return "\n".join(out)
    if op == "NAME":
        ea = int(arg, 16)
        return "%08X\t%s" % (ea, ida_name.get_name(ea) or "")
    if op == "FIND":
        out = []
        low = arg.lower()
        for ea, name in idautils.Names():
            if low in name.lower():
                out.append("%08X\t%s" % (ea, name))
                if len(out) >= 300:
                    break
        return "\n".join(out)
    if op == "XREFS":
        ea = int(arg, 16)
        out = []
        for x in idautils.XrefsTo(ea):
            out.append("%08X\t%s" % (x.frm, ida_funcs.get_func_name(x.frm) or ""))
            if len(out) >= 300:
                break
        return "\n".join(out)
    if op == "EXPORT":
        target = arg.strip() if arg else "ida_names.txt"
        fname = os.path.basename(target) or "ida_names.txt"
        if not fname.endswith(".txt"):
            fname += ".txt"
        base_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
        path = os.path.join(base_dir, fname)
        n = 0
        with open(path, "w", encoding="utf-8") as f:
            for ea, name in idautils.Names():
                if name.startswith(_DUMMY):
                    continue
                f.write("%08X\t%s\t%s\n" % (ea, name, _demangle(name)))
                n += 1
        return "exported %d -> %s" % (n, path)

    # Ghidra JSON-style commands
    res = None
    if op == "HELP":
        res = _help_text()
    elif op == "CURRENT":
        res = _function_info("CURRENT")
    elif op in ("FUNC", "DECOMP"):
        res = _function_info(arg)
    elif op == "XREF":
        res = _refs_to(arg)
    elif op == "XFROM":
        res = _refs_from(arg)
    elif op == "STR":
        res = _search_ascii(arg)
    elif op == "WSTR":
        res = _search_utf16(arg)
    elif op == "BYTES":
        res = _search_bytes(arg)
    elif op == "DECOMP_XREF":
        res = _decompile_xrefs(arg)
    elif op == "TRACE":
        res = _trace_addr(arg)
    elif op == "MAKEFUNC":
        res = _make_func(arg)
    elif op == "RENAME_FUNC":
        res = _rename_symbol(arg, "function")
    elif op in ("RENAME_SYMBOL", "RENAME_LABEL", "RENAME"):
        res = _rename_symbol(arg, "symbol")
    elif op == "RENAME_LOCAL":
        res = _rename_local(arg)
    elif op == "NEARSTR":
        res = _strings_near(arg)
    elif op == "READPTR":
        res = _read_pointers(arg)
    elif op == "WRITERS":
        res = _refs_filtered(arg, "write")
    elif op == "READERS":
        res = _refs_filtered(arg, "read")
    elif op == "CALLERS":
        res = _refs_filtered(arg, "call")
    elif op == "FINDPTR":
        res = _find_pointers_to(arg)
    elif op == "STRUCT":
        res = _dump_struct(arg)
    elif op == "VTABLE":
        res = _vtable_context(arg)
    elif op == "VTDUMP":
        res = _vtable_dump(arg)
    elif op == "MKPTRS":
        res = _make_pointers(arg)
    elif op == "RTTI":
        res = _rtti_walk(arg)
    elif op == "IMPORTXREF":
        res = _import_xrefs(arg)
    elif op == "PCODE":
        res = _dump_pcode(arg)
    elif op == "RETYPE":
        res = _retype_var(arg)
    elif op == "DEFSTRUCT":
        res = _def_struct(arg)
    elif op == "SETFIELD":
        res = _set_field(arg)
    elif op == "SETCONV":
        res = _set_conv(arg)
    elif op in ("PATCH", "PATCHBYTES"):
        res = _patch_bytes(arg)
    elif re.match(r"^[0-9a-fA-F]{1,16}$", cmd.strip()):
        res = _function_info(cmd.strip())
    else:
        res = _err("Unknown command: %s" % op, hint="Send HELP")

    return json.dumps(res)

def _run_sync(cmd):
    box = {}
    def f():
        try:
            box["r"] = _do(cmd)
        except Exception:
            box["r"] = json.dumps(_err("Exception: " + traceback.format_exc()))
        return 1
    ida_kernwin.execute_sync(f, ida_kernwin.MFF_WRITE)
    return box.get("r", "")

def _serve():
    global _srv, _running, PORT
    for p in range(BASE_PORT, 65536):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            s.bind(("127.0.0.1", p))
            s.settimeout(1.0)
            s.listen(16)
            _srv = s
            PORT = p
            break
        except OSError:
            try:
                s.close()
            except Exception:
                pass
            continue
    if _srv is None:
        print("[ida_bridge] ERROR: no se encontro ningun puerto libre a partir de %d" % BASE_PORT)
        return

    print("[ida_bridge] listening on 127.0.0.1:%d" % PORT)
    while _running:
        try:
            c, _ = _srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            c.settimeout(120)
            data = b""
            while not data.endswith(b"\n"):
                chunk = c.recv(65536)
                if not chunk:
                    break
                data += chunk
            cmd = data.decode("utf-8", "replace").strip()
            if cmd.upper() in ("QUIT", "SHUTDOWN", "STOP", "EXIT"):
                c.sendall(json.dumps({"ok": True, "shutdown": True}).encode("utf-8") + b"\n")
                _running = False
                c.close()
                break
            res = _run_sync(cmd)
            c.sendall((res + "\n").encode("utf-8", "replace"))
        except Exception:
            try:
                err_msg = json.dumps(_err("Socket loop exception: " + traceback.format_exc()))
                c.sendall((err_msg + "\n").encode("utf-8", "replace"))
            except Exception:
                pass
        finally:
            try:
                c.close()
            except Exception:
                pass
    try:
        _srv.close()
    except Exception:
        pass
    print("[ida_bridge] stopped")

def ida_bridge_stop():
    global _running
    _running = False
    try:
        if _srv is not None:
            _srv.close()
    except Exception:
        pass
    print("[ida_bridge] stopping (envia QUIT o cierra IDA)")

# Re-ejecutar el script en la misma instancia de IDA: el interprete sigue vivo,
# asi que primero se mata el servidor anterior para liberar y reutilizar su puerto.
import builtins
_prev = getattr(builtins, "_ida_bridge_prev", None)
if _prev:
    try:
        _prev["stop"]()
        _prev["thread"].join(3.0)
    except Exception:
        pass

_t = threading.Thread(target=_serve, name="ida_bridge", daemon=True)
builtins._ida_bridge_prev = {"stop": ida_bridge_stop, "thread": _t}
_t.start()
print("[ida_bridge] started, hexrays=%s. Stop: ida_bridge_stop() o comando QUIT" % _HAS_HR)
