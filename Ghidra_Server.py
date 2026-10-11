
import json
import traceback

# jarray es exclusivo de Jython (ghidraRun viejo). PyGhidra (pyghidraRun, Python
# real) no lo tiene y arma los byte[] de Java via JPype. Se soportan los dos.
try:
    import jarray
    def _make_byte_array(signed):
        return jarray.array(signed, 'b')
except ImportError:
    import jpype
    _JByteArray = jpype.JArray(jpype.JByte)
    def _make_byte_array(signed):
        return _JByteArray(signed)

from ghidra.app.decompiler import DecompInterface
try:
    from ghidra.app.decompiler import HighFunctionDBUtil
except ImportError:
    from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.app.services import CodeViewerService
from ghidra.program.model.symbol import RefType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from ghidra.program.model.data import (StructureDataType, PointerDataType,
    DataTypeConflictHandler, Undefined4DataType, IntegerDataType,
    UnsignedIntegerDataType, ByteDataType, CharDataType, ShortDataType,
    UnsignedShortDataType, LongDataType, UnsignedLongDataType, FloatDataType,
    DoubleDataType, VoidDataType, BooleanDataType)
from ghidra.util.task import ConsoleTaskMonitor
from java.net import ServerSocket, InetSocketAddress, SocketTimeoutException
from java.io import BufferedReader, InputStreamReader, PrintWriter

PORT = 5093
MAX_RESULTS = 200

print("=== GHIDRA SERVER V2 STARTED ===")

decomp = DecompInterface()
decomp.openProgram(currentProgram)

try:
    script_monitor = monitor
except NameError:
    script_monitor = None

monitor = ConsoleTaskMonitor()


def is_cancelled():
    try:
        if script_monitor is not None and script_monitor.isCancelled():
            return True
    except:
        pass
    return monitor.isCancelled()


# API LAZY: FlatProgramAPI.getReferencesTo() hace getReferenceCountTo()+array eager
# (dispara "Loading references N of M" y cuelga con miles de refs). El ReferenceManager
# devuelve un iterador perezoso: se corta apenas juntamos lo necesario.
_refmgr = currentProgram.getReferenceManager()


def refs_to_iter(addr):
    return _refmgr.getReferencesTo(addr)


def refs_from_iter(addr):
    return _refmgr.getReferencesFrom(addr)


def ok(data):
    data["ok"] = True
    return data


def err(msg, **extra):
    out = {"ok": False, "error": str(msg)}
    out.update(extra)
    return out


def addr_of(s):
    s = s.strip()
    if not s:
        raise Exception("Empty address")
    a = toAddr(s)
    if a is None:
        raise Exception("Invalid address: %s" % s)
    return a


def current_addr():
    service = state.getTool().getService(CodeViewerService)
    if service is None:
        raise Exception("CodeViewerService not found")
    loc = service.getCurrentLocation()
    if loc is None:
        raise Exception("Current CodeBrowser location not found")
    return loc.getAddress()


def get_func(addr):
    f = getFunctionContaining(addr)
    if f is None:
        f = getFunctionAt(addr)
    return f


def decompile_func(f):
    res = decomp.decompileFunction(f, 60, monitor)
    if not res.decompileCompleted():
        return None
    return res.getDecompiledFunction().getC()


def function_info(addr_text):
    try:
        addr = current_addr() if addr_text.upper() == "CURRENT" else addr_of(addr_text)
    except Exception as e:
        return err(str(e), requested=addr_text)
    if addr is None:
        return err("Address resolved to null", requested=addr_text)
    f = get_func(addr)
    if f is None:
        return err("No function found", requested=addr_text, resolved=str(addr))

    code = decompile_func(f)
    listing = currentProgram.getListing()
    instructions = listing.getInstructions(f.getBody(), True)
    asm = []
    for ins in instructions:
        asm.append("%s  %s" % (ins.getAddress(), ins))

    return ok({
        "address": str(f.getEntryPoint()),
        "function_entry": str(f.getEntryPoint()),
        "function_name": f.getName(),
        "size": f.getBody().getNumAddresses(),
        "code": code,
        "asm": asm
    })


SCAN_CAP = 4000


def refs_to(addr_text):
    addr = addr_of(addr_text)
    refs = []
    total = 0
    capped = False
    for r in refs_to_iter(addr):
        total += 1
        if len(refs) < MAX_RESULTS:
            frm = r.getFromAddress()
            f = get_func(frm)
            refs.append({
                "from": str(frm),
                "to": str(addr),
                "type": str(r.getReferenceType()),
                "function": f.getName() if f else None,
                "function_entry": str(f.getEntryPoint()) if f else None
            })
        if total >= SCAN_CAP:
            capped = True
            break
    return ok({"address": str(addr), "refs": refs, "count": total, "capped": capped})


def refs_from(addr_text):
    addr = addr_of(addr_text)
    refs = []
    for r in refs_from_iter(addr):
        to = r.getToAddress()
        f = get_func(addr)
        refs.append({
            "from": str(addr),
            "to": str(to),
            "type": str(r.getReferenceType()),
            "function": f.getName() if f else None,
            "function_entry": str(f.getEntryPoint()) if f else None
        })
    return ok({"address": str(addr), "refs": refs[:MAX_RESULTS], "count": len(refs)})


def read_c_string(addr, max_len=512):
    mem = currentProgram.getMemory()
    bs = []
    for i in range(max_len):
        b = mem.getByte(addr.add(i)) & 0xff
        if b == 0:
            break
        if b < 0x20 or b > 0x7e:
            return None
        bs.append(chr(b))
    if not bs:
        return None
    return "".join(bs)


def read_utf16_string(addr, max_chars=512):
    mem = currentProgram.getMemory()
    chars = []
    for i in range(max_chars):
        lo = mem.getByte(addr.add(i * 2)) & 0xff
        hi = mem.getByte(addr.add(i * 2 + 1)) & 0xff
        v = lo | (hi << 8)
        if v == 0:
            break
        if v < 0x20 or v > 0x7e:
            return None
        chars.append(chr(v))
    if not chars:
        return None
    return "".join(chars)


def find_bytes(pattern):
    mem = currentProgram.getMemory()
    signed = []
    for b in pattern:
        signed.append(b - 256 if b > 127 else b)
    jpattern = _make_byte_array(signed)
    results = []
    start = mem.getMinAddress()
    while start is not None and len(results) < MAX_RESULTS:
        found = mem.findBytes(start, jpattern, None, True, monitor)
        if found is None:
            break
        f = get_func(found)
        results.append({
            "address": str(found),
            "function": f.getName() if f else None,
            "function_entry": str(f.getEntryPoint()) if f else None
        })
        start = found.add(1)
    return results


def parse_hex(hex_text):
    clean = hex_text.replace(" ", "").replace("\\x", "").replace(",", "")
    if len(clean) % 2 != 0:
        raise Exception("Odd hex length")
    return [int(clean[i:i+2], 16) for i in range(0, len(clean), 2)]


def search_bytes(hex_text):
    pattern = parse_hex(hex_text)
    return ok({"pattern": hex_text, "results": find_bytes(pattern)})


def search_ascii(text):
    pattern = [ord(c) for c in text]
    raw = find_bytes(pattern)
    out = []
    for hit in raw:
        addr = addr_of(hit["address"])
        value = read_c_string(addr)
        refs = []
        for r in refs_to_iter(addr):
            frm = r.getFromAddress()
            f = get_func(frm)
            refs.append({
                "from": str(frm),
                "function": f.getName() if f else None,
                "function_entry": str(f.getEntryPoint()) if f else None
            })
        hit["string"] = value
        hit["refs"] = refs[:50]
        hit["ref_count"] = len(refs)
        out.append(hit)
    return ok({"text": text, "encoding": "ascii", "results": out})


def search_utf16(text):
    pattern = []
    for c in text:
        v = ord(c)
        pattern.append(v & 0xff)
        pattern.append((v >> 8) & 0xff)
    raw = find_bytes(pattern)
    out = []
    for hit in raw:
        addr = addr_of(hit["address"])
        value = read_utf16_string(addr)
        refs = []
        for r in refs_to_iter(addr):
            frm = r.getFromAddress()
            f = get_func(frm)
            refs.append({
                "from": str(frm),
                "function": f.getName() if f else None,
                "function_entry": str(f.getEntryPoint()) if f else None
            })
        hit["string"] = value
        hit["refs"] = refs[:50]
        hit["ref_count"] = len(refs)
        out.append(hit)
    return ok({"text": text, "encoding": "utf16le", "results": out})


def decompile_xrefs(addr_text):
    addr = addr_of(addr_text)
    funcs = {}
    for r in refs_to_iter(addr):
        f = get_func(r.getFromAddress())
        if f is not None:
            funcs[str(f.getEntryPoint())] = f

    out = []
    for entry, f in funcs.items():
        out.append({
            "function_entry": entry,
            "function_name": f.getName(),
            "code": decompile_func(f)
        })
    return ok({"address": str(addr), "functions": out[:50], "count": len(out)})


def make_func(addr_text):
    addr = addr_of(addr_text)
    listing = currentProgram.getListing()
    try:
        disassemble(addr)
    except Exception:
        pass

    f = getFunctionAt(addr)
    if f is None:
        try:
            f = createFunction(addr, None)
        except Exception as e:
            return err("createFunction failed", address=str(addr), details=str(e))
    if f is None:
        return err("No function after create", address=str(addr))
    return function_info(str(f.getEntryPoint()))


def import_xrefs(name):
    symtab = currentProgram.getSymbolTable()
    symbols = symtab.getSymbols(name)
    out = []
    for sym in symbols:
        addr = sym.getAddress()
        refs = []
        for r in refs_to_iter(addr):
            frm = r.getFromAddress()
            f = get_func(frm)
            refs.append({
                "from": str(frm),
                "type": str(r.getReferenceType()),
                "function": f.getName() if f else None,
                "function_entry": str(f.getEntryPoint()) if f else None
            })
        out.append({
            "symbol": sym.getName(True),
            "address": str(addr),
            "refs": refs[:MAX_RESULTS],
            "ref_count": len(refs)
        })
    return ok({"name": name, "symbols": out, "count": len(out)})


def trace_addr(addr_text):
    try:
        addr_of(addr_text)
    except Exception as e:
        return err(str(e), requested=addr_text)

    xref = refs_to(addr_text)
    decomp = decompile_xrefs(addr_text)
    near = strings_near(addr_text)
    funcs = set()
    if xref.get("ok"):
        for ref in xref.get("refs", []):
            fe = ref.get("function_entry")
            if fe:
                funcs.add(fe)
    if decomp.get("ok"):
        for fn in decomp.get("functions", []):
            fe = fn.get("function_entry")
            if fe:
                funcs.add(fe)

    func_details = []
    for entry in sorted(funcs)[:20]:
        info = function_info(entry)
        if info.get("ok"):
            func_details.append({
                "function_entry": entry,
                "function_name": info.get("function_name"),
                "code": info.get("code"),
            })

    return ok({
        "address": addr_text,
        "xref": xref,
        "decompile_xref": decomp,
        "nearstr": near,
        "functions": func_details,
        "function_count": len(func_details),
    })


def validate_name(name):
    import re
    name = name.strip()
    if not name:
        raise Exception("Empty name")
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
        raise Exception("Bad name: %s (use C identifier: letters/numbers/_)" % name)
    return name


def rename_function(cmd_text):
    parts = cmd_text.split(None, 1)
    if len(parts) != 2:
        return err("Usage: RENAME_FUNC <addr> <new_name>")
    addr = addr_of(parts[0])
    new_name = validate_name(parts[1])
    f = get_func(addr)
    if f is None:
        return err("No function found", address=str(addr))
    old_name = f.getName()
    f.setName(new_name, SourceType.USER_DEFINED)
    decomp.flushCache()
    return ok({
        "kind": "function",
        "address": str(f.getEntryPoint()),
        "old_name": old_name,
        "new_name": f.getName()
    })


def rename_symbol(cmd_text):
    parts = cmd_text.split(None, 1)
    if len(parts) != 2:
        return err("Usage: RENAME_SYMBOL <addr> <new_name>")
    addr = addr_of(parts[0])
    new_name = validate_name(parts[1])
    symtab = currentProgram.getSymbolTable()
    sym = symtab.getPrimarySymbol(addr)
    if sym is None:
        sym = createLabel(addr, new_name, True)
        decomp.flushCache()
        return ok({
            "kind": "symbol",
            "address": str(addr),
            "old_name": None,
            "new_name": sym.getName(),
            "created": True
        })
    old_name = sym.getName()
    sym.setName(new_name, SourceType.USER_DEFINED)
    decomp.flushCache()
    return ok({
        "kind": "symbol",
        "address": str(addr),
        "old_name": old_name,
        "new_name": sym.getName(),
        "created": False
    })


def rename_label(cmd_text):
    return rename_symbol(cmd_text)


def rename_local(cmd_text):
    parts = cmd_text.split()
    if len(parts) != 3:
        return err("Usage: RENAME_LOCAL <func_addr> <old_local_name> <new_name>")

    func_addr = addr_of(parts[0])
    old_name = parts[1].strip()
    new_name = validate_name(parts[2])
    f = get_func(func_addr)
    if f is None:
        return err("No function found", address=str(func_addr))

    res = decomp.decompileFunction(f, 60, monitor)
    if not res.decompileCompleted():
        return err("Decompile failed", function=str(f.getEntryPoint()))
    high = res.getHighFunction()
    if high is None:
        return err("No HighFunction", function=str(f.getEntryPoint()))

    local_map = high.getLocalSymbolMap()
    symbols = local_map.getSymbols()
    matches = []
    while symbols.hasNext():
        sym = symbols.next()
        if sym.getName() == old_name:
            matches.append(sym)

    if len(matches) == 0:
        return err("Local not found", function=str(f.getEntryPoint()), old_name=old_name)
    if len(matches) > 1:
        return err("Multiple locals matched; rename manually or use unique old name",
                   function=str(f.getEntryPoint()), old_name=old_name, count=len(matches))

    sym = matches[0]
    try:
        HighFunctionDBUtil.updateDBVariable(sym, new_name, None, SourceType.USER_DEFINED)
    except TypeError:
        try:
            HighFunctionDBUtil.updateDBVariable(sym, new_name, sym.getDataType(), SourceType.USER_DEFINED)
        except Exception as e:
            return err("RENAME_LOCAL failed", details=str(e), function=str(f.getEntryPoint()),
                       old_name=old_name, new_name=new_name)
    except Exception as e:
        return err("RENAME_LOCAL failed", details=str(e), function=str(f.getEntryPoint()),
                   old_name=old_name, new_name=new_name)

    decomp.flushCache()
    return ok({
        "kind": "local",
        "function": str(f.getEntryPoint()),
        "old_name": old_name,
        "new_name": new_name
    })


def read_pointers(cmd_text):
    parts = cmd_text.split()
    addr = addr_of(parts[0])
    count = int(parts[1]) if len(parts) > 1 else 1
    mem = currentProgram.getMemory()
    out = []
    for i in range(count):
        a = addr.add(i * 4)
        v = 0
        for j in range(4):
            v |= (mem.getByte(a.add(j)) & 0xff) << (8 * j)
        target = "%08x" % v
        f = None
        try:
            ta = toAddr(target)
            fn = get_func(ta) if ta is not None else None
            f = fn.getName() if fn else None
        except:
            pass
        out.append({"slot": i, "at": str(a), "value": target, "function": f})
    return ok({"address": str(addr), "count": count, "pointers": out})


def strings_near(addr_text, before=128, after=128):
    addr = addr_of(addr_text)
    mem = currentProgram.getMemory()
    start = addr.subtract(before)
    end = addr.add(after)
    found = []
    a = start
    while a.compareTo(end) <= 0 and len(found) < 100:
        s = read_c_string(a, 200)
        if s and len(s) >= 3:
            found.append({"address": str(a), "type": "ascii", "value": s})
            a = a.add(len(s))
        else:
            ws = read_utf16_string(a, 200)
            if ws and len(ws) >= 3:
                found.append({"address": str(a), "type": "utf16le", "value": ws})
                a = a.add(len(ws) * 2)
            else:
                a = a.add(1)
    return ok({"around": str(addr), "strings": found})


def _is_hex_addr(text):
    if not text:
        return False
    for c in text:
        if c not in "0123456789abcdefABCDEF":
            return False
    return True


def _addr_le_bytes(addr):
    v = addr.getOffset() & 0xffffffff
    return [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff]


def _classify(v):
    # v = uint32. Devuelve (kind, detail) si apunta a func/string/data mapeado.
    mem = currentProgram.getMemory()
    try:
        ta = toAddr("%08x" % v)
    except:
        return (None, None)
    if ta is None or not mem.contains(ta):
        return (None, None)
    fn = get_func(ta)
    if fn is not None:
        off = ta.subtract(fn.getEntryPoint())
        return ("func", fn.getName() if off == 0 else "%s+0x%x" % (fn.getName(), off))
    s = read_c_string(ta, 64)
    if s and len(s) >= 3:
        return ("str", s)
    return ("ptr", None)


def refs_filtered(addr_text, want):
    addr = addr_of(addr_text)
    out = []
    total = 0
    capped = False
    for r in refs_to_iter(addr):
        total += 1
        rt = r.getReferenceType()
        keep = True
        try:
            if want == "write":
                keep = rt.isWrite()
            elif want == "read":
                keep = rt.isRead()
            elif want == "call":
                keep = rt.isCall()
        except:
            keep = True
        if keep and len(out) < MAX_RESULTS:
            frm = r.getFromAddress()
            f = get_func(frm)
            out.append({
                "from": str(frm),
                "type": str(rt),
                "function": f.getName() if f else None,
                "function_entry": str(f.getEntryPoint()) if f else None
            })
        if total >= SCAN_CAP:
            capped = True
            break
    return ok({"address": str(addr), "filter": want, "refs": out, "scanned": total, "capped": capped})


def find_pointers_to(addr_text):
    addr = addr_of(addr_text)
    hits = find_bytes(_addr_le_bytes(addr))
    out = []
    for h in hits:
        out.append({"at": h["address"], "in_function": h["function"]})
    return ok({"target": str(addr), "pointer_locations": out, "count": len(out)})


def dump_struct(cmd_text):
    parts = cmd_text.split()
    addr = addr_of(parts[0])
    count = int(parts[1]) if len(parts) > 1 else 16
    mem = currentProgram.getMemory()
    out = []
    for i in range(count):
        a = addr.add(i * 4)
        v = 0
        try:
            for j in range(4):
                v |= (mem.getByte(a.add(j)) & 0xff) << (8 * j)
        except:
            out.append({"off": "+0x%x" % (i * 4), "at": str(a), "error": "unreadable"})
            continue
        sv = v if v < 0x80000000 else v - 0x100000000
        entry = {"off": "+0x%x" % (i * 4), "at": str(a), "hex": "%08x" % v, "int": sv}
        kind, detail = _classify(v)
        if kind:
            entry["kind"] = kind
        if detail is not None:
            entry["detail"] = detail
        out.append(entry)
    return ok({"address": str(addr), "fields": out})


def vtable_context(addr_text):
    addr = addr_of(addr_text)
    hits = find_bytes(_addr_le_bytes(addr))
    mem = currentProgram.getMemory()
    out = []
    for h in hits:
        loc = addr_of(h["address"])
        slots = []
        for k in range(-3, 6):
            a = loc.add(k * 4)
            v = 0
            try:
                for j in range(4):
                    v |= (mem.getByte(a.add(j)) & 0xff) << (8 * j)
            except:
                continue
            kind, detail = _classify(v)
            slots.append({
                "slot_off": "%+d" % (k * 4),
                "at": str(a),
                "val": "%08x" % v,
                "func": detail if kind == "func" else None,
                "is_target": (k == 0)
            })
        # quien referencia la base probable de la vtable (para hallar el ctor/clase)
        base = loc
        writers = []
        try:
            for r in refs_to_iter(base):
                frm = r.getFromAddress()
                f = get_func(frm)
                writers.append({"from": str(frm), "function": f.getName() if f else None})
                if len(writers) >= 20:
                    break
        except:
            pass
        out.append({"vtable_hit": h["address"], "slots": slots, "refs_to_slot": writers})
    return ok({"target": str(addr), "vtables": out, "count": len(out)})


_BUILTIN_TYPES = {
    "undefined4": Undefined4DataType, "int": IntegerDataType,
    "uint": UnsignedIntegerDataType, "byte": ByteDataType, "char": CharDataType,
    "short": ShortDataType, "ushort": UnsignedShortDataType, "long": LongDataType,
    "ulong": UnsignedLongDataType, "float": FloatDataType, "double": DoubleDataType,
    "void": VoidDataType, "bool": BooleanDataType,
}


def parse_type(s):
    s = s.strip()
    depth = 0
    while s.endswith("*"):
        depth += 1
        s = s[:-1].strip()
    dtm = currentProgram.getDataTypeManager()
    dt = None
    low = s.lower()
    if low in _BUILTIN_TYPES:
        dt = _BUILTIN_TYPES[low]()
    if dt is None:
        for cand in (s, "/" + s):
            dt = dtm.getDataType(cand)
            if dt is not None:
                break
    if dt is None:
        dt = dtm.findDataType("/" + s)
    if dt is None:
        raise Exception("Unknown type: %s" % s)
    for _ in range(depth):
        dt = PointerDataType(dt)
    return dt


def find_high_sym(f, vname):
    res = decomp.decompileFunction(f, 60, monitor)
    if not res.decompileCompleted():
        return None, None, "Decompile failed"
    high = res.getHighFunction()
    if high is None:
        return None, None, "No HighFunction"
    syms = high.getLocalSymbolMap().getSymbols()
    while syms.hasNext():
        s = syms.next()
        if s.getName() == vname:
            return high, s, None
    return high, None, "Var not found: %s" % vname


def dump_pcode(addr_text):
    addr = addr_of(addr_text)
    f = get_func(addr)
    if f is None:
        return err("No function found", address=str(addr))
    res = decomp.decompileFunction(f, 60, monitor)
    if not res.decompileCompleted():
        return err("Decompile failed", function=str(f.getEntryPoint()))
    high = res.getHighFunction()
    if high is None:
        return err("No HighFunction", function=str(f.getEntryPoint()))
    ops = high.getPcodeOps()
    out = []
    n = 0
    while ops.hasNext() and n < 3000:
        op = ops.next()
        n += 1
        mn = op.getMnemonic()
        outp = op.getOutput()
        ins = op.getInputs()
        item = {
            "at": str(op.getSeqnum().getTarget()),
            "op": mn,
            "out": outp.toString() if outp is not None else None,
            "in": [v.toString() for v in ins],
        }
        if mn in ("CALL", "CALLIND", "BRANCHIND") and len(ins) > 0:
            t = ins[0]
            try:
                if t.isAddress() or t.isConstant():
                    ta = t.getAddress()
                    fn = get_func(ta) if ta is not None else None
                    if fn is not None:
                        item["call"] = fn.getName()
            except:
                pass
        out.append(item)
    return ok({"function": str(f.getEntryPoint()), "name": f.getName(), "pcode": out, "count": n})


def retype_var(cmd_text):
    parts = cmd_text.split(None, 2)
    if len(parts) != 3:
        return err("Usage: RETYPE <func_addr> <var> <type>")
    faddr = addr_of(parts[0])
    vname = parts[1].strip()
    dt = parse_type(parts[2])
    f = get_func(faddr)
    if f is None:
        return err("No function found", address=str(faddr))
    high, sym, msg = find_high_sym(f, vname)
    if sym is None:
        return err(msg, function=str(f.getEntryPoint()))
    try:
        HighFunctionDBUtil.updateDBVariable(sym, sym.getName(), dt, SourceType.USER_DEFINED)
    except Exception as e:
        return err("RETYPE failed", details=str(e))
    decomp.flushCache()
    return ok({"function": str(f.getEntryPoint()), "var": vname, "type": str(dt)})


def def_struct(cmd_text):
    parts = cmd_text.split()
    if len(parts) < 1:
        return err("Usage: DEFSTRUCT <name> [size]")
    name = parts[0]
    size = int(parts[1], 0) if len(parts) > 1 else 0
    dtm = currentProgram.getDataTypeManager()
    st = StructureDataType(name, size)
    nd = dtm.addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER)
    return ok({"struct": name, "size": nd.getLength()})


def set_field(cmd_text):
    parts = cmd_text.split(None, 3)
    if len(parts) < 3:
        return err("Usage: SETFIELD <struct> <off> <type> [fieldname]")
    name = parts[0]
    off = int(parts[1], 0)
    dt = parse_type(parts[2])
    fname = parts[3].strip() if len(parts) > 3 else None
    dtm = currentProgram.getDataTypeManager()
    st = dtm.getDataType("/" + name)
    if st is None:
        st = dtm.getDataType(name)
    if st is None:
        return err("Struct not found (DEFSTRUCT first)", struct=name)
    try:
        st.replaceAtOffset(off, dt, dt.getLength(), fname, None)
    except Exception as e:
        return err("SETFIELD failed", details=str(e))
    return ok({"struct": name, "offset": "0x%x" % off, "type": str(dt), "field": fname})


def rtti_walk(cmd_text):
    # RTTI <type_descriptor_string_addr>  (32-bit MSVC).
    # Cadena: name-string@(td+8) -> TypeDescriptor(td) <- COL+0x0C <- vtable[-1].
    # Usa scan de memoria (find_bytes) para funcionar aunque no haya analisis previo.
    arg = cmd_text.strip()
    # Acepta la direccion del string O el nombre de la clase, mangled
    # (".?AVCClientPlayer@Game@@") o a secas ("CClientPlayer", "Game::CClientPlayer").
    if arg.startswith(".?A"):
        needle = arg
    elif not _is_hex_addr(arg):
        cls = arg.split("::")
        needle = ".?AV" + cls[-1] + "@" + "".join(p + "@" for p in reversed(cls[:-1])) + "@"
    else:
        needle = None
    if needle is not None:
        hits = find_bytes([ord(c) for c in needle])
        if not hits:
            return err("no encontre el RTTI de '%s' (probe con: %s)" % (arg, needle))
        saddr = addr_of(hits[0]["address"])
    else:
        saddr = addr_of(arg)
    name = read_c_string(saddr, 512)
    td = saddr.subtract(8)
    mem = currentProgram.getMemory()
    out = []
    for h in find_bytes(_addr_le_bytes(td)):
        colref = addr_of(h["address"])          # apunta a COL+0x0C
        col = colref.subtract(0x0c)             # base del CompleteObjectLocator
        # validar: COL.signature (col+0) suele ser 0 en x86
        for h2 in find_bytes(_addr_le_bytes(col)):
            vtm4 = addr_of(h2["address"])        # vtable-4 (slot del COL)
            vt = vtm4.add(4)                     # inicio de la vtable
            v0 = 0
            try:
                for j in range(4):
                    v0 |= (mem.getByte(vt.add(j)) & 0xff) << (8 * j)
            except:
                continue
            k, detail = _classify(v0)
            # Al TypeDescriptor tambien lo apunta el BaseClassDescriptor (en +0),
            # que da un "COL" fantasma cuyo supuesto primer metodo no es codigo.
            # Una vtable de verdad arranca con una funcion.
            if k != "func":
                continue
            out.append({
                "col": str(col),
                "vtable": str(vt),
                "first_method": detail
            })
    return ok({"type_descriptor": str(td), "name": name, "instances": out,
               "hint": "RENAME_SYMBOL <vtable> vftable_<Clase> ; el 1er metodo suele ser el ctor/dtor"})


def make_pointers(cmd_text):
    # MKPTRS <addr> [count]: tipa N dwords como punteros.
    # Sin esto una vtable se ve como bytes sueltos ("?? 50h") y no como la lista
    # de metodos, aunque el VTDUMP si los encuentre.
    parts = cmd_text.split()
    if len(parts) < 1:
        return err("Usage: MKPTRS <addr> [count]")
    addr = addr_of(parts[0])
    count = int(parts[1], 0) if len(parts) > 1 else 1
    listing = currentProgram.getListing()
    dt = PointerDataType()
    made = []
    for i in range(count):
        a = addr.add(i * 4)
        try:
            listing.clearCodeUnits(a, a.add(3), False)
            listing.createData(a, dt)
            made.append(str(a))
        except:
            break
    return ok({"address": str(addr), "created": len(made), "at": made})


def vtable_dump(cmd_text):
    parts = cmd_text.split()
    if len(parts) < 1:
        return err("Usage: VTDUMP <addr> [count]")
    addr = addr_of(parts[0])
    count = int(parts[1], 0) if len(parts) > 1 else 128
    mem = currentProgram.getMemory()
    out = []
    junk = 0
    for i in range(count):
        a = addr.add(i * 4)
        v = 0
        broke = False
        for j in range(4):
            try:
                v |= (mem.getByte(a.add(j)) & 0xff) << (8 * j)
            except:
                broke = True
                break
        if broke:
            break
        kind, detail = _classify(v)
        # Un slot que no es funcion no termina la vtable: con herencia multiple
        # las vtables van pegadas y entre medio queda el COL de la siguiente,
        # y ademas puede haber metodos que Ghidra todavia no creo como funcion.
        # Se corta con el 0 terminador o tras varios slots seguidos sin sentido.
        if v == 0:
            break
        if kind != "func":
            junk += 1
            if junk > 3:
                break
        else:
            junk = 0
        out.append({
            "idx": i,
            "off": "0x%x" % (i * 4),
            "at": str(a),
            "val": "%08x" % v,
            "func": detail if kind == "func" else None,
            "kind": kind
        })
    while out and out[-1]["kind"] != "func":
        out.pop()
    return ok({"vtable": str(addr), "slots": out, "count": len(out)})


def set_conv(cmd_text):
    parts = cmd_text.split()
    if len(parts) != 2:
        return err("Usage: SETCONV <func_addr> <__thiscall|__fastcall|__cdecl|__stdcall>")
    f = get_func(addr_of(parts[0]))
    if f is None:
        return err("No function found", address=parts[0])
    try:
        f.setCallingConvention(parts[1])
    except Exception as e:
        names = []
        try:
            for n in currentProgram.getFunctionManager().getCallingConventionNames():
                names.append(str(n))
        except:
            pass
        return err("SETCONV failed", details=str(e), valid=names)
    decomp.flushCache()
    return ok({"function": str(f.getEntryPoint()), "convention": f.getCallingConventionName()})


def patch_bytes(cmd_text):
    # PATCH <addr> <hex bytes>   ej: PATCH 01aec298 EB   |   PATCH 01aec298 90 90
    parts = cmd_text.split()
    if len(parts) < 2:
        return err("Usage: PATCH <addr> <hex bytes>   ej: PATCH 01aec298 EB")
    a = addr_of(parts[0])
    if a is None:
        return err("Bad address", address=parts[0])
    raw = "".join(parts[1:]).replace(",", "").replace("0x", "")
    if len(raw) % 2 != 0:
        return err("Hex bytes must be pairs", got=raw)
    try:
        vals = [int(raw[i:i + 2], 16) for i in range(0, len(raw), 2)]
    except Exception as e:
        return err("Bad hex", details=str(e), got=raw)
    mem = currentProgram.getMemory()
    before = []
    for i in range(len(vals)):
        try:
            before.append("%02X" % (mem.getByte(a.add(i)) & 0xFF))
        except:
            before.append("??")
    # Ghidra no deja escribir encima de una instruccion: hay que limpiar el code
    # unit ANTES. (bare except: las excepciones Java no las atrapa `except Exception`)
    try:
        currentProgram.getListing().clearCodeUnits(a, a.add(len(vals) - 1), False)
    except:
        pass
    try:
        for i, v in enumerate(vals):
            b = v & 0xFF
            mem.setByte(a.add(i), b - 256 if b > 127 else b)
    except:
        try:
            disassemble(a)
        except:
            pass
        return err("PATCH failed", details=traceback.format_exc().splitlines()[-1],
                   hint="Memoria no escribible? Ghidra: Window > Memory Map > marcar la W del bloque")
    after = []
    for i in range(len(vals)):
        try:
            after.append("%02X" % (mem.getByte(a.add(i)) & 0xFF))
        except:
            after.append("??")
    try:
        disassemble(a)
    except:
        pass
    decomp.flushCache()
    return ok({"address": str(a), "before": before, "after": after, "count": len(vals)})


def help_text():
    return ok({
        "commands": [
            "HELP",
            "CURRENT",
            "FUNC <addr>",
            "DECOMP <addr>",
            "XREF <addr>",
            "XFROM <addr>",
            "STR <ascii text>",
            "WSTR <utf16 text>",
            "BYTES <hex bytes>",
            "DECOMP_XREF <addr>",
            "TRACE <addr>",
            "MAKEFUNC <addr>",
            "RENAME_FUNC <addr> <new_name>",
            "RENAME_SYMBOL <addr> <new_name>",
            "RENAME_LABEL <addr> <new_name>",
            "RENAME_LOCAL <func_addr> <old_local_name> <new_name>",
            "IMPORTXREF <name>",
            "NEARSTR <addr>",
            "READPTR <addr> [count]",
            "WRITERS <addr>    (quien ESCRIBE ese global)",
            "READERS <addr>    (quien LEE ese global)",
            "CALLERS <addr>    (refs de tipo call, incl. indirectas resueltas)",
            "FINDPTR <addr>    (donde en memoria hay un puntero a addr: vtables/tablas)",
            "STRUCT <addr> [n] (dump de campos: int/ptr/func/string)",
            "VTABLE <funcaddr> (vtables que contienen la func + slots vecinos con nombres)",
            "PCODE <addr>      (p-code del decompilador: STOREs=quien escribe, CALLIND resueltos)",
            "RETYPE <func> <var> <type>   (tipo real a una variable; acepta Struct*)",
            "DEFSTRUCT <name> [size]      (crea una estructura real)",
            "SETFIELD <struct> <off> <type> [field]  (define un campo de la estructura)",
            "VTDUMP <addr> [count]        (dumpea la vtable ENTERA: cada slot -> nombre de metodo)",
            "RTTI <addr|Clase|Ns::Clase>  (camina TypeDescriptor->COL->vtable; da la vtable de la clase)",
            "SETCONV <func> <convention>  (__thiscall/__fastcall/__cdecl/__stdcall)",
            "PATCH <addr> <hex bytes>     (escribe bytes: PATCH 01aec298 EB)",
            "QUIT"
        ]
    })


def handle(line):
    line = line.strip()
    if not line:
        return err("Empty command")

    upper = line.upper()
    if upper == "HELP":
        return help_text()
    if upper == "CURRENT":
        return function_info("CURRENT")
    if upper.startswith("FUNC "):
        return function_info(line[5:].strip())
    if upper.startswith("DECOMP "):
        return function_info(line[7:].strip())
    if upper.startswith("XREF "):
        return refs_to(line[5:].strip())
    if upper.startswith("XFROM "):
        return refs_from(line[6:].strip())
    if upper.startswith("STR "):
        return search_ascii(line[4:])
    if upper.startswith("WSTR "):
        return search_utf16(line[5:])
    if upper.startswith("BYTES "):
        return search_bytes(line[6:].strip())
    if upper.startswith("DECOMP_XREF "):
        return decompile_xrefs(line[12:].strip())
    if upper.startswith("MAKEFUNC "):
        return make_func(line[9:].strip())
    if upper.startswith("RENAME_FUNC "):
        return rename_function(line[12:].strip())
    if upper.startswith("RENAME_SYMBOL "):
        return rename_symbol(line[14:].strip())
    if upper.startswith("RENAME_LABEL "):
        return rename_label(line[13:].strip())
    if upper.startswith("RENAME_LOCAL "):
        return rename_local(line[13:].strip())
    if upper.startswith("IMPORTXREF "):
        return import_xrefs(line[11:].strip())
    if upper.startswith("NEARSTR "):
        return strings_near(line[8:].strip())
    if upper.startswith("READPTR "):
        return read_pointers(line[8:].strip())
    if upper.startswith("TRACE "):
        return trace_addr(line[6:].strip())
    if upper.startswith("WRITERS "):
        return refs_filtered(line[8:].strip(), "write")
    if upper.startswith("READERS "):
        return refs_filtered(line[8:].strip(), "read")
    if upper.startswith("CALLERS "):
        return refs_filtered(line[8:].strip(), "call")
    if upper.startswith("FINDPTR "):
        return find_pointers_to(line[8:].strip())
    if upper.startswith("STRUCT "):
        return dump_struct(line[7:].strip())
    if upper.startswith("VTABLE "):
        return vtable_context(line[7:].strip())
    if upper.startswith("PCODE "):
        return dump_pcode(line[6:].strip())
    if upper.startswith("RETYPE "):
        return retype_var(line[7:].strip())
    if upper.startswith("DEFSTRUCT "):
        return def_struct(line[10:].strip())
    if upper.startswith("SETFIELD "):
        return set_field(line[9:].strip())
    if upper.startswith("VTDUMP "):
        return vtable_dump(line[7:].strip())
    if upper.startswith("MKPTRS "):
        return make_pointers(line[7:].strip())
    if upper.startswith("RTTI "):
        return rtti_walk(line[5:].strip())
    if upper.startswith("SETCONV "):
        return set_conv(line[8:].strip())
    if upper.startswith("PATCHBYTES "):
        return patch_bytes(line[11:].strip())

    if upper.startswith("PATCH "):
        return patch_bytes(line[6:].strip())

    import re
    if re.match(r"^[0-9a-fA-F]{1,16}$", line):
        return function_info(line)

    return err("Unknown command", command=line, hint="Send HELP")


# Si el loop muere sin cerrar el socket, el puerto queda tomado dentro de
# la JVM de Ghidra y no se libera hasta reiniciarla. En vez de obligar a eso,
# se prueba el siguiente puerto libre.
server = None
for _port in range(PORT, PORT + 10):
    try:
        _s = ServerSocket()
        _s.setReuseAddress(True)
        _s.bind(InetSocketAddress("127.0.0.1", _port))
        server = _s
        PORT = _port
        break
    except:
        try:
            _s.close()
        except:
            pass
if server is None:
    raise Exception("no hay puertos libres entre %d y %d" % (PORT, PORT + 9))
server.setSoTimeout(1000)
print("Server listening on 127.0.0.1:%d" % PORT)
print("Commands: HELP, CURRENT, FUNC, DECOMP, XREF, XFROM, STR, WSTR, BYTES, DECOMP_XREF, TRACE, MAKEFUNC, RENAME_FUNC, RENAME_SYMBOL, RENAME_LABEL, RENAME_LOCAL, IMPORTXREF, NEARSTR, QUIT")
print("Parar: Cancel del script en Ghidra (revisa cada 1s) o mandar 'QUIT'.")

running = True
while running:
    if is_cancelled():
        print("monitor cancelado -> apagando server")
        break
    client = None
    writer = None
    try:
        client = server.accept()
    except SocketTimeoutException:
        continue
    except Exception:
        if is_cancelled():
            break
        continue
    try:
        reader = BufferedReader(InputStreamReader(client.getInputStream()))
        writer = PrintWriter(client.getOutputStream(), True)
        line = reader.readLine()
        if line is not None and line.strip().upper() in ("QUIT", "SHUTDOWN", "STOP", "EXIT"):
            writer.println(json.dumps({"ok": True, "shutdown": True}))
            running = False
        else:
            result = handle(line)
            writer.println(json.dumps(result))
    except:
        # bare except A PROPOSITO: `except Exception` de Jython NO atrapa las
        # excepciones de Java -> escapaban del loop, el script moria y el
        # server.close() del final nunca corria (puerto ocupado hasta reiniciar Ghidra).
        try:
            if writer:
                writer.println(json.dumps({
                    "ok": False,
                    "error": traceback.format_exc().splitlines()[-1],
                    "trace": traceback.format_exc()
                }))
        except:
            pass
    finally:
        if client:
            try:
                client.close()
            except:
                pass

try:
    server.close()
except:
    pass
print("=== GHIDRA SERVER V2 STOPPED (puerto liberado) ===")
