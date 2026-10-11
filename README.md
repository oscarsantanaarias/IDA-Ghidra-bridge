# IDA-Ghidra-bridge

Lightweight TCP JSON bridge servers for **IDA Pro** and **Ghidra** that expose reverse-engineering workflows over a simple socket protocol.

Allows external tools, CLI scripts, Python utilities, and automated pipelines to query decompilation, xrefs, symbols, virtual tables, RTTI, structures, and patch memory without manual GUI interaction.

---

## Architecture & Lifecycle

### 1. Dynamic Port Binding & Multi-Instance Support
When working on large reversing projects with multiple binaries open at the same time (e.g. game client, launcher, DLL proxies, and stubs simultaneously):
- The servers do **not** crash if a port is already taken.
- The server starts scanning at **`BASE_PORT = 5073`** and automatically probes sequential ports (`5073`, `5074`, `5075`, `5076`...) until it finds an available one.
- Each IDA or Ghidra window binds to its own port independently without conflicts.

### 2. Hot-Reloading & Clean Re-Execution
In IDA Pro, the Python interpreter remains alive across multiple script executions:
- `ID_Server.py` registers the running server handle into `builtins._ida_bridge_prev`.
- If you re-run or reload the script in the same IDA instance, it automatically invokes `stop()` on the previous instance and joins its thread (`join(3.0)`), cleanly releasing the port before starting the new server.
- You never get `Address already in use` or orphaned threads from re-running the script.

### 3. Graceful Shutdown
- **Via Socket**: Send `QUIT`, `STOP`, `EXIT`, or `SHUTDOWN` through the connection. The server confirms with `{"ok": true, "shutdown": true}` and closes immediately.
- **In IDA Pro**: Call `ida_bridge_stop()` directly from the IDA Python CLI, or simply close IDA (daemon threads exit automatically).
- **In Ghidra**: Click the red Cancel button in Ghidra's Script Manager (`is_cancelled()` is checked every 1s via socket timeout), or send `QUIT`.

---

## Installation & Setup

### IDA Pro
1. Open your target database (`.idb` / `.i64`) in IDA Pro.
2. In the IDA Python CLI (or via `File -> Script file...` / `Alt+F7`), execute:
   ```python
   import ID_Server
   ```
3. The server starts listening on `127.0.0.1:5073` (or the next available port).
4. To stop the server manually:
   ```python
   ida_bridge_stop()
   ```

### Ghidra
1. Open your target program in Ghidra CodeBrowser.
2. In the **Script Manager** (`Window -> Script Manager`), add the folder containing `Ghidra_Server.py` or run it directly in the Python interpreter.
3. The server binds to `127.0.0.1:5073` (or next free port).

---

## Complete Command Reference (All 39 Commands)

Commands are plain newline-delimited strings sent over TCP (`127.0.0.1:<PORT>`). The server replies with a JSON object (or tab-delimited text for legacy commands).

### 1. Navigation & Inspection

| Command | Syntax | Description |
|---|---|---|
| `PING` | `PING` | Health check. Returns `"pong"`. |
| `CURRENT` | `CURRENT` | Returns the current cursor address, function name, size, assembly instructions, and decompiled code. |
| `NAME` | `NAME <ea>` | Returns the symbol/function name defined at `<ea>`. |
| `FUNC` | `FUNC <addr>` | Returns full function metadata, entry point, size, signature, assembly, and Hex-Rays/Ghidra decompilation. |
| `DECOMP` | `DECOMP <addr>` | Alias for `FUNC`. Decompiles the target function. |
| `DISASM` | `DISASM <ea> [n]` | Returns disassembly lines for `[n]` instructions starting from `<ea>` (default: 40). |
| `FIND` | `FIND <substr>` | Case-insensitive search across all symbols and function names matching `<substr>` (up to 300 matches). |
| `EXPORT` | `EXPORT [filename]` | Exports all non-dummy symbols, mangled and demangled names to a text file (default: `ida_names.txt`). |
| `HELP` | `HELP` | Returns a JSON list of all available commands supported by the server. |
| `QUIT` | `QUIT` | Gracefully closes the client connection and stops the bridge server socket. |

### 2. Cross-References & Call Graph

| Command | Syntax | Description |
|---|---|---|
| `XREF` | `XREF <addr>` | Lists all incoming cross-references (code calls, data reads/writes) targeting `<addr>`. |
| `XFROM` | `XFROM <addr>` | Lists all outgoing cross-references originating from `<addr>`. |
| `CALLERS` | `CALLERS <addr>` | Filters incoming references to return **only call sites** (including resolved indirect calls). |
| `READERS` | `READERS <addr>` | Filters incoming references to return only instructions that **read** from `<addr>`. |
| `WRITERS` | `WRITERS <addr>` | Filters incoming references to return only instructions that **write** to `<addr>`. |
| `DECOMP_XREF` | `DECOMP_XREF <addr>` | Batch-decompiles every calling function of `<addr>` in a single request. |
| `IMPORTXREF` | `IMPORTXREF <name>` | Locates all call sites throughout the entire binary for an imported Windows/C API (e.g. `IMPORTXREF WSASendTo`). |
| `TRACE` | `TRACE <addr>` | Traces the execution flow and basic blocks surrounding `<addr>`. |

### 3. Pointers, Memory & Structures

| Command | Syntax | Description |
|---|---|---|
| `READPTR` | `READPTR <addr> [count]` | Reads memory as pointer chains (32-bit or 64-bit) and classifies each target (`func`, `string`, `vtable`). |
| `FINDPTR` | `FINDPTR <addr>` | Scans global data and tables to find any pointer referencing `<addr>` (finds vtables, dispatch tables). |
| `STRUCT` | `STRUCT <addr> [n]` | Heuristically dumps contiguous memory interpreting fields as ints, floats, pointers, and strings. |
| `DEFSTRUCT` | `DEFSTRUCT <name> [size]` | Creates a new named structure in the database type library. |
| `SETFIELD` | `SETFIELD <struct> <off> <type> [name]` | Defines or modifies a structure field at `<off>` with `<type>` and optional field name. |
| `MKPTRS` | `MKPTRS <addr> [count]` | Converts raw database bytes into typed pointers in bulk. |
| `NEARSTR` | `NEARSTR <addr>` | Finds string references located nearby in code or data sections within range. |

### 4. Virtual Tables & RTTI

| Command | Syntax | Description |
|---|---|---|
| `VTABLE` | `VTABLE <funcaddr>` | Identifies which virtual tables contain `<funcaddr>`, including neighboring method slots. |
| `VTDUMP` | `VTDUMP <addr> [count]` | Dumps an entire virtual table: resolves each slot to its method name, offset, and index. |
| `RTTI` | `RTTI <addr\|Name>` | Traverses MSVC C++ RTTI structures (`TypeDescriptor` -> `CompleteObjectLocator` -> `vftable`) to resolve class hierarchies and base classes. |

### 5. String & Byte Scanning

| Command | Syntax | Description |
|---|---|---|
| `STR` | `STR <ascii>` | Searches for ASCII strings across all loaded segments. |
| `WSTR` | `WSTR <utf16>` | Searches for UTF-16 wide strings across all loaded segments. |
| `BYTES` | `BYTES <hex>` | Searches for raw opcode or data byte sequences (e.g. `BYTES 55 8B EC 83 EC`). |

### 6. Database Modification & Typing

| Command | Syntax | Description |
|---|---|---|
| `RENAME_FUNC` | `RENAME_FUNC <addr> <name>` | Renames the function at `<addr>` to `<name>`. |
| `RENAME_SYMBOL` | `RENAME_SYMBOL <addr> <name>` | Renames a global data symbol or variable. |
| `RENAME_LABEL` | `RENAME_LABEL <addr> <name>` | Renames a code label or jump target. |
| `RENAME_LOCAL` | `RENAME_LOCAL <func> <old> <new>` | Renames a local variable inside the decompiler view. |
| `RETYPE` | `RETYPE <func> <var> <type>` | Modifies the data type of a variable or parameter inside the decompiler (e.g. `RETYPE 00401000 a1 Player*`). |
| `SETCONV` | `SETCONV <func> <convention>` | Sets calling convention (`__cdecl`, `__stdcall`, `__fastcall`, `__thiscall`). |
| `MAKEFUNC` | `MAKEFUNC <addr>` | Forces creation of a function boundary at `<addr>`. |
| `PATCH` | `PATCH <addr> <hex>` | Directly overwrites bytes in the database (e.g. `PATCH 00401234 90 90`). |
| `PCODE` | `PCODE <addr>` | Dumps Hex-Rays Microcode or Ghidra P-Code intermediate representation for deep compiler analysis. |

---

## Python Client Example

```python
import socket
import json

class BridgeClient:
    def __init__(self, host="127.0.0.1", port=5073):
        self.host = host
        self.port = port

    def send(self, cmd: str) -> dict:
        s = socket.socket()
        s.connect((self.host, self.port))
        s.sendall((cmd + "\n").encode("utf-8"))
        
        chunks = []
        while True:
            chunk = s.recv(16384)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        s.close()
        
        raw = b"".join(chunks).decode("utf-8", errors="ignore").strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}

# Example usage:
client = BridgeClient(port=5074)

# Decompile target function
res = client.send("FUNC 007B11C0")
if res.get("ok"):
    print("Function Name:", res.get("function_name"))
    print(res["code"][:300])

# Trace incoming callers
callers = client.send("CALLERS 007B11C0")
print("Total callers:", callers.get("count"))
```

---

## License

MIT

