# Tool reference

_Generated from `src/retriage/tools.py` by `scripts/gen_docs.py`; do not edit by hand._

All tools are read-only against the sample. `rename_function` and `add_comment` modify only the analysis database. Every result is wrapped as `{ok, _notice, data}` where `data` is **untrusted** content from the binary.

| Tool | Arguments | What it does |
|---|---|---|
| `get_binary_info` | - | File hashes, size, format, architecture, bitness, stripped/PIE/NX flags. |
| `get_sections` | - | Sections with virtual address, size, permissions and Shannon entropy (>7.0 suggests packing/encryption). |
| `list_functions` | `limit`?, `name_filter`? | Functions found by analysis (address, name, size, basic blocks, kind=function|import|entry). Renamed functions appear with their new names. |
| `get_imports` | - | Imported functions and libraries. |
| `get_strings` | `min_len`?, `limit`?, `pattern`? | Strings found in the file with addresses. Use pattern (regex) to narrow. |
| `get_disassembly` | `target`, `max_lines`? | Disassembly of the function containing target (or of the address if not in a function). |
| `get_pseudocode` | `target`, `max_lines`? | Approximate pseudo-C for the function (radare2 'pdc': LOW fidelity, always cross-check the disassembly). |
| `get_xrefs_to` | `target` | Code/data references to target, with the function containing each reference. |
| `get_callees` | `target` | Functions called by the function containing target (call graph, one level). |
| `read_bytes` | `target`, `length`? | Read up to 256 bytes at an address (hex + printable preview). |
| `xor_bruteforce` | `target`, `length`? | Try all single-byte XOR keys on the bytes at an address (stops at the first NUL byte) and return readable candidates. Use on suspected encoded strings. |
| `rename_function` | `target`, `new_name` | Rename a function in the analysis database once you understand it (e.g. 'xor_decode_routine'). Renames appear in callers' disassembly, so later analysis becomes easier. |
| `add_comment` | `target`, `text` | Attach a short note to an address in the analysis database. |
| `submit_report` | `report` (see [report schema](../schemas/submission.schema.json)) | Finish the analysis. Provide verdict, summary, behaviors (each with evidence citing addresses/tool results), iocs, obfuscation, limitations (required), recommendations. Hashes and metadata are added automatically. |

`?` marks optional arguments. `target` accepts a symbol name (`[A-Za-z_.][A-Za-z0-9_.]*`) or a `0x` hex address; anything else is rejected.
