# Triage report: `0202553cca2144d8…`

**Verdict:** suspicious (confidence low) · **Risk:** low

- SHA-256: `0202553cca2144d89f77092d7b5c5a775a4a3ff46541e178e3044902fcd6ff2f`
- MD5: `f8f66658c3b52ae3df30c1af620ff4c2` · SHA-1: `785088c95d8ae98b85cbad6a8cb69b845209d224`
- Size: 14,400 bytes · elf x86 64-bit

## Summary

Stripped binary with 1 function(s) that XOR-decode data at runtime. The routine at 0x1149 with key 0x5a recovers 'http://c2.example.invalid/gate.php' from 0x2020, called from 0x11cf. Network-related imports: none observed.

## Behaviors

- **Runtime decoding of an obfuscated string (single-byte XOR)** (medium) · T1140 · `0x1149`
  - evidence: 0x1149 contains a loop with a non-zeroing XOR (renamed xor_decode_routine)
  - evidence: xor_bruteforce at 0x2020: key 0x5a -> 'http://c2.example.invalid/gate.php'
  - evidence: caller 0x11cf references 0x2020 and calls 0x1149

## Indicators

- url: `hxxp://c2[.]example[.]invalid/gate[.]php` - decoded with key 0x5a from data at 0x2020
- domain: `c2[.]example[.]invalid` - decoded with key 0x5a from data at 0x2020

## Obfuscation

- single-byte XOR string encoding (key 0x5a)

## Limitations

- Produced by the offline heuristic policy (not a language model): it only recognizes single-byte XOR decode loops. No finding does not mean benign.
- Static analysis only; nothing was executed and no network lookups were made.
- Pseudo-code fidelity is low; conclusions rely on disassembly and decoded bytes.

## Recommendations

- Validate the decoded indicator against threat intelligence before blocking.
- Run with an LLM backend (--llm openai) to characterize the rest of the program.

## Analysis metadata

retriage 0.1.0 · backend radare2 · model/policy `heuristic-offline-policy` · 17 steps · 17 tool calls
- renamed: `fcn.00001149` → `xor_decode_routine`

_Static analysis only; indicators are defanged. Verify before acting._
