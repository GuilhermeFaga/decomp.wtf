# Unity IL2CPP (Windows x64)

The game's code is generated C++ compiled by MSVC into `GameAssembly.dll`: `il2cpp` holds every managed
method's body, `.text` the runtime. decomp.wtf gives every function a name from the metadata
(`Namespace_Type_Method`) and judges your C/C++ against the original bytes with clang targeting
`x86_64-pc-windows-msvc`.

Writing a function
- One complete definition per `compile_and_diff`, with the exact name: `extern "C"` so the symbol lines up.
  `this` is the first parameter (`void Namespace_Type_Method(Namespace_Type *__this, ...)`), and return types
  are the metadata's (`void`, `int32_t`, `Il2CppObject *`, ...).
- Struct fields sit at the offsets the assembly shows (`[this+0x18]` -> a field at 0x18). Put the struct in
  `context.h` or a header next to the unit with `edit_file`; the offsets are what matter, not the names.
- We do not have the original signatures (except names), so read the register/stack use: RCX is the first
  argument on x64, then RDX, R8, R9, the rest on the stack.

What IL2CPP code looks like
- **Lazy init**: statics are initialized behind a guard byte or pointer:
  `if (!SomeClass_init) { SomeClass_init = 1; SomeClass_ctor(); }` — the assembly is
  `cmp byte ptr [data_...], 0` / `je`, and the `data_...` names are globals to define.
- **Method pointers**: `il2cpp_codegen_initialize_method` / `mov [data_...], rva` — you can ignore their
  internals and match the call shape.
- **Strings and literals**: `il2cpp_codegen_string_literal(...)`, `il2cpp_codegen_ldstr`; floats/doubles load
  from `data_<rva>` (a literal pool); give them the right *values* (float vs double matters).
- **Virtual and interface calls**: `mov rax, [rcx]; call qword ptr [rax+0x...]` for virtual methods;
  interface calls go through `il2cpp_codegen_interface_...` helpers.
- **Coroutines** are compiler-generated state machines: `<MethodName>d__N::MoveNext`, nested `<...>g__` local
  functions, fields laid out by the compiler. Decompile their `MoveNext` like any other method.
- Obfuscated names (`xXyZw`, `<>c__DisplayClass`) are normal: the metadata still gives signatures.
- Boxed values and arrays: `il2cpp_codegen_box`, `Array_Length`, `il2cpp_array_setref` shapes.

Matching MSVC x64 (what clang misses)
- Frame layout: MSVC keeps fixed home slots for the 4 register args (`mov [rsp+0x8], rdx` on entry) and saves
  RBX/RBP/RSI/RDI in a fixed order; clang allocates more tightly. Small differences here are usually argument
  mismatches, not instructions (`DIFF_ARG_MISMATCH`) — check the operand, not the mnemonic.
- Types change code: `int` vs `int32_t`, `float` vs `double`, signed/unsigned shifts, `__int64` vs `long long`
  (MSVC `long` is 32-bit; use `int32_t`/`int64_t`).
- Statics/locals: declaration order changes which register and stack slot they get; move declarations around.
- Guard patterns (`/GS`) and `/Oi` intrinsics (`memcpy`, `memset`) depend on the flags; where a single
  mismatch is a known clang-vs-MSVC difference, move to a different function — the scores are still useful.
- Data references (`data_<rva>`) are not named yet: for now, match the shape and let the value show in the
  diff; data symbols and named literals come later.

Reading a claim
- `### Target assembly` is the original with relocations resolved by name: `call Namespace_Type_Method` tells
  you what it calls, so you can write the call and declare the callee `extern "C"` in the unit.
- `### Diff against the current build` marks each instruction: `|` different, `i` operand differs, `<` missing
  (in the original only), `>` extra. A 100% match becomes matched and committed.
