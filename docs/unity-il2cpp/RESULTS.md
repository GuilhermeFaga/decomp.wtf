# F0 — Resultados dos spikes (decomp.wtf × Unity IL2CPP)

> ⚠️ **PRIVADO**: contém detalhes de análise do cliente Apogea (builds, endereços, nomes).
> **Sanitizar antes de qualquer push/PR upstream.**

Data: 2026-10-14 · Spike de viabilidade do plano `docs/unity-il2cpp-plan.md`.

## Veredito

**O caminho é viável e já validado de ponta a ponta** — sem nenhuma modificação no decomp.wtf:

| # | Spike | Resultado |
|---|---|---|
| S0 | Projeto objdiff aberto como fork no app (zero patch) | ✅ clone local → `kind=objdiff` → `check` mediu: `0/3 functions, fuzzy 49.4%`, listado como `win32`/“Windows PC” |
| S1 | objdiff-cli 3.8.2 × COFF x86-64 (clang) | ✅ `diff`/`report` com % por símbolo e rows por instrução |
| S2 | Inventário unificado (`.pdata` + mapa de símbolos) | ✅ **135.954** funções `.pdata`; **53.063/63.520** métodos com start exato; funções conhecidas das sessões validam |
| S3 | Draft x86 via Ghidra (decomp já tem `forks/ghidra.py`) | ⏳ pendente (baixo risco; Ghidra 12.1.4 presente) |
| S4 | Delink mínimo + diff real (alvo COFF sintético com relocs) | ✅ 3/3 funções comparadas: 39.75% / 36.0% / 64.4% (clang × MSVC) |
| S5 | Proximidade clang-cl × MSVC (20 funções) | ⏳ pendente (depende da decisão sobre toolchain MSVC) |

## Evidências-chave

### Builds (⚠️ são DOIS builds diferentes!)

| | `game-real/` (alvo do RE) | `Games/Apogea Playtest/` |
|---|---|---|
| Unity | **2021.3.45f2** | 2021.3.38f1 |
| Build (timestamp PE) | 2026-08-02 | 2025-08-05 |
| Toolset (Rich header) | VS2022 17.10/17.11/17.12 (33145/35721/36243), linker 14.51 | VS2019 16.11 + VS2022 17.2/17.3, linker 14.29 |
| PDB (RSDS) | `…\apogea-unity\…\6h2wl\GameAssembly.pdb` | `…\apogea-closed\…\y2vqe\GameAssembly.pdb` |
| Tamanho DLL | 42,8 MB | 14,4 MB |
| Símbolos/metadata | **mapa em `dumps/decomp/` (decryptor da sessão 7)** | sem mapa (header de proteção é por build) |

**O mapa de símbolos só vale para o `game-real`.** O `Games/Apogea Playtest` (mais antigo) precisaria de
re-extração (o `HEADER_HEX` do decryptor é por build).

### Estrutura do `game-real/GameAssembly.dll`

- Seções: `il2cpp` (27,7 MB — código gerado dos métodos), `.text` (3,4 MB — engine/runtime), `.rdata`,
  `.data`, `.pdata` (1,6 MB), `.fptable`, `.reloc`.
- **`.pdata`: 135.954 funções** (113.168 em `il2cpp`, 22.786 em `.text`) — boundaries exatos, de graça.
- **53.063 dos 63.520 RVAs** de `methods_final.json` caem exatamente em starts de `.pdata`
  (`Setup` = 0x1a9e30..0x1aa563 — os endereços internos das notas cont. 599-604 caem dentro ✓);
  os ~10.457 restantes = leaf/thunks sem unwind info.
- **Fragmentos frios**: parte das entradas `.pdata` sem nome são *stubs de throw* (ex.: o “próximo” após
  `set_Mode` em 0xc5bbf4 = `mov [rsp+0x30],rbx; lea rcx,[rip+…]`): branches “para fora do span” são
  jump-para-fragmento; o agrupamento do import precisa associá-los ao parent (F2).
- `.reloc`: ~94k DIR64 (mapa de ponteiros embutidos) — insumo para data symbols.

### Pipeline S4 (o teste crítico)

1. `docs/unity-il2cpp/s4_delink.py` — lê o inventário, sintetiza objeto-alvo COFF por função:
   bytes do `.text` + símbolo + relocs REL32 (calls/jmps e `[rip+disp]` via capstone), campo de reloc
   **zerado** (convenção de objeto pré-link — igual ao compilador).
2. `clang --target=x86_64-pc-windows-msvc -O2 -c` no C escrito à mão (nomes sanitizados `Mod_Classe_Metodo`).
3. `objdiff-cli diff -1 target.obj -2 base.obj` → match % + rows (DIFF_INSERT/DELETE/REPLACE/ARG_MISMATCH),
   relocs resolvidas por símbolo (`call sub_1d57f60`, `jmp sub_1d0b5e0`) ✓.

Scores do spike: **39.75%** (0x1aa0 `ChatHoverDetector::OnPointerEnter` — reloc + bloco frio),
**36.0%** (0xe40ba0 `Thread::Sleep` — tail-call), **64.4%** (0x1060 ctor — spill+call).
Os gaps são os esperados clang×MSVC (clang salva em `rsi/rdi`, MSVC em `rbx`/home slots; frames 0x20×0x28) —
exatamente o que a fase F4 (MSVC via wine) ataca; **o pipeline em si está provado**.

### S0 (zero patch) — como foi feito

- Repo local `/tmp/opencode/decomp-unity/proj` (git) com `objdiff.json` + `target/*.obj` + `base/*.obj` + `src/*.c`.
- API do app (cookie `~/Decomp/.decomp/server.json` + `X-Decomp: 1`):
  `POST /api/fork {"repo": "<path>", "platform": "win32"}` → `POST /api/fork/check {"slug": "unity-spike"}`.
- Resultado: projeto `unity-spike` no app, plataforma “Windows PC”, `ready=true`, 3 funções, fuzzy 49.4%.
- **Conclusão**: a integração com o decomp pode ser toda pelo caminho fork/objdiff existente; o trabalho
  pesado é o *gerador* (inventário + objetos-alvo + `objdiff.json` + `context.h`), não o core do app.

## Reprodução

```bash
PY=/home/faga/.local/share/uv/tools/decompnet/bin/python
cd /tmp/opencode/decomp-unity
$PY docs/unity-il2cpp/s2_inventory.py --dll /home/faga/Documents/apogea-rea/game-real/GameAssembly.dll
$PY docs/unity-il2cpp/s4_delink.py 1aa0 e40ba0 1060      # gera s4/target_*.obj
# base C em s4/base_*.c → clang --target=x86_64-pc-windows-msvc -O2 -c
OD=~/.local/share/decompnet/toolchains/objdiff-cli/objdiff-cli
$OD --no-color diff -1 s4/target_1aa0.obj -2 s4/base_1aa0.obj -c functionRelocDiffs=none -o - --format json
```

## Pendências do F0

- **S3**: draft Ghidra num objeto sintético (verificar `forks/ghidra.py` com x86-64 — o caminho já existe).
- **S5**: medir clang×MSVC em ~20 funções (precisa da decisão sobre a toolchain MSVC).
- **Decisões do plano (§7)**: fork upstream × branch local; aceitar MSVC proprietário; escopo do MVP
  (`Assembly-CSharp` × DLL inteira); iniciar F1.
