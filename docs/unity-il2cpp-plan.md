# Plano — Suporte a Unity (IL2CPP) no decomp.wtf

> ⚠️ **PRIVADO**: este documento contém detalhes de análise do cliente Apogea (builds, endereços,
> nomes do metadata). **Sanitizar antes de qualquer push/PR upstream** (ou manter o branch privado).
> Regra do projeto de origem: nunca publicar conteúdo do cliente.

- Data: 2026-10-14 (sessão 7 cont. 604)
- Status: **proposta** (nenhuma modificação feita ainda)
- Objetivo deste doc: definir como estender o decomp.wtf para importar builds **Unity IL2CPP (Windows x64)**
  como plataforma de primeira classe, reutilizando a arquitetura de *forks* existente, para decompilar o
  cliente Apogea com agentes e alimentar o RE do servidor local.

---

## 1. Objetivo e escopo

**Objetivo:** `decomp.wtf` passa a aceitar a pasta de um jogo Unity (ex.: `/home/faga/Games/Apogea Playtest/`)
e cria um projeto decomp com:

- inventário de funções (métodos gerenciados do metadata + código de engine via `.pdata`),
- nomes e assinaturas vindos do metadata (diferencial enorme vs decomps de console),
- loop agentic existente: `claim_function` → draft → `compile_and_diff` → matched/percentual,
- `context.h` auto-gerado (structs, campos, protótipos) e `export_project` = árvore de fontes.

**Sucesso do MVP:** abrir o Apogea no app, agentes decompilando `Assembly-CSharp.dll` (lógica do cliente —
rede/login/zona/player) com diffs por função e percentual de similaridade visível. **Meta aspiracional:**
funções byte-exatas com a toolchain MSVC original; o valor real está na decompilação legível + verificada
por diff, não em reproduzir o DLL inteiro.

**Não-objetivos:** rebuild byte-a-byte do DLL completo; redistribuir código do jogo (export é local, `orig/`
fica fora); suportar Unity sem IL2CPP (Mono é outro problema); portar o cliente.

---

## 2. Estado atual (evidência levantada)

### 2.1 decomp.wtf (decompnet 0.9.8, MIT, `github.com/i12bp8/decomp.wtf`)

- Instalado em `~/.local/share/uv/tools/decompnet/` (wheel `decompnet-0.9.8`), CLI `/home/faga/.local/bin/decomp`.
  **Open source (MIT) → fork/branch/PR são o caminho** (patch em site-packages é só spike).
- Import atual: `app/engine.py:296` `import_rom()` → `app/engine.py:426` `_community_layout()` reconhece
  dtk/dsd (GC/Wii/DS) → `app/forkengine.py:298` `create_scratch()` gera o layout da comunidade e registra
  como **fork** (`kind=fork`, `platform`, `program_sha1`, `legal={personal-copy}`). Qualquer outra coisa cai em
  `rom/detect.py` (`n64|psx|ps2|gba`) e falha com "isn't a ROM, disc or game program this app can read".
- **Forks genéricos já suportam qualquer projeto com `objdiff.json`** (`forks/project.py` docstring: layouts
  `manifest` (`.decomp.wtf.json` com `game` + `setup`), dtk, configure, splat; "Everything else (CMake,
  justfiles, custom scripts) … once the build has produced objdiff.json, decomp.wtf takes over").
- Fluxos de fork na UI/servidor já existem: `/api/fork` (clone de repo), `/api/fork/setup` (aponta/sobe o
  arquivo do jogo do usuário, com confirmação de cópia própria), `/api/fork/check` (mede `objdiff.json`),
  `/api/fork/start-files`, `/api/fork/needs` (`app/server.py:464-565`).
- **`objdiff-cli` 3.8.2 (pinned, `toolchains.toml`) já suporta x86-64/COFF**: strings do binário mostram
  `X86_64`, `IMAGE_REL_AMD64_REL32(_1.._5)`, `ADDR64/ADDR32NB/SECREL`, iced-x86, `fuzzy_match_percent`,
  "Invalid COFF/PE section headers". **O juiz existe; falta gerar os alvos.**
- **Drafts x86 já implementados**: `forks/ghidra.py` ("decompiled C for platforms m2c doesn't read (x86, …)")
  — agentes ganham draft via Ghidra headless no modo fork.
- Registro de toolchains com precedente para **proprietários** (`license="proprietary"`,
  `--accept-license`): IDO, MWCC, "Xbox 360 MSVC". Há **wibo** ("runs the old Windows compilers … MSVC on
  Linux") e o catálogo já tem `"win32": "Windows PC"` (`forks/catalog.py`) — forks win32 são conceito existente.
- **Mudanças de core necessárias são pequenas**: detecção/registro da plataforma + maker do scratch.
  Todo o resto (claim/draft/build/diff/report/export) é o caminho de fork já existente.

### 2.2 O alvo (⚠️ são DOIS builds diferentes)

| | `game-real/` — **o alvo do RE** | `Games/Apogea Playtest/` |
|---|---|---|
| Unity | **2021.3.45f2** | 2021.3.38f1 |
| Build (timestamp PE) | 2026-08-02 | 2025-08-05 |
| Toolset (Rich header) | VS2022 17.10/17.11/17.12 (builds 33145/35721/36243), linker 14.51 | VS2019 16.11 + VS2022 17.2/17.3, linker 14.29 |
| PDB (RSDS) | `…\apogea-unity\…\WinPlayerBuildProgram\6h2wl\GameAssembly.pdb` | `…\apogea-closed\…\y2vqe\GameAssembly.pdb` |
| DLL | 42,8 MB | 14,4 MB |
| Símbolos | **mapa em `dumps/decomp/` (decryptor da sessão 7)** | sem mapa (proteção é por build) |

- **O mapa de símbolos só vale para o `game-real`** (`HEADER_HEX` do decryptor é por build; o copy do
  `Games/` precisaria de re-extração). Todo o F0 usou o `game-real`.
- Estrutura do `game-real/GameAssembly.dll`: seções `il2cpp` (27,7 MB — código gerado dos métodos),
  `.text` (3,4 MB — engine/runtime), `.rdata`, `.data`, `.pdata` (1,6 MB), `.fptable`, `.reloc`.
- **`.pdata` = 135.954 funções** (113.168 em `il2cpp`, 22.786 em `.text`): boundaries exatos de graça,
  incluindo código sem símbolo. **53.063 dos 63.520 RVAs** de `methods_final.json` são starts exatos
  (os ~10.457 restantes = leaf/thunks sem unwind). Parte das entradas sem nome são **fragmentos frios**
  (stubs de throw) — branches "para fora do span" apontam para eles; o import precisa agrupá-los (F2).
- `.reloc`: ~94k DIR64 (mapa de ponteiros embutidos) — insumo para data symbols.
- `global-metadata.dat` **protegido** (magic padrão ausente) — proteção **já revertida** (sessão 7) com
  pipeline offline (`scripts/apogea_symbol_dump.py`): `dumps/decomp/methods_final.json` (**91.057 métodos,
  63.520 RVAs**, `Assembly-CSharp.dll` com 6.059) + `symbols.txt` (63.519 nomes). Ferramentas presentes:
  Il2CppDumper v6.7.46, .NET 8, pyghidra, Ghidra 12.1.4, wine prefix do projeto.

> **F0 executado em 14/10** — resultados e evidências completas em `docs/unity-il2cpp/RESULTS.md`:
> S0/S1/S2/S4 **PASSOU** (fork x86-64 no app sem patch; objdiff x86-64 ok; inventário validado; delink +
> diff real com relocs); S3/S5 pendentes. Scripts: `docs/unity-il2cpp/{s2_inventory,s4_delink}.py`.

---

## 3. Desenho da extensão

### 3.1 Opções avaliadas

- **A — scratch Unity espelhando `scratch_dtk`/`scratch_dsd` (recomendada).**
  Novo maker `forks/scratch_unity.py` + hook em `_community_layout`/`import_rom` + entradas de toolchain.
  Tudo depois roda no **fork engine existente** (objdiff report, edit_file, drafts Ghidra, notes, export).
- **B — plataforma nativa "rom-like"** (detect/split/scoring/export dedicados). Mais invasiva; só se o fork
  engine não atender (ex.: se objdiff x86-64 tiver lacunas nos spikes). Fallback, não primeira opção.
- **C — zero patch: gerar o projeto à parte e abrir como fork** (git local / manifest). Melhor *primeiro
  experimento* (valida tudo sem tocar no decomp), mas não dá o fluxo `import direto da pasta` do MVP.

### 3.2 Pipeline alvo (MVP)

```
import pasta Unity ──► scratch_unity.create()
   ├─ orig/GameAssembly.dll + global-metadata.dat (sha1 pinado; fica fora do export)
   ├─ tools/il2cppsplit.py     gerador do projeto (roda 1×, repetível)
   ├─ src/<modulo>/<arquivo>.cpp   esqueletos por unidade (agentes escrevem aqui)
   ├─ include/context.h        structs + campos + protótipos (auto, do metadata)
   ├─ objdiff.json             unidades {target_path, base_path, source_path}
   ├─ build.ninja              clang-cl (default) ou MSVC-under-wine (exato)
   └─ .decomp.wtf.json         manifest (game/path/sha1 + setup)  ← layout já suportado
                     │
 agentes: claim_function ──► asm (iced/capstone) + draft Ghidra + assinatura do metadata
                     │        escrevem C/C++ ──► build ──► objdiff (match% + fuzzy%)
                     ▼
 update /api/fork/check ──► report no app (progresso, matched, notas, export)
```

Componentes:

1. **`forks/scratch_unity.py`** (novo): `is_unity(pasta|dll)`, `game_info()` (título, Unity version de
   `app.info`/`globalgamemanagers`, sha1 do GameAssembly.dll), `create(dest, game)` → gera o projeto e devolve
   `facts {platform:"win32", id, compiler, title}`. Entra em `forkengine.create_scratch()` como terceiro maker
   (ao lado de `scratch_dtk`/`scratch_dsd`).
2. **`forks/il2cppsplits.py`** (novo, o coração):
   - **inventário**: métodos do metadata (parser padrão Il2CppDumper-compatible v24–v31; sem dispor de
     decryptor — ver §4) **ou** `--symbols map.json` (Apogea: `dumps/decomp/methods_final.json` +
     `symbols.txt`); **+ `.pdata`** para TODAS as 48k funções (nome `func_<rva>` quando sem símbolo).
   - **grupos/unidades**: managed = por `mod` (assembly) + chunk (~100–200 funções/arquivo); engine = clusters
     de `.pdata` com nomes do mapa do repo (`symbols.txt`).
   - **objetos-alvo COFF sintéticos**: `.text` do range + symbol table (nomes reais) + relocações reconstruídas
     — DIR64 do `.reloc` + varredura de `E8/E9 rel32` e `[rip+disp]` (capstone, já é dependência do decomp)
     → símbolos `data_<rva>` (94k entradas DIR64 = catálogo inicial de dados).
   - **`objdiff.json`** com `arch x86_64` (validar chave exata no spike S1) + `symbol_mappings` de dados.
   - **`context.h`**: structs dos tipos do metadata (layout Il2CppClass, campos por offset), enums, protótipos
     com a assinatura real (`Nome::Metodo` → `Nome_Metodo`), typedefs — gera valor direto para os agentes.
   - **build**: `clang-cl` (LLVM toolchain pinned; `toolchains.toml`) com flags aproximadas do IL2CPP
     (`/O2`, `/GS-`, `/std:` etc. — calibrar no spike S5); opção MSVC exato na F4.
3. **Hook no core** (~50 linhas): `app/engine.py` `import_rom/_community_layout` reconhece pasta Unity →
   `forks.create_scratch()` (maker novo) → registra fork com `platform="win32"` (nome "Windows PC" já no
   `catalog.PLATFORMS`), `program_sha1` = sha1 do GameAssembly.dll, `legal` = cópia própria. `detect.PLATFORMS`
   ganha a entrada p/ exibição. Guia novo em `app/guide/` (`il2cpp`: padrões do código gerado, method pointers,
   ICs, uso do context.h).
4. **Juiz**: `objdiff-cli` 3.8.2 existente. Match = 100% com `REPORT_OPTIONS` atuais; senão `fuzzy%`.
   *Fallback* (se o spike mostrar lacunas em x86-64): matcher próprio estendendo a lógica de `rom/match.py`
   (link aritmético das relocs + compare com capstone) — já há `similarity.py`/`datadiff.py` para reuso.
5. **Toolchains** (`toolchains.toml`):
   - `llvm-clang-cl` (release oficial LLVM, Apache-2.0 c/ exceção) — default do MVP.
   - `msvc-19.29 / 19.32 / 19.33 via wine` (proprietário, `--accept-license`, precedente IDO/MWCC; empacotar
     com msvc-wine; usar o wine já existente do projeto) — F4, para match exato.
   - wibo continua disponível para MSVC antigo, se algum alvo pedir.

---

## 4. Separação de responsabilidades (privacidade/proteção)

O decryptor do metadata do Apogea **fica no repo `apogea-rea`** (nunca vai ao decomp, que é público):
o `il2cppsplit` consome apenas um **mapa nome→RVA** (`methods_final.json`/`symbols.txt`) via `--symbols`.
Para jogos Unity sem proteção, o parser padrão do metadata funciona sozinho. Nada do jogo é publicado:
`orig/` fora do export, hashes pinados, `legal=personal-copy` como nos demais imports.

---

## 5. Fases, entregáveis e aceite

### F0 — Spikes (2–3 dias) — *todos os riscos grandes resolvidos em mini-experimentos*

| # | Spike | Critério de aceite |
|---|---|---|
| S1 | objdiff x86_64: montar 2 COFF triviais (clang-cl) do mesmo C; `report generate` + diff por função | report com % e rows; `arch x86_64` aceito |
| S2 | Inventário: `methods_final.json` + `.pdata` → lista unificada; validar 10 RVAs conhecidos (ex.: `zdEAPOW`, `Setup#3` 0x1a9e30) contra o disasm | 100% dos RVAs amostrados batem; contagens (48.100 pdata / 63.521 rvas) consistentes |
| S3 | Draft x86: rodar Ghidra headless (via decomp) num objeto sintético do Apogea | C legível para funções de teste |
| S4 | Alvo sintético + diff E2E: 1 função pequena conhecida → C à mão → objdiff = 100% | match real em x86-64 com relocs (incl. 1 `call` e 1 `[rip+disp]`) |
| S5 | Proximidade clang-cl × MSVC: compilar 20 funções simples com ambos; medir matched/fuzzy | números para decidir peso do MSVC-under-wine (F4) |
| S0 | *(barato, antes de tudo)* protótipo Opção C: projeto gerado à mão + aberto como fork na UI; report aparece | valida o caminho sem patch algum |

### F1 — Import + projeto scratch (4–6 dias)

Entregável: `import_game(pasta Apogea)` cria o projeto fork no app com inventário e uma unidade de exemplo.
Aceite: `project_info` mostra game/plataforma/inventário; `claim_function` devolve asm + draft + assinatura;
`/api/fork/check` roda o report; UI lista o projeto. *(Nenhum match ainda é OK.)*

### F2 — Inventário completo + context.h (≈1 semana)

Todas as unidades (managed por módulo; engine por cluster), `context.h` completo, builds de todas as unidades
verdes (funções como stubs `#error`/retorno vazio não quebram o report), primeiro lote real decompilado
(`Assembly-CSharp`: login/rede/zona/player — prioridade do servidor local).

### F3 — Loop de match afiado (≈1 semana)

Relocs completas (jump tables de `switch`, `movabs`/DIR64 em dados), data symbols nomeados via metadata,
`symbol_mappings` no objdiff, guia `il2cpp`, notas/renames, export verificado (`verify.py`). Meta: primeiras
funções **100% (byte-exatas)** com clang-cl e degradação suave fora disso (fuzzy% útil).

### F4 — Exatidão MSVC (1–2 semanas de setup; contínuo depois)

Toolchain MSVC 19.29/19.32/19.33 via wine (defaults/`/Ob`//Oi`//GS` calibrados pelo Rich header), medição de
match real por módulo; onde o binário foi LTCG, aceitar fuzzy% (risco §6).

### F5 — Upstream e polish (contínuo)

PR para `i12bp8/decomp.wtf` (a fatia genérica: scratch maker + guia + toolchains; sem nada do Apogea),
fixtures de teste sintéticos, docs do projeto, integração das descobertas de volta no PROGRESS do repo
(quando a implementação começar).

**Estimativa total até MVP útil (F1–F2): ~2 semanas de trabalho focado.** F0 elimina ~80% da incerteza antes de
qualquer patch.

---

## 6. Riscos e mitigação

| Risco | Prob. | Impacto | Mitigação |
|---|---|---|---|
| objdiff x86-64 imaturo p/ relocs (ex.: "Unsupported x86 implicit relocation") | média | alto | S1/S4 decidem cedo; fallback = matcher próprio (padrão `match.py`) |
| Codegen MSVC ≠ clang-cl (fuzzy baixo) | alta | médio | F4 MSVC-under-wine p/ exato; fora disso o valor é decompilação legível + diff |
| Build original com LTCG/inline agressivo (IL2CPP) | média | médio | S5 mede; aceitar fuzzy%; foco nas funções não-inlined (wrappers/IC/stubs) |
| Variantes/proteções de metadata | certa p/ este jogo | resolvido | mapa offline do repo (`--symbols`); parser padrão p/ jogos limpos |
| MSVC sob wine (setup chato, licença) | média | médio | precedente do decomp p/ proprietários (`--accept-license`); consumo do tempo budgetado em F4 |
| Volume (91k métodos) esmaga UI/agentes | média | médio | unidades chunked; priorização por módulo; budget de agentes do app (`budget_usd`) |
| RAM (wine + Ghidra + agentes + jogo) | média | médio | runbook do repo: serializar, limpar `/tmp/opencode` (tmpfs), agentes com cap |
| Duplicar trabalho do repo (Ghidra/Frida já em uso) | baixa | baixo | decomp vira camada de *matching + agentes em escala*; `dumps/decomp` continua a fonte de nomes |

---

## 7. Decisões pendentes (precisam do usuário)

1. **Fork upstream ou branch local?** Recomendo: clone do upstream (`~/tools/decomp.wtf`, tag v0.9.8) → branch
   `unity-il2cpp`; instalar do checkout para o MCP do opencode usar o código novo; PR depois (F5).
2. **Aceitar toolchain MSVC proprietária** (download dos VS archives + `--accept-license` + wine) para match
   exato? Sem ela o teto de exatidão com clang-cl é baixo.
3. **Escopo do MVP**: começar por `Assembly-CSharp` (6.059 métodos — lógica do cliente, utilidade imediata p/
   o servidor) ou pela DLL inteira (48.100 funções *pdata*) com priorização depois?
4. **Executar F0 agora?** S0/S1/S2 são baratos e mudam pouco no repo (nota + artefatos em `/tmp/opencode`).

---

## 8. Operação (lembretes do repo)

- Runs/experimentos em background com logs em `/tmp/opencode/` (tmpfs ⇒ limpar antigos antes).
- Serializar Ghidra/wine/jogo (RAM); nunca bloquear foreground por minutos.
- Registrar cada spike como run (`hsNNN`) quando virar experimento de RE; PROGRESS/`memory` atualizados a partir
  da F1.
- Nunca publicar conteúdo do cliente (o plano mantém `orig/` fora do export e o decryptor local).

---

## 9. F0 — Resultados (14/10/2026)

Executado (detalhes/evidências em `docs/unity-il2cpp/RESULTS.md`):

| # | Spike | Status |
|---|---|---|
| S0 | Projeto objdiff aberto como fork no app, zero patch (API: `/api/fork` + `/api/fork/check`) | ✅ `unity-spike` listado, fuzzy 49.4% |
| S1 | objdiff-cli 3.8.2 × COFF x86-64 | ✅ |
| S2 | Inventário `.pdata`+símbolos (`docs/unity-il2cpp/s2_inventory.py`) | ✅ 135.954 funções; 53.063/63.520 starts |
| S3 | Draft Ghidra x86-64 | ⏳ pendente (caminho já existe no decomp) |
| S4 | Delink + diff real (`docs/unity-il2cpp/s4_delink.py`) | ✅ 39.75% / 36% / 64.4% (clang×MSVC, esperado) |
| S5 | clang×MSVC em 20 funções | ⏳ pendente (decisão §7.2) |

Descoberta operacional importante: **existem dois builds** (o `game-real` = 2021.3.45f2, que tem o mapa de
símbolos; o `Games/Apogea Playtest` = 2021.3.38f1, sem mapa) — o import deve pinar o DLL e validar o mapa
por build. Próximo passo natural: **F1** (o gerador `il2cppsplit` + `scratch_unity`) usando os scripts do F0
como semente.
