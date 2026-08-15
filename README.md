# ChaCha Source Codes

Companion source code for the paper *"Improved Key-Recovery Attack on ChaCha
Using the Carry-Lock Method"*. The repository implements forward / backward
bias measurement and PNB (Probabilistic Neutral Bit) search for ChaCha,
including carry-lock, syncopation, pattern-split, and harmonic variants.

## Supported Targets

- ChaCha-7   / 128-bit key
- ChaCha-7.5 / 256-bit key

Other round counts and key sizes can be set by editing the config block at
the top of each program (see *Configuration Model* below).

## Quick Start

```bash
# any single C++ program in this repo
cd corr_check        # or pnb_search
g++ -std=c++20 -O3 -flto <filename>.cpp -o run
./run                # programs that take CLI args document them in their header
```

The PNB-search programs accept an optional neutrality threshold:

```bash
./run 0.35           # |bias| >= 0.35  ->  classify as PNB
```

Python helpers run with `python3 <file>` and accept `--help`.

## Repository Layout

```
corr_check/
  correlation_check.cpp                       backward-bias measurement (carry-lock + syncopation flags)
  correlation_check_carrylock_condition.cpp   side-by-side comparison: carry-lock conditions vs XOR shortcut
  harmonic_correlation_check.cpp              harmonic carry-lock + paired PNB randomization

pnb_search/
  pnb_search_xor_condition.cpp        per-key-bit PNB search with the XOR shortcut
  pnb_search_carry_lock_condition.cpp per-key-bit PNB search with carry-lock rejection

header/                  ChaCha cipher + analysis utilities (state ops, PNB loader,
                         random / report / log helpers, bit ops, attack util)

chacha7_pnbs/            PNB sets for ChaCha-7  / 128-bit
chacha7.5_pnbs/          PNB sets for ChaCha-7.5 / 256-bit
harmonic_pair.txt        PNB list for harmonic_correlation_check.cpp

complexity/
  complexity_128_24.py   ChaCha-7   / 128-bit complexity script
  complexity_256_25.py   ChaCha-7.5 / 256-bit complexity script

table3/                  Python helpers for table generation
                         (aumasson, carry-lock, syncopation, pattern)
```

## Configuration Model

Every C++ program is configured via a `// ------- Control Panel -------`
block at the top of the file. The relevant `constexpr` knobs are:

| Knob                       | Meaning                                              |
| -------------------------- | ---------------------------------------------------- |
| `KEY_SIZE_BITS`            | `128` or `256`                                       |
| `TOTAL_ROUNDS`             | e.g. `7.0`, `7.5`, `8.0`                             |
| `DISTINGUISHING_ROUND`     | distinguisher boundary (integer or `*.5` for half)   |
| `INPUT_DIFF_BITS`          | input difference `{(word, bit), ...}`                |
| `OUTPUT_MASK_BITS`         | output linear mask `{(word, bit), ...}`              |
| `SAMPLES.samples_per_thread_` / `SAMPLES.num_batches_` | runtime / accuracy   |
| `PNB_INLINE` / `PNB_FILE_PATH` | exactly one must be set (the other empty)        |

Program-specific flags (where applicable):

| File                                  | Flag                  | Effect                                              |
| ------------------------------------- | --------------------- | --------------------------------------------------- |
| `correlation_check.cpp`                       | `USE_PATTERN_SPLIT`   | split PNB list into pattern / border / isolated     |
|                                               | `USE_CARRYLOCK`       | XOR replaces modular `+`/`-` (no rejection)         |
|                                               | `USE_SYNCOPATION`     | rejection sampling on derived sync bits             |
| `correlation_check_carrylock_condition.cpp`   | `USE_CARRYLOCK_CON`   | proper `+`/`-`, reject when conditions fail         |
|                                               | `USE_CARRYLOCK_XOR`   | XOR replaces `+`/`-`, no conditions                 |
| `pnb_search_*.cpp`                            | `DEFAULT_NEUTRALITY_THRESHOLD` | default if no CLI argument is passed       |

`USE_CARRYLOCK` takes precedence over `USE_SYNCOPATION` when both are on;
`USE_CARRYLOCK_CON` and `USE_CARRYLOCK_XOR` are mutually exclusive (enforced
via `static_assert`).

## PNB File Format

Plain whitespace- or comma-separated integers in `[0, KEY_SIZE_BITS)`:

```
2, 3, 4, 21, 22, 7
```

The loader (`header/pnb_util.hpp`) sorts and deduplicates the list. With
`USE_PATTERN_SPLIT = true` it also categorizes:

- *pattern*  — every member of a consecutive run except the last
- *border*   — the last member of each run (length >= 2)
- *isolated* — singletons

`harmonic_correlation_check.cpp` reads its file in **insertion order** (no
sort) and pairs `pnb_list[i]` with `pnb_list[i + N/2]` for the harmonic
randomization. If `STRIP_LEGACY_FOOTER` is `true` the last three tokens are
treated as legacy block-length counts and dropped before pairing.

## Per-program Notes

- **`correlation_check.cpp`** — the main backward-bias driver. Run with
  `USE_CARRYLOCK = false`, `USE_SYNCOPATION = false` for the plain
  modular `+`/`-` baseline; toggle the flags to compare against the
  carry-lock / syncopation variants.
- **`correlation_check_carrylock_condition.cpp`** — empirically validates
  the carry-lock approximation. Run twice (once with `USE_CARRYLOCK_CON`,
  once with `USE_CARRYLOCK_XOR`) and compare the converged biases.
- **`harmonic_correlation_check.cpp`** — measures the bias under the
  harmonic carry-lock conditions (per-PNB bit constraint + min-bit segment
  constraint), with paired PNB randomization.
- **`pnb_search_xor_condition.cpp`** — sweeps every key bit and reports
  PNBs using the XOR shortcut. CLI: `./run [neutrality]`.
- **`pnb_search_carry_lock_condition.cpp`** — same sweep but with
  rejection sampling on the carry-lock conditions for the current bit
  (and its mirror word `w + 4` when `KEY_SIZE_BITS == 128`).

## Complexity Calculator

```bash
python3 complexity/complexity_128_24.py    # ChaCha-7   / 128-bit
python3 complexity/complexity_256_25.py    # ChaCha-7.5 / 256-bit
```

Each script has a `__main__` block at the bottom with the per-target
parameters (`alpha`, `dim_g_new`, `m_list`, `bwd_biases`, `R`, `r`,
`fwd_eps`); edit those values in place to compute the data complexity
`N`, the four time-complexity terms, and total `C` as defined in the
paper.
