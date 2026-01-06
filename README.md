# ChaCha Source Codes

This repository contains the source code accompanying the paper "Improved Key-Recovery Attack on ChaCha Using
Carry-Lock Method" and focuses on backward bias detection in ChaCha using the carry-lock method.

## Updated Article
The updated/revised version of the article is uploaded in the article folder along with the difflatex pdf.

## Supported Targets

- ChaCha-7 / 128-bit key
- ChaCha-7.5 / 256-bit key

<!-- ## Methods Included

- Classical approach of Aumasson et al. (https://www.aumasson.jp/data/papers/AFKMR08.pdf)
- Wang et al. (https://eprint.iacr.org/2023/1087)
- Pattern-based technique by Dey, Garai, Sarkar, and Sharma (https://ieeexplore.ieee.org/abstract/document/10107619) -->

## Quick Start
clone the repo.

```bash
g++ -std=c++20 -O3 <filename>
./a.out
```
for pnb search add the neutrality measure in the command in the end.
## Configuration Guide (`corr_check/correlation_check.cpp`)

Change these fields to switch versions, round counts, and bias methods:

- `basic_config.key_bits`: `128` or `256`
- `basic_config.total_rounds`: `7`, `7.5`, etc. (integer/half/quarter rounds are supported)

<!-- - `diff_config.fwd_rounds`: forward distinguisher rounds (can be fractional) -->
- `pnb_config.pnb_file`: PNB file path
  - Use `chacha7_pnbs/...` for ChaCha-7
  - Use `chacha7.5_pnbs/...` for ChaCha-7.5
- `pnb_config.pnb_pattern_flag`, `pnb_config.pnb_carrylock_flag`, `pnb_config.pnb_syncopation_flag`:
  select the pattern/carry-lock/syncopation behavior
  
- `diff_config.id`, `diff_config.mask`: input difference and output mask bits
- `samples_config.samples_per_thread`, `samples_config.total_loop_count`: runtime and accuracy controls

### Example presets

ChaCha-7 / 128-bit:
- `basic_config.key_bits = 128`
- `basic_config.total_rounds = 7`
- `pnb_config.pnb_file = "chacha7_pnbs/pnb24.txt"`

ChaCha-7.5 / 256-bit:
- `basic_config.key_bits = 256`
- `basic_config.total_rounds = 7.5`
- `pnb_config.pnb_file = "chacha7.5_pnbs/<choose-a-file>.txt"`

## PNB File Notes

PNB files are comma-separated lists of indices. The last three values are footer counts; total PNBs =
sum of those three counts (see `header/chacha.hpp:openPNBFile`). For pattern mode, those counts also
encode segment lengths (see the comment header in `corr_check/correlation_check.cpp`).

## Repository Layout

- `corr_check/correlation_check.cpp` — correlation calculation (carry-lock via xor conditions)
- `corr_check/correlation_check_carry_lock_condition.cpp` — carry-lock segment condition checker (exact segment rules)
- `corr_check/harmonic_correlation_check.cpp` — backward correlation check with carry-lock conditions and paired randomization
- `pnb_search/pnb_search_carry_lock_condition.cpp` — PNB search with exact carry-lock filter 
- `pnb_search/pnb_search_xor_condition.cpp` — PNB search with equivalent XOR-based filter
- `header/` — ChaCha implementation and shared utilities
- `chacha7_pnbs/` — PNB sets for ChaCha-7
- `chacha7.5_pnbs/` — PNB sets for ChaCha-7.5
- `table3/` — scripts used for table generation (Aumasson, carry-lock, syncopation, pattern)
- `complexity/complexity_128_24.py`, `complexity/complexity_256.py` — complexity calculations
- `article/` — revised article PDF and diff
