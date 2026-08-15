"""
EXPECTED CARRY PROPAGATION PAST A PNB BLOCK -- CARRY-LOCK APPROACH

Synopsis:
Estimates E[X], the number of bit positions above a PNB block [n2:n1] at
which the modular differences (Z - X) and (Z - X1) disagree, under the
carry-lock conditions introduced in this work:

  (1) every bit of Z inside the block is set, and
  (2) the bits of Z below the block are >= those of X,

so that no carry propagates into or through the block and the modular
subtraction agrees with XOR at every PNB position inside it.

Used for the comparison in Table 3 of the paper.
"""

import argparse
import json
import random
import sys
import time
from typing import Tuple

WORD_BITS = 32


def block_masks(block_start: int, block_len: int) -> Tuple[int, int, int, int]:
    """
    Return the (block, bit-above-block, above-block, below-block) masks for
    the PNB block occupying bits [block_start, block_start + block_len).
    """
    top = block_start + block_len - 1
    block = ((1 << block_len) - 1) << block_start
    bit_above = 1 << (top + 1)
    above = (1 << WORD_BITS) - (1 << (top + 1))
    below = (1 << block_start) - 1
    return block, bit_above, above, below


def expected_propagation(
    block_start: int, block_len: int, num_trials: int, rng: random.Random
) -> float:
    """Average number of differing bit positions above the block per trial."""
    block, _, above, below = block_masks(block_start, block_len)
    all_ones = (1 << block_len) - 1

    count = 0
    for _ in range(num_trials):
        Z = rng.getrandbits(WORD_BITS)
        X = rng.getrandbits(WORD_BITS)

        # Carry-lock condition (2): no borrow may enter the block from below.
        while (Z & below) < (X & below):
            Z = rng.getrandbits(WORD_BITS)
            X = rng.getrandbits(WORD_BITS)

        # Carry-lock condition (1): every bit of Z inside the block is set.
        Z = (Z & ~block) | (all_ones << block_start)

        # With 50% chance, randomise X's PNB block.
        if rng.getrandbits(1):
            X1 = (X & ~block) | (rng.getrandbits(block_len) << block_start)
        else:
            X1 = X

        # XOR isolates the effect of the PNB perturbation on the difference.
        W = ((Z - X) % (1 << WORD_BITS)) ^ ((Z - X1) % (1 << WORD_BITS))
        count += bin(W & above).count("1")

    return count / float(num_trials)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Expected carry propagation past a PNB block "
                    "(carry-lock approach).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--block-start", type=int, default=16,
                   help="lowest bit index n1 of the PNB block")
    p.add_argument("--block-len", type=int, default=5,
                   help="width of the PNB block in bits")
    p.add_argument("--trials", type=int, default=2 ** 20,
                   help="number of accepted samples")
    p.add_argument("--seed", type=int, default=None,
                   help="PRNG seed for reproducibility")
    p.add_argument("--json", type=str, default=None,
                   help="append the run as a JSON line to this file")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.block_len < 1:
        raise ValueError("block_len must be at least 1")
    if args.block_start + args.block_len > WORD_BITS:
        raise ValueError("PNB block does not fit in a 32-bit word")

    print(f"Parameters: {vars(args)}")
    started = time.time()
    rng = random.Random(args.seed)
    result = expected_propagation(
        args.block_start, args.block_len, args.trials, rng
    )
    runtime = time.time() - started

    print(f"Expected Propagation: {result:.2f}")
    print(f"Runtime: {runtime:.3f}s")

    if args.json:
        record = dict(vars(args))
        record.update({"method": "carrylock", "expected_propagation": result,
                       "runtime_s": runtime})
        with open(args.json, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        print(f"Appended JSON line to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
