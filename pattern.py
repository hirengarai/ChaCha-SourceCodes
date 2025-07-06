import random

# Define the PNB block (e.g., bits 16 to 20)
pnb_block = list(range(16, 16 + 5))

def mask(lst):
    """Return a bitmask of length len(lst) with all bits set to 1."""
    temp = 1
    for _ in range(len(lst) - 1):
        temp = (temp << 1) | 1
    return temp

# Bitmask for extracting/modifying PNB bits
bit_mask_pnb_block = mask(pnb_block) << pnb_block[0]  # Mask for bits 16–20
bit_mask_pnb_block_1 = 1 << (pnb_block[-1] + 1)        # Mask for bit after PNB block
bit_mask_post_pnb_block_value = (1 << 32) - (1 << (pnb_block[-1] + 1))  # Mask for bits 21–31
bit_mask_pre_pnb_block = (1 << pnb_block[0]) - 1       # Mask for bits 0–15

num_trials = 2**20  # Number of random samples

count = 0

for _ in range(num_trials):
    Z = random.getrandbits(32)  # Random 32-bit input
    X = random.getrandbits(32)  # Another 32-bit input

    # With 50% chance, modify X's PNB block using a fixed pattern (e.g., 0b10000)
    if random.getrandbits(1):
        X1 = (X & ~bit_mask_pnb_block) | (0b10000 << pnb_block[0])
    else:
        X1 = X

    # Compute modular differences
    Z_minus_X1 = (Z - X1) % (1 << 32)
    Z_minus_X  = (Z - X) % (1 << 32)

    # XOR to isolate the effect of PNB perturbation
    W = Z_minus_X ^ Z_minus_X1

    # Count number of changed bits in the post-PNB region
    count += bin(W & bit_mask_post_pnb_block_value).count('1')

# Report expected propagation (average flipped bits per trial)
print(f"Expected Propagation: {count / float(num_trials):.2f}")