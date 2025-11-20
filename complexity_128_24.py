"""
REFERENCE IMPLEMENTATION OF COMPLEXITY COMPUTATION

Synopsis:
Computes the data, time, and space complexity
cryptanalytic attack on ChaCha using the carry-lock framework.

"""

import math
from statistics import NormalDist

# ----------------------------- Utility -----------------------------

def bias_product(biases):
    """
    Return the product of a list of biases.
    Example: biases=[2**-4.5, 2**-1.2] -> 2**(-5.7)
    decimal value also works
    """
    prod = 1.0
    for b in biases:
        prod *= b
    return prod


def compute_stage_N(alpha, fwd_eps, bwd_eps, constant=None):
    """
    Compute the required data complexity N for a single stage.

        epsilon = fwd_eps * bwd_eps
        one_minus_eps_sq = 1 - epsilon^2
        numerator = sqrt(alpha * ln 4) - constant * sqrt(1 - epsilon^2)
        N = (numerator / epsilon)^2

    If constant is not provided, defaults to NormalDist(mu=0, sigma=1).inv_cdf(0.0013)
    """

    if constant is None:
        constant = NormalDist(mu=0, sigma=1).inv_cdf(0.0013)

    epsilon = fwd_eps * bwd_eps
    print(f"The product of fwd and bwd biases:~2^{{{math.log2(epsilon):.2f}}}.")
    one_minus_eps_sq = 1.0 - (epsilon * epsilon)
    numerator = math.sqrt(alpha * math.log(4.0)) - constant * math.sqrt(one_minus_eps_sq)
    N = (numerator / epsilon) ** 2

    return N


def compute_C(m_list, N, dim_g_new, R, r, key_size, alpha):
    """
    Compute and print log2 of each term in:

        C = sum_i 2^{m_i} * N
          + 2^{dim(g_new)} * N * (k - 1) / (2^{11} * (R - r))
          + 2^{|K| - alpha}
          + 2^{|K| - dim(g_new)}
    """
    k = len(m_list)

    term1 = sum(2 ** m for m in m_list) * N
    term2 = (2 ** dim_g_new) * N * (k - 1) / (2 ** 11 * (R - r))
    term3 = 2 ** (key_size - alpha)
    term4 = 2 ** (key_size - dim_g_new)

    print(f"\nTerm1:~2^{{{math.log2(term1):.2f}}}.")
    print(f"Term2:~2^{{{math.log2(term2):.2f}}}.")
    print(f"Term3:~2^{{{key_size - alpha:.2f}}}.")
    print(f"Term4:~2^{{{key_size - dim_g_new:.2f}}}.")

    C = term1 + term2 + term3 + term4
    print(f"\nFinal time complexity:~2^{{{math.log2(C):.2f}}}.\n")
    return C


# ----------------------------- Example run -----------------------------
if __name__ == "__main__":
    key_size = 128
    init_pnb_count = 24
    dim_g_new = key_size-init_pnb_count
    constant = 0.8
    alpha =  1.7
    
    m_list = [dim_g_new-26, dim_g_new-18, dim_g_new-11] # <--- for chacha7/128
    bwd_biases = [0.00413] # <--- for chacha7/128
    
    R, r = 7, 4
    fwd_eps = 0.00317
    
    bwd_eps = bias_product(bwd_biases)
    print(f"The product of bwd bias(es):{bwd_eps:.5f} ~ 2^{{{math.log2(bwd_eps):.2f}}}.")
    
    N = compute_stage_N(alpha, fwd_eps,bwd_eps , constant)
    print(f"The init. data complexity:~2^{{{math.log2(N):.2f}}}.")

    # Compute C using that N
    compute_C(m_list, N, dim_g_new, R, r, key_size, alpha)