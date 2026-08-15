/*
 * Filename: bit_ops.hpp
 *
 * Bit-level helpers on unsigned integers: bit-range extract / insert and
 * related primitives used across the cipher and analysis code.
 */

#pragma once

#include <bit>
#include <concepts>
#include <limits>

namespace bit_ops
{

    /// Extracts bits in the inclusive range [start_bit, end_bit].
    template <std::unsigned_integral T>
    constexpr T extract_bits(T word, int start_bit, int end_bit)
    {
        const int width = end_bit - start_bit + 1;
        const int bit_size = std::numeric_limits<T>::digits;
        const T mask = (width == bit_size) ? std::numeric_limits<T>::max() : ((T(1) << width) - 1);
        return (word >> start_bit) & mask;
    }

    /// Replaces bits in dst on the inclusive range [start_bit, end_bit] with bits from src.
    template <std::unsigned_integral T>
    constexpr void replace_bits(T &dst, T src, int start_bit, int end_bit)
    {
        const int width = end_bit - start_bit + 1;
        const int bit_size = std::numeric_limits<T>::digits;
        const T base_mask = (width == bit_size) ? std::numeric_limits<T>::max() : (T(1) << width) - 1;
        const T mask = base_mask << start_bit;
        const T segment = (src >> start_bit) & base_mask;
        dst = (dst & ~mask) | (segment << start_bit);
    }

    /// Computes the total Hamming weight of an array of unsigned integers.
    template <std::unsigned_integral T, std::size_t N>
    inline int hamming_weight(const T (&arr)[N])
    {
        int weight = 0;
        for (std::size_t i = 0; i < N; ++i)
        {
            weight += std::popcount(arr[i]);
        }
        return weight;
    }
}