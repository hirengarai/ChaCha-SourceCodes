/*
 * REFERENCE IMPLEMENTATION OF ChaCha (Unified Traits Framework)
 *
 * Filename: chacha.hpp
 *
 * Synopsis:
 * Unifies 32-bit (Standard) and 8-bit (Scaled) ChaCha using C++ Concepts and
 * Traits. Features atomic ARX step support for precise fractional round
 * attacks.
 */

#pragma once

#include <algorithm>
#include <bit>
#include <concepts>
#include <cstdint>

#include "core_types.hpp"
#include "random_util.hpp"

namespace chacha {
// ------- Traits Definition -------

template <std::unsigned_integral T> struct ChaChaTraits;

template <> struct ChaChaTraits<u32> {
  static constexpr const char *name = "ChaCha";
  static constexpr u32 c0 = 0x61707865;
  static constexpr u32 c1 = 0x3320646e;
  static constexpr u32 c2 = 0x79622d32;
  static constexpr u32 c3 = 0x6b206574;

  static constexpr int rot_a = 16;
  static constexpr int rot_b = 12;
  static constexpr int rot_c = 8;
  static constexpr int rot_d = 7;
};

template <> struct ChaChaTraits<u8> {
  static constexpr const char *name = "ToyChaCha";
  static constexpr u8 c0 = 0x65;
  static constexpr u8 c1 = 0x6e;
  static constexpr u8 c2 = 0x32;
  static constexpr u8 c3 = 0x74;

  static constexpr int rot_a = 4;
  static constexpr int rot_b = 3;
  static constexpr int rot_c = 2;
  static constexpr int rot_d = 1;
};

// ------- Constants & Indices -------

constexpr size_t STATE_WORDS = 16;
constexpr size_t IV_START = 12;
constexpr size_t IV_END = 15;
constexpr size_t KEY_START = 4;
constexpr size_t KEY_END = 11;

inline constexpr int COL[4][4] = {
    {0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15}};
inline constexpr int DIAG[4][4] = {
    {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}};

// ------- Forward -------

template <std::unsigned_integral T, bool UseXor = false> struct Forward {
  static inline void qr_step1(T &a, T &b, [[maybe_unused]] T &c, T &d) {
    if constexpr (UseXor)
      a ^= b;
    else
      a += b;
    d = std::rotl(T(d ^ a), ChaChaTraits<T>::rot_a);
  }

  static inline void qr_step2([[maybe_unused]] T &a, T &b, T &c, T &d) {
    if constexpr (UseXor)
      c ^= d;
    else
      c += d;
    b = std::rotl(T(b ^ c), ChaChaTraits<T>::rot_b);
  }

  static inline void qr_step3(T &a, T &b, [[maybe_unused]] T &c, T &d) {
    if constexpr (UseXor)
      a ^= b;
    else
      a += b;
    d = std::rotl(T(d ^ a), ChaChaTraits<T>::rot_c);
  }

  static inline void qr_step4([[maybe_unused]] T &a, T &b, T &c, T &d) {
    if constexpr (UseXor)
      c ^= d;
    else
      c += d;
    b = std::rotl(T(b ^ c), ChaChaTraits<T>::rot_d);
  }

  static inline void qr_half1(T &a, T &b, T &c, T &d) {
    qr_step1(a, b, c, d);
    qr_step2(a, b, c, d);
  }
  static inline void qr_half2(T &a, T &b, T &c, T &d) {
    qr_step3(a, b, c, d);
    qr_step4(a, b, c, d);
  }
  static inline void qr_full(T &a, T &b, T &c, T &d) {
    qr_half1(a, b, c, d);
    qr_half2(a, b, c, d);
  }

  template <typename Op>
  static inline void apply_layer(T *x, const int idx[4][4], Op op) {
    for (int i = 0; i < 4; ++i)
      op(x[idx[i][0]], x[idx[i][1]], x[idx[i][2]], x[idx[i][3]]);
  }

  static inline void full_even(T *x) { apply_layer(x, DIAG, qr_full); }
  static inline void full_odd(T *x) { apply_layer(x, COL, qr_full); }

  static inline void round_function(T *x, int round) {
    if (round & 1)
      full_odd(x);
    else
      full_even(x);
  }

  /*
  //
  // EXPERIMENTAL / CUSTOM ROUND TEMPLATE (For fault attacks, tweaks, etc.)
  // 
  // To use: Uncomment, modify, and call from your hot loop instead of
  round_function().
  //
  // 1. Define your modified step:
  // static inline void qr_step2_modified(T &a, T &b, T &c, T &d) {
  //     c += d; // e.g., dropped XOR
  //     b = std::rotl(T(b + c), ChaChaTraits<T>::rot_b);
  // }
  //
  // 2. Define your application layer using the new step:
  // static inline void apply_experimental_round(T *x, bool is_even_round) {
  //     auto experimental_qr = [](T& a, T& b, T& c, T& d) {
  //         qr_step1(a, b, c, d);
  //         qr_step2_modified(a, b, c, d); // <-- INJECTED HERE
  //         qr_step3(a, b, c, d);
  //         qr_step4(a, b, c, d);
  //     };
  //     if (is_even_round) apply_layer(x, DIAG, experimental_qr);
  //     else               apply_layer(x, COL,  experimental_qr);
  // }
  // ====================================================================
  */

  // --- Fractional ARX Step Support (Forward) ---
  static inline void apply_even_arx(T *x, int num_steps) {
    if (num_steps == 1)
      apply_layer(x, DIAG,
                  [](T &a, T &b, T &c, T &d) { qr_step1(a, b, c, d); });
    else if (num_steps == 2)
      apply_layer(x, DIAG, qr_half1);
    else if (num_steps == 3)
      apply_layer(x, DIAG, [](T &a, T &b, T &c, T &d) {
        qr_step1(a, b, c, d);
        qr_step2(a, b, c, d);
        qr_step3(a, b, c, d);
      });
  }
  static inline void apply_odd_arx(T *x, int num_steps) {
    if (num_steps == 1)
      apply_layer(x, COL, [](T &a, T &b, T &c, T &d) { qr_step1(a, b, c, d); });
    else if (num_steps == 2)
      apply_layer(x, COL, qr_half1);
    else if (num_steps == 3)
      apply_layer(x, COL, [](T &a, T &b, T &c, T &d) {
        qr_step1(a, b, c, d);
        qr_step2(a, b, c, d);
        qr_step3(a, b, c, d);
      });
  }

  static inline void finish_even_arx(T *x, int remaining_steps) {
    if (remaining_steps == 3)
      apply_layer(x, DIAG, [](T &a, T &b, T &c, T &d) {
        qr_step2(a, b, c, d);
        qr_step3(a, b, c, d);
        qr_step4(a, b, c, d);
      });
    else if (remaining_steps == 2)
      apply_layer(x, DIAG, qr_half2);
    else if (remaining_steps == 1)
      apply_layer(x, DIAG,
                  [](T &a, T &b, T &c, T &d) { qr_step4(a, b, c, d); });
  }
  static inline void finish_odd_arx(T *x, int remaining_steps) {
    if (remaining_steps == 3)
      apply_layer(x, COL, [](T &a, T &b, T &c, T &d) {
        qr_step2(a, b, c, d);
        qr_step3(a, b, c, d);
        qr_step4(a, b, c, d);
      });
    else if (remaining_steps == 2)
      apply_layer(x, COL, qr_half2);
    else if (remaining_steps == 1)
      apply_layer(x, COL, [](T &a, T &b, T &c, T &d) { qr_step4(a, b, c, d); });
  }
};

// ------- Backward -------

template <std::unsigned_integral T, bool UseXor = false> struct Backward {
  static inline void qr_step4([[maybe_unused]] T &a, T &b, T &c, T &d) {
    b = T(std::rotr(T(b), ChaChaTraits<T>::rot_d) ^ c);
    if constexpr (UseXor)
      c ^= d;
    else
      c -= d;
  }

  static inline void qr_step3(T &a, T &b, [[maybe_unused]] T &c, T &d) {
    d = T(std::rotr(T(d), ChaChaTraits<T>::rot_c) ^ a);
    if constexpr (UseXor)
      a ^= b;
    else
      a -= b;
  }

  static inline void qr_step2([[maybe_unused]] T &a, T &b, T &c, T &d) {
    b = T(std::rotr(T(b), ChaChaTraits<T>::rot_b) ^ c);
    if constexpr (UseXor)
      c ^= d;
    else
      c -= d;
  }

  static inline void qr_step1(T &a, T &b, [[maybe_unused]] T &c, T &d) {
    d = T(std::rotr(T(d), ChaChaTraits<T>::rot_a) ^ a);
    if constexpr (UseXor)
      a ^= b;
    else
      a -= b;
  }

  static inline void qr_half1(T &a, T &b, T &c, T &d) {
    qr_step4(a, b, c, d);
    qr_step3(a, b, c, d);
  }
  static inline void qr_half2(T &a, T &b, T &c, T &d) {
    qr_step2(a, b, c, d);
    qr_step1(a, b, c, d);
  }
  static inline void qr_full(T &a, T &b, T &c, T &d) {
    qr_half1(a, b, c, d);
    qr_half2(a, b, c, d);
  }

  template <typename Op>
  static inline void apply_layer(T *x, const int idx[4][4], Op op) {
    for (int i = 0; i < 4; ++i)
      op(x[idx[i][0]], x[idx[i][1]], x[idx[i][2]], x[idx[i][3]]);
  }

  static inline void full_even(T *x) { apply_layer(x, DIAG, qr_full); }
  static inline void full_odd(T *x) { apply_layer(x, COL, qr_full); }

  static inline void round_function(T *x, int round) {
    if (round & 1)
      full_odd(x);
    else
      full_even(x);
  }

  // --- Fractional ARX Step Support (Backward) ---
  static inline void apply_even_arx(T *x, int num_steps) {
    if (num_steps == 3)
      apply_layer(x, DIAG, [](T &a, T &b, T &c, T &d) {
        qr_step3(a, b, c, d);
        qr_step2(a, b, c, d);
        qr_step1(a, b, c, d);
      });
    else if (num_steps == 2)
      apply_layer(x, DIAG, qr_half2);
    else if (num_steps == 1)
      apply_layer(x, DIAG,
                  [](T &a, T &b, T &c, T &d) { qr_step1(a, b, c, d); });
  }
  static inline void apply_odd_arx(T *x, int num_steps) {
    if (num_steps == 3)
      apply_layer(x, COL, [](T &a, T &b, T &c, T &d) {
        qr_step3(a, b, c, d);
        qr_step2(a, b, c, d);
        qr_step1(a, b, c, d);
      });
    else if (num_steps == 2)
      apply_layer(x, COL, qr_half2);
    else if (num_steps == 1)
      apply_layer(x, COL, [](T &a, T &b, T &c, T &d) { qr_step1(a, b, c, d); });
  }

  static inline void finish_even_arx(T *x, int remaining_steps) {
    if (remaining_steps == 3)
      apply_layer(x, DIAG, [](T &a, T &b, T &c, T &d) {
        qr_step4(a, b, c, d);
        qr_step3(a, b, c, d);
        qr_step2(a, b, c, d);
      });
    else if (remaining_steps == 2)
      apply_layer(x, DIAG, qr_half1);
    else if (remaining_steps == 1)
      apply_layer(x, DIAG,
                  [](T &a, T &b, T &c, T &d) { qr_step4(a, b, c, d); });
  }
  static inline void finish_odd_arx(T *x, int remaining_steps) {
    if (remaining_steps == 3)
      apply_layer(x, COL, [](T &a, T &b, T &c, T &d) {
        qr_step4(a, b, c, d);
        qr_step3(a, b, c, d);
        qr_step2(a, b, c, d);
      });
    else if (remaining_steps == 2)
      apply_layer(x, COL, qr_half1);
    else if (remaining_steps == 1)
      apply_layer(x, COL, [](T &a, T &b, T &c, T &d) { qr_step4(a, b, c, d); });
  }
};

// ------- State Management & Encryption -------

template <std::unsigned_integral T>
inline void init_iv_const(T *x, bool random_flag = true, T value = 1) {
  x[0] = ChaChaTraits<T>::c0;
  x[1] = ChaChaTraits<T>::c1;
  x[2] = ChaChaTraits<T>::c2;
  x[3] = ChaChaTraits<T>::c3;

  for (size_t i = IV_START; i <= IV_END; ++i)
    x[i] = random_flag ? random_util::random_number<T>() : value;
}

template <std::unsigned_integral T> inline void insert_key(T *x, const T *k) {
  for (size_t i = KEY_START; i <= KEY_END; ++i)
    x[i] = k[i - 4];
}

template <std::unsigned_integral T>
inline void calculate_word_bit(u16 index, u16 &word, u16 &bit) {
  constexpr u16 bits_per_word = sizeof(T) * 8;
  word = (index / bits_per_word) + KEY_START;
  bit = index % bits_per_word;
}

template <size_t KeyWords, std::unsigned_integral T>
inline void init_key(T *k, bool random_flag = true, T value = 0) {
  static_assert(KeyWords == 8 || KeyWords == 4, "KeyWords must be 8 or 4");
  for (size_t i = 0; i < KeyWords; ++i) {
    k[i] = random_flag ? random_util::random_number<T>() : value;
    if constexpr (KeyWords == 4)
      k[i + 4] = k[i];
  }
}
} // namespace chacha
