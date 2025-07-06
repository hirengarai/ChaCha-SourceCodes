/*
 * REFERENCE IMPLEMENTATION OF ChaCha.h header file
 *
 * Filename: CHACHA.h
 *
 * created: 23/9/23
 * updated: 23/6/25
 *
 * by Hiren
 * Researcher
 *
 *
 * Synopsis:
 * This file contains functions that implement the bare minimum of CHACHA cipher
 */

#pragma once
#include "commonfiles2.h"

// QR helping functions
// #define ROTATE_RIGHT(x, n) (((x) >> (n)) ^ ((x) << (WORD_SIZE - n)))
constexpr u32 rotateRight(u32 x, u32 n)
{
  return ((x >> n) | (x << (WORD_SIZE - n)));
}

#define UPDATE(a, b, n) (ROTATE_LEFT((a) ^ (b), (n)))

// ---------------------------FW QR-----------------------------------
// #define FWDARX16(a, b, c, d, X) ((X) ? ((a) ^= (b)) : ((a) += (b)), (d) = UPDATE((a), (d), 16))
#define FWDARX16(a, b, c, d, X) \
  do                            \
  {                             \
    if ((X))                    \
      (a) ^= (b);               \
    else                        \
      (a) += (b);               \
    (d) = UPDATE((a), (d), 16); \
  } while (0)
#define FWDARX12(a, b, c, d, X) \
  do                            \
  {                             \
    if ((X))                    \
      (c) ^= (d);               \
    else                        \
      (c) += (d);               \
    (b) = UPDATE((b), (c), 12); \
  } while (0)

#define FWDARX8(a, b, c, d, X) \
  do                           \
  {                            \
    if ((X))                   \
      (a) ^= (b);              \
    else                       \
      (a) += (b);              \
    (d) = UPDATE((a), (d), 8); \
  } while (0)

#define FWDARX7(a, b, c, d, X) \
  do                           \
  {                            \
    if ((X))                   \
      (c) ^= (d);              \
    else                       \
      (c) += (d);              \
    (b) = UPDATE((b), (c), 7); \
  } while (0)

#define FWDARX_16_12(a, b, c, d, X)    \
  do                                   \
  {                                    \
    FWDARX16((a), (b), (c), (d), (X)); \
    FWDARX12((a), (b), (c), (d), (X)); \
  } while (0)

#define FWDARX_8_7(a, b, c, d, X)     \
  do                                  \
  {                                   \
    FWDARX8((a), (b), (c), (d), (X)); \
    FWDARX7((a), (b), (c), (d), (X)); \
  } while (0)

#define FWDQR_16_12_8_7(a, b, c, d, X)     \
  do                                       \
  {                                        \
    FWDARX_16_12((a), (b), (c), (d), (X)); \
    FWDARX_8_7((a), (b), (c), (d), (X));   \
  } while (0)

// ---------------------------BW QR-----------------------------------
#define BWDARX7(a, b, c, d, X)       \
  do                                 \
  {                                  \
    (b) = rotateRight((b), 7) ^ (c); \
    if ((X))                         \
      (c) ^= (d);                    \
    else                             \
      (c) -= (d);                    \
  } while (0)

#define BWDARX8(a, b, c, d, X)       \
  do                                 \
  {                                  \
    (d) = rotateRight((d), 8) ^ (a); \
    if ((X))                         \
      (a) ^= (b);                    \
    else                             \
      (a) -= (b);                    \
  } while (0)

#define BWDARX12(a, b, c, d, X)       \
  do                                  \
  {                                   \
    (b) = rotateRight((b), 12) ^ (c); \
    if ((X))                          \
      (c) ^= (d);                     \
    else                              \
      (c) -= (d);                     \
  } while (0)

#define BWDARX16(a, b, c, d, X)       \
  do                                  \
  {                                   \
    (d) = rotateRight((d), 16) ^ (a); \
    if ((X))                          \
      (a) ^= (b);                     \
    else                              \
      (a) -= (b);                     \
  } while (0)

#define BWQR_7_8(a, b, c, d, X)       \
  do                                  \
  {                                   \
    BWDARX7((a), (b), (c), (d), (X)); \
    BWDARX8((a), (b), (c), (d), (X)); \
  } while (0)

#define BWQR_12_16(a, b, c, d, X)      \
  do                                   \
  {                                    \
    BWDARX12((a), (b), (c), (d), (X)); \
    BWDARX16((a), (b), (c), (d), (X)); \
  } while (0)

#define BWQR_7_8_12_16(a, b, c, d, X)    \
  do                                     \
  {                                      \
    BWQR_7_8((a), (b), (c), (d), (X));   \
    BWQR_12_16((a), (b), (c), (d), (X)); \
  } while (0)
// -------------------------------------- RoundFunctionDefinition
// ------------------------------------------------
/*
fw rounds
16
12
8
7
*/
class FORWARD
{
public:
  // XOR version of full round functions, round means even or odd round
  void XRoundFunction(u32 *x, u32 round)
  {
    if (round & 1)
    {
      for (int index{0}; index < 4; ++index)
      {
        int j{0};
        FWDQR_16_12_8_7(x[CHACHA::column[index][j]],
                        x[CHACHA::column[index][j + 1]],
                        x[CHACHA::column[index][j + 2]],
                        x[CHACHA::column[index][j + 3]], true);
      }
    }
    else
    {
      for (int index{0}; index < 4; ++index)
      {
        int j{0};
        FWDQR_16_12_8_7(x[CHACHA::diag[index][j]],
                        x[CHACHA::diag[index][j + 1]],
                        x[CHACHA::diag[index][j + 2]],
                        x[CHACHA::diag[index][j + 3]], true);
      }
    }
  }

  //   void EVENARX_16(u32 *x)
  //   {
  //     // for (int index{0}; index < 4; ++index) {
  //     //   int j{0};
  //     //   FWDARX16(x[CHACHA::diag[index][j]], x[CHACHA::diag[index][j + 1]],
  //     //            x[CHACHA::diag[index][j + 2]],
  //     //            x[CHACHA::diag[index][j + 3]], false);
  //     // }

  // #pragma unroll
  //     for (int index = 0; index < 4; ++index)
  //     {
  //       FWDARX16(
  //           x[CHACHA::diag[index][0]],
  //           x[CHACHA::diag[index][1]],
  //           x[CHACHA::diag[index][2]],
  //           x[CHACHA::diag[index][3]],
  //           false);
  //     }
  //   }

  // template <int Index>
  // void UnrollEVENFWDARX16(u32 *x)
  // {
  //   FWDARX16(
  //       x[CHACHA::diag[Index][0]],
  //       x[CHACHA::diag[Index][1]],
  //       x[CHACHA::diag[Index][2]],
  //       x[CHACHA::diag[Index][3]],
  //       false);
  //   if constexpr (Index + 1 < 4)
  //     UnrollEVENFWDARX16<Index + 1>(x);
  // }

  // void EVENARX_16(u32 *x)
  // {
  //   UnrollEVENFWDARX16<0>(x);
  // }

  // template <int Index>
  // void UnrollFWDARX16(u32 *x)
  // {
  //   FWDARX16(
  //       x[CHACHA::column[Index][0]],
  //       x[CHACHA::column[Index][1]],
  //       x[CHACHA::column[Index][2]],
  //       x[CHACHA::column[Index][3]],
  //       false);
  //   if constexpr (Index + 1 < 4)
  //     UnrollFWDARX16<Index + 1>(x);
  // }

  // void ODDARX_16(u32 *x)
  // {
  //   UnrollFWDARX16<0>(x);
  // }

  // void ODDARX_16(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     FWDARX16(x[CHACHA::column[index][j]], x[CHACHA::column[index][j + 1]],
  //              x[CHACHA::column[index][j + 2]], x[CHACHA::column[index][j + 3]],
  //              false);
  //   }
  // }

  // void EVENARX_12(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     FWDARX12(x[CHACHA::diag[index][j]], x[CHACHA::diag[index][j + 1]],
  //              x[CHACHA::diag[index][j + 2]],
  //              x[CHACHA::diag[index][j + 3]], false);
  //   }
  // }

  // void ODDARX_12(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     FWDARX12(x[CHACHA::column[index][j]], x[CHACHA::column[index][j + 1]],
  //              x[CHACHA::column[index][j + 2]], x[CHACHA::column[index][j + 3]],
  //              false);
  //   }
  // }

  // void EVENARX_8(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     FWDARX8(x[CHACHA::diag[index][j]], x[CHACHA::diag[index][j + 1]],
  //             x[CHACHA::diag[index][j + 2]],
  //             x[CHACHA::diag[index][j + 3]], false);
  //   }
  // }

  // void ODDARX_8(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     FWDARX8(x[CHACHA::column[index][j]], x[CHACHA::column[index][j + 1]],
  //             x[CHACHA::column[index][j + 2]], x[CHACHA::column[index][j + 3]],
  //             false);
  //   }
  // }

  // void EVENARX_7(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     FWDARX7(x[CHACHA::diag[index][j]], x[CHACHA::diag[index][j + 1]],
  //             x[CHACHA::diag[index][j + 2]],
  //             x[CHACHA::diag[index][j + 3]], false);
  //   }
  // }

  // void ODDARX_7(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     FWDARX7(x[CHACHA::column[index][j]], x[CHACHA::column[index][j + 1]],
  //             x[CHACHA::column[index][j + 2]], x[CHACHA::column[index][j + 3]],
  //             false);
  //   }
  // }

  void ODDARX_16(u32 *x)
  {
    FWDARX16(x[0], x[4], x[8], x[12], false);
    FWDARX16(x[1], x[5], x[9], x[13], false);
    FWDARX16(x[2], x[6], x[10], x[14], false);
    FWDARX16(x[3], x[7], x[11], x[15], false);
  }

  void EVENARX_16(u32 *x)
  {
    FWDARX16(x[0], x[5], x[10], x[15], false);
    FWDARX16(x[1], x[6], x[11], x[12], false);
    FWDARX16(x[2], x[7], x[8], x[13], false);
    FWDARX16(x[3], x[4], x[9], x[14], false);
  }
  void ODDARX_12(u32 *x)
  {
    FWDARX12(x[0], x[4], x[8], x[12], false);
    FWDARX12(x[1], x[5], x[9], x[13], false);
    FWDARX12(x[2], x[6], x[10], x[14], false);
    FWDARX12(x[3], x[7], x[11], x[15], false);
  }
  void EVENARX_12(u32 *x)
  {
    FWDARX12(x[0], x[5], x[10], x[15], false);
    FWDARX12(x[1], x[6], x[11], x[12], false);
    FWDARX12(x[2], x[7], x[8], x[13], false);
    FWDARX12(x[3], x[4], x[9], x[14], false);
  }

  void ODDARX_8(u32 *x)
  {
    FWDARX8(x[0], x[4], x[8], x[12], false);
    FWDARX8(x[1], x[5], x[9], x[13], false);
    FWDARX8(x[2], x[6], x[10], x[14], false);
    FWDARX8(x[3], x[7], x[11], x[15], false);
  }

  void EVENARX_8(u32 *x)
  {
    FWDARX8(x[0], x[5], x[10], x[15], false);
    FWDARX8(x[1], x[6], x[11], x[12], false);
    FWDARX8(x[2], x[7], x[8], x[13], false);
    FWDARX8(x[3], x[4], x[9], x[14], false);
  }

  void ODDARX_7(u32 *x)
  {
    FWDARX7(x[0], x[4], x[8], x[12], false);
    FWDARX7(x[1], x[5], x[9], x[13], false);
    FWDARX7(x[2], x[6], x[10], x[14], false);
    FWDARX7(x[3], x[7], x[11], x[15], false);
  }

  void EVENARX_7(u32 *x)
  {
    FWDARX7(x[0], x[5], x[10], x[15], false);
    FWDARX7(x[1], x[6], x[11], x[12], false);
    FWDARX7(x[2], x[7], x[8], x[13], false);
    FWDARX7(x[3], x[4], x[9], x[14], false);
  }

  void Half_1_EvenRF(u32 *x)
  {
    EVENARX_16(x);
    EVENARX_12(x);
  }
  void Half_1_OddRF(u32 *x)
  {
    ODDARX_16(x);
    ODDARX_12(x);
  }

  void Half_2_EvenRF(u32 *x)
  {
    EVENARX_8(x);
    EVENARX_7(x);
  }

  void Half_2_OddRF(u32 *x)
  {
    ODDARX_8(x);
    ODDARX_7(x);
  }
  // full round function, round means even or odd round
  void RoundFunction(u32 *x, u32 round)
  {
    if (round & 1)
    {
      Half_1_OddRF(x);
      Half_2_OddRF(x);
    }
    else
    {
      Half_1_EvenRF(x);
      Half_2_EvenRF(x);
    }
  }
} frward;

/* bw rounds
7
8
12
16
*/

class BACKWARD
{
public:
  // void EVENARX_7(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     BWDARX7(x[CHACHA::diag[index][j]], x[CHACHA::diag[index][j + 1]],
  //             x[CHACHA::diag[index][j + 2]],
  //             x[CHACHA::diag[index][j + 3]], false);
  //   }
  // }

  // void ODDARX_7(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     BWDARX7(x[CHACHA::column[index][j]], x[CHACHA::column[index][j + 1]],
  //             x[CHACHA::column[index][j + 2]], x[CHACHA::column[index][j + 3]],
  //             false);
  //   }
  // }

  // void EVENARX_8(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     BWDARX8(x[CHACHA::diag[index][j]], x[CHACHA::diag[index][j + 1]],
  //             x[CHACHA::diag[index][j + 2]],
  //             x[CHACHA::diag[index][j + 3]], false);
  //   }
  // }

  // void ODDARX_8(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     BWDARX8(x[CHACHA::column[index][j]], x[CHACHA::column[index][j + 1]],
  //             x[CHACHA::column[index][j + 2]], x[CHACHA::column[index][j + 3]],
  //             false);
  //   }
  // }

  // void EVENARX_12(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     BWDARX12(x[CHACHA::diag[index][j]], x[CHACHA::diag[index][j + 1]],
  //              x[CHACHA::diag[index][j + 2]],
  //              x[CHACHA::diag[index][j + 3]], false);
  //   }
  // }

  // void ODDARX_12(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     BWDARX12(x[CHACHA::column[index][j]], x[CHACHA::column[index][j + 1]],
  //              x[CHACHA::column[index][j + 2]], x[CHACHA::column[index][j + 3]],
  //              false);
  //   }
  // }

  // void EVENARX_16(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     BWDARX16(x[CHACHA::diag[index][j]], x[CHACHA::diag[index][j + 1]],
  //              x[CHACHA::diag[index][j + 2]],
  //              x[CHACHA::diag[index][j + 3]], false);
  //   }
  // }

  // void ODDARX_16(u32 *x) {
  //   for (int index{0}; index < 4; ++index) {
  //     int j{0};
  //     BWDARX16(x[CHACHA::column[index][j]], x[CHACHA::column[index][j + 1]],
  //              x[CHACHA::column[index][j + 2]], x[CHACHA::column[index][j + 3]],
  //              false);
  //   }
  // }

  void ODDARX_16(u32 *x)
  {
    BWDARX16(x[0], x[4], x[8], x[12], false);
    BWDARX16(x[1], x[5], x[9], x[13], false);
    BWDARX16(x[2], x[6], x[10], x[14], false);
    BWDARX16(x[3], x[7], x[11], x[15], false);
  }

  void EVENARX_16(u32 *x)
  {
    BWDARX16(x[0], x[5], x[10], x[15], false);
    BWDARX16(x[1], x[6], x[11], x[12], false);
    BWDARX16(x[2], x[7], x[8], x[13], false);
    BWDARX16(x[3], x[4], x[9], x[14], false);
  }
  void ODDARX_12(u32 *x)
  {
    BWDARX12(x[0], x[4], x[8], x[12], false);
    BWDARX12(x[1], x[5], x[9], x[13], false);
    BWDARX12(x[2], x[6], x[10], x[14], false);
    BWDARX12(x[3], x[7], x[11], x[15], false);
  }
  void EVENARX_12(u32 *x)
  {
    BWDARX12(x[0], x[5], x[10], x[15], false);
    BWDARX12(x[1], x[6], x[11], x[12], false);
    BWDARX12(x[2], x[7], x[8], x[13], false);
    BWDARX12(x[3], x[4], x[9], x[14], false);
  }

  void ODDARX_8(u32 *x)
  {
    BWDARX8(x[0], x[4], x[8], x[12], false);
    BWDARX8(x[1], x[5], x[9], x[13], false);
    BWDARX8(x[2], x[6], x[10], x[14], false);
    BWDARX8(x[3], x[7], x[11], x[15], false);
  }

  void EVENARX_8(u32 *x)
  {
    BWDARX8(x[0], x[5], x[10], x[15], false);
    BWDARX8(x[1], x[6], x[11], x[12], false);
    BWDARX8(x[2], x[7], x[8], x[13], false);
    BWDARX8(x[3], x[4], x[9], x[14], false);
  }

  void ODDARX_7(u32 *x)
  {
    BWDARX7(x[0], x[4], x[8], x[12], false);
    BWDARX7(x[1], x[5], x[9], x[13], false);
    BWDARX7(x[2], x[6], x[10], x[14], false);
    BWDARX7(x[3], x[7], x[11], x[15], false);
  }

  void EVENARX_7(u32 *x)
  {
    BWDARX7(x[0], x[5], x[10], x[15], false);
    BWDARX7(x[1], x[6], x[11], x[12], false);
    BWDARX7(x[2], x[7], x[8], x[13], false);
    BWDARX7(x[3], x[4], x[9], x[14], false);
  }

  void Half_1_EvenRF(u32 *x)
  {
    EVENARX_7(x);
    EVENARX_8(x);
  }
  void Half_1_OddRF(u32 *x)
  {
    ODDARX_7(x);
    ODDARX_8(x);
  }

  void Half_2_EvenRF(u32 *x)
  {
    EVENARX_12(x);
    EVENARX_16(x);
  }

  void Half_2_OddRF(u32 *x)
  {
    ODDARX_12(x);
    ODDARX_16(x);
  }
  // full round function, round means even or odd round
  void RoundFunction(u32 *x, u32 round)
  {
    if (round & 1)
    {
      Half_1_OddRF(x);
      Half_2_OddRF(x);
    }
    else
    {
      Half_1_EvenRF(x);
      Half_2_EvenRF(x);
    }
  }
} bckward;