/*
 * REFERENCE IMPLEMENTATION OF chacha cipher round function header file
 *
 *
 * created: 23/09/23
 * updated: 12/11/25
 *
 *
 *
 * Synopsis:
 * This file contains functions that implement the bare minimum of chacha cipher and the PNB related analysis
 */

#pragma once
#ifndef CHACHA_HEADER_NAME
#define CHACHA_HEADER_NAME "commonfiles.hpp"
#endif
#include "commonfiles.hpp"

constexpr size_t KEY_COUNT = 8;
constexpr size_t WORD_SIZE = 32;
constexpr size_t WORD_COUNT = 16; // state is formed by sixteen 32-bit words

constexpr size_t CHACHA_IV_START = 12;
constexpr size_t CHACHA_IV_END = 15;

constexpr size_t CHACHA_KEY_START = 4;
constexpr size_t CHACHA_KEY_END = 11;

#define UPDATE(a, b, n) (ROTATE_LEFT((a) ^ (b), (n)))

// ---------------------------FW QR-----------------------------------
#define FWDQR_16(a, b, c, d, X) \
  do                            \
  {                             \
    if ((X))                    \
      (a) ^= (b);               \
    else                        \
      (a) += (b);               \
    (d) = UPDATE((a), (d), 16); \
  } while (0)

#define FWDQR_12(a, b, c, d, X) \
  do                            \
  {                             \
    if ((X))                    \
      (c) ^= (d);               \
    else                        \
      (c) += (d);               \
    (b) = UPDATE((b), (c), 12); \
  } while (0)

#define FWDQR_8(a, b, c, d, X) \
  do                           \
  {                            \
    if ((X))                   \
      (a) ^= (b);              \
    else                       \
      (a) += (b);              \
    (d) = UPDATE((a), (d), 8); \
  } while (0)

#define FWDQR_7(a, b, c, d, X) \
  do                           \
  {                            \
    if ((X))                   \
      (c) ^= (d);              \
    else                       \
      (c) += (d);              \
    (b) = UPDATE((b), (c), 7); \
  } while (0)

#define FWDQR_16_12(a, b, c, d, X)     \
  do                                   \
  {                                    \
    FWDQR_16((a), (b), (c), (d), (X)); \
    FWDQR_12((a), (b), (c), (d), (X)); \
  } while (0)

#define FWDQR_8_7(a, b, c, d, X)      \
  do                                  \
  {                                   \
    FWDQR_8((a), (b), (c), (d), (X)); \
    FWDQR_7((a), (b), (c), (d), (X)); \
  } while (0)

#define FWDQR_16_12_8_7(a, b, c, d, X)    \
  do                                      \
  {                                       \
    FWDQR_16_12((a), (b), (c), (d), (X)); \
    FWDQR_8_7((a), (b), (c), (d), (X));   \
  } while (0)

// ---------------------------BW QR-----------------------------------
#define BWDQR_7(a, b, c, d, X)        \
  do                                  \
  {                                   \
    (b) = ROTATE_RIGHT((b), 7) ^ (c); \
    if ((X))                          \
      (c) ^= (d);                     \
    else                              \
      (c) -= (d);                     \
  } while (0)

#define BWDQR_8(a, b, c, d, X)        \
  do                                  \
  {                                   \
    (d) = ROTATE_RIGHT((d), 8) ^ (a); \
    if ((X))                          \
      (a) ^= (b);                     \
    else                              \
      (a) -= (b);                     \
  } while (0)

#define BWDQR_12(a, b, c, d, X)        \
  do                                   \
  {                                    \
    (b) = ROTATE_RIGHT((b), 12) ^ (c); \
    if ((X))                           \
      (c) ^= (d);                      \
    else                               \
      (c) -= (d);                      \
  } while (0)

#define BWDQR_16(a, b, c, d, X)        \
  do                                   \
  {                                    \
    (d) = ROTATE_RIGHT((d), 16) ^ (a); \
    if ((X))                           \
      (a) ^= (b);                      \
    else                               \
      (a) -= (b);                      \
  } while (0)

#define BWQR_7_8(a, b, c, d, X)       \
  do                                  \
  {                                   \
    BWDQR_7((a), (b), (c), (d), (X)); \
    BWDQR_8((a), (b), (c), (d), (X)); \
  } while (0)

#define BWQR_12_16(a, b, c, d, X)      \
  do                                   \
  {                                    \
    BWDQR_12((a), (b), (c), (d), (X)); \
    BWDQR_16((a), (b), (c), (d), (X)); \
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
      FWDQR_16_12_8_7(x[0], x[4], x[8], x[12], true);
      FWDQR_16_12_8_7(x[1], x[5], x[9], x[13], true);
      FWDQR_16_12_8_7(x[2], x[6], x[10], x[14], true);
      FWDQR_16_12_8_7(x[3], x[7], x[11], x[15], true);
    }
    else
    {
      FWDQR_16_12_8_7(x[0], x[5], x[10], x[15], true);
      FWDQR_16_12_8_7(x[1], x[6], x[11], x[12], true);
      FWDQR_16_12_8_7(x[2], x[7], x[8], x[13], true);
      FWDQR_16_12_8_7(x[3], x[4], x[9], x[14], true);
    }
  }

  void ODDARX_16(u32 *x)
  {
    FWDQR_16(x[0], x[4], x[8], x[12], false);
    FWDQR_16(x[1], x[5], x[9], x[13], false);
    FWDQR_16(x[2], x[6], x[10], x[14], false);
    FWDQR_16(x[3], x[7], x[11], x[15], false);
  }

  void EVENARX_16(u32 *x)
  {
    FWDQR_16(x[0], x[5], x[10], x[15], false);
    FWDQR_16(x[1], x[6], x[11], x[12], false);
    FWDQR_16(x[2], x[7], x[8], x[13], false);
    FWDQR_16(x[3], x[4], x[9], x[14], false);
  }
  void ODDARX_12(u32 *x)
  {
    FWDQR_12(x[0], x[4], x[8], x[12], false);
    FWDQR_12(x[1], x[5], x[9], x[13], false);
    FWDQR_12(x[2], x[6], x[10], x[14], false);
    FWDQR_12(x[3], x[7], x[11], x[15], false);
  }
  void EVENARX_12(u32 *x)
  {
    FWDQR_12(x[0], x[5], x[10], x[15], false);
    FWDQR_12(x[1], x[6], x[11], x[12], false);
    FWDQR_12(x[2], x[7], x[8], x[13], false);
    FWDQR_12(x[3], x[4], x[9], x[14], false);
  }

  void ODDARX_8(u32 *x)
  {
    FWDQR_8(x[0], x[4], x[8], x[12], false);
    FWDQR_8(x[1], x[5], x[9], x[13], false);
    FWDQR_8(x[2], x[6], x[10], x[14], false);
    FWDQR_8(x[3], x[7], x[11], x[15], false);
  }

  void EVENARX_8(u32 *x)
  {
    FWDQR_8(x[0], x[5], x[10], x[15], false);
    FWDQR_8(x[1], x[6], x[11], x[12], false);
    FWDQR_8(x[2], x[7], x[8], x[13], false);
    FWDQR_8(x[3], x[4], x[9], x[14], false);
  }

  void ODDARX_7(u32 *x)
  {
    FWDQR_7(x[0], x[4], x[8], x[12], false);
    FWDQR_7(x[1], x[5], x[9], x[13], false);
    FWDQR_7(x[2], x[6], x[10], x[14], false);
    FWDQR_7(x[3], x[7], x[11], x[15], false);
  }

  void EVENARX_7(u32 *x)
  {
    FWDQR_7(x[0], x[5], x[10], x[15], false);
    FWDQR_7(x[1], x[6], x[11], x[12], false);
    FWDQR_7(x[2], x[7], x[8], x[13], false);
    FWDQR_7(x[3], x[4], x[9], x[14], false);
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
  // XOR version of full round functions, round means even or odd round
  void XRoundFunction(u32 *x, u32 round)
  {
    if (round & 1)
    {
      BWQR_7_8_12_16(x[0], x[4], x[8], x[12], true);
      BWQR_7_8_12_16(x[1], x[5], x[9], x[13], true);
      BWQR_7_8_12_16(x[2], x[6], x[10], x[14], true);
      BWQR_7_8_12_16(x[3], x[7], x[11], x[15], true);
    }
    else
    {
      BWQR_7_8_12_16(x[0], x[5], x[10], x[15], true);
      BWQR_7_8_12_16(x[1], x[6], x[11], x[12], true);
      BWQR_7_8_12_16(x[2], x[7], x[8], x[13], true);
      BWQR_7_8_12_16(x[3], x[4], x[9], x[14], true);
    }
  }

  void ODDARX_16(u32 *x)
  {
    BWDQR_16(x[0], x[4], x[8], x[12], false);
    BWDQR_16(x[1], x[5], x[9], x[13], false);
    BWDQR_16(x[2], x[6], x[10], x[14], false);
    BWDQR_16(x[3], x[7], x[11], x[15], false);
  }

  void EVENARX_16(u32 *x)
  {
    BWDQR_16(x[0], x[5], x[10], x[15], false);
    BWDQR_16(x[1], x[6], x[11], x[12], false);
    BWDQR_16(x[2], x[7], x[8], x[13], false);
    BWDQR_16(x[3], x[4], x[9], x[14], false);
  }
  void ODDARX_12(u32 *x)
  {
    BWDQR_12(x[0], x[4], x[8], x[12], false);
    BWDQR_12(x[1], x[5], x[9], x[13], false);
    BWDQR_12(x[2], x[6], x[10], x[14], false);
    BWDQR_12(x[3], x[7], x[11], x[15], false);
  }
  void EVENARX_12(u32 *x)
  {
    BWDQR_12(x[0], x[5], x[10], x[15], false);
    BWDQR_12(x[1], x[6], x[11], x[12], false);
    BWDQR_12(x[2], x[7], x[8], x[13], false);
    BWDQR_12(x[3], x[4], x[9], x[14], false);
  }

  void ODDARX_8(u32 *x)
  {
    BWDQR_8(x[0], x[4], x[8], x[12], false);
    BWDQR_8(x[1], x[5], x[9], x[13], false);
    BWDQR_8(x[2], x[6], x[10], x[14], false);
    BWDQR_8(x[3], x[7], x[11], x[15], false);
  }

  void EVENARX_8(u32 *x)
  {
    BWDQR_8(x[0], x[5], x[10], x[15], false);
    BWDQR_8(x[1], x[6], x[11], x[12], false);
    BWDQR_8(x[2], x[7], x[8], x[13], false);
    BWDQR_8(x[3], x[4], x[9], x[14], false);
  }

  void ODDARX_7(u32 *x)
  {
    BWDQR_7(x[0], x[4], x[8], x[12], false);
    BWDQR_7(x[1], x[5], x[9], x[13], false);
    BWDQR_7(x[2], x[6], x[10], x[14], false);
    BWDQR_7(x[3], x[7], x[11], x[15], false);
  }

  void EVENARX_7(u32 *x)
  {
    BWDQR_7(x[0], x[5], x[10], x[15], false);
    BWDQR_7(x[1], x[6], x[11], x[12], false);
    BWDQR_7(x[2], x[7], x[8], x[13], false);
    BWDQR_7(x[3], x[4], x[9], x[14], false);
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

namespace chacha
{
  u16 column[4][4] = {
      {0, 4, 8, 12}, {1, 5, 9, 13}, {2, 6, 10, 14}, {3, 7, 11, 15}};
  u16 diag[4][4] = {
      {0, 5, 10, 15}, {1, 6, 11, 12}, {2, 7, 8, 13}, {3, 4, 9, 14}};
  void init_iv_const(u32 *x, bool random_flag = true, u32 value = 1)
  {
    x[0] = 0x61707865;
    x[1] = 0x3320646e;
    x[2] = 0x79622d32;
    x[3] = 0x6b206574;
    if (random_flag)
    {
      for (size_t index{CHACHA_IV_START}; index <= CHACHA_IV_END; ++index)
        x[index] = RandomNumber<u32>(); // IV
    }
    else
    {
      for (size_t index{0}; index < WORD_COUNT; ++index)
        x[index] = value;
    }
  }
  void insert_key(u32 *x, u32 *k)
  {
    for (size_t index{CHACHA_KEY_START}; index <= CHACHA_KEY_END; ++index)
      x[index] = k[index - 4];
  }
  // calculates the position of the index in the state matrix
  void calculate_word_bit(u16 index, u16 &WORD, u16 &BIT)
  {
    WORD = (index / WORD_SIZE) + 4;
    BIT = index % WORD_SIZE;
  }

  template <typename T>
  struct HW_Config
  {
    static_assert(std::is_unsigned_v<T>, "State type must be an unsigned integer type");

    const T *state = nullptr;           // pointer to full state (e.g., 16 words)
    const u16 (*column)[4] = nullptr;   // 4x4 mapping: column[col][i] -> state index
    const u16 (*diagonal)[4] = nullptr; // 4x4 mapping: diagonal[d][i] -> state index

    u16 column_no = 0; // 0..3
    u16 diag_no = 0;   // 0..3
  };

  // --- public helpers you’ll actually call ---
  template <typename T>
  int computeHammingWeight(const HW_Config<T> &cfg)
  {
    static_assert(std::is_unsigned_v<T>, "State type must be an unsigned integer type");

    if (!cfg.state)
      throw std::invalid_argument("HW_Config: state pointer is null.");

    int hw = 0;

    if (cfg.column && cfg.column_no < 4)
    {
      for (int i = 0; i < 4; ++i)
        hw += ops::hammingWeight(cfg.state[cfg.column[cfg.column_no][i]]);
    }
    else if (cfg.diagonal && cfg.diag_no < 4)
    {
      for (int i = 0; i < 4; ++i)
        hw += ops::hammingWeight(cfg.state[cfg.diagonal[cfg.diag_no][i]]);
    }
    else
    {
      throw std::invalid_argument("HW_Config: No valid mapping provided.");
    }

    return hw;
  }

  struct InitKey
  {
    // randflag = true, means random key values, otherwise key = value
    void key_256bit(u32 *k, bool random_flag = true, u32 value = 0)
    {
      if (random_flag)
      {
        for (size_t index{0}; index < KEY_COUNT; ++index)
          k[index] = RandomNumber<u32>();
      }
      else
      {
        for (size_t index{0}; index < KEY_COUNT; ++index)
          k[index] = value;
      }
    }
    void key_128bit(u32 *k, bool random_flag = true, u32 value = 1)
    {
      if (random_flag)
      {
        for (size_t index{0}; index < KEY_COUNT / 2; ++index)
        {
          k[index] = RandomNumber<u32>();
          k[index + 4] = k[index];
        }
      }
      else
      {
        for (size_t index{0}; index < KEY_COUNT / 2; ++index)
        {
          k[index] = value;
          k[index + 4] = k[index];
        }
      }
    }
  };

  struct PNBInfo
  {
    std::string pnb_file;            // optional: file with precomputed PNBs
    double neutrality_measure = -1.0; // threshold for neutrality

    bool pnb_search_flag = false;      // run a PNB search?
    bool pnb_pattern_flag = false;     // use pattern filtering?
    bool pnb_carrylock_flag = false;   // enable carry-lock analysis?
    bool pnb_syncopation_flag = false; // enable syncopation filter?

    std::size_t potential_pnb_count = 0; // number of potential PNBs found

    std::vector<u16> pnbs; // list of discovered PNB bit positions
    std::vector<std::size_t> pnbs_in_pattern;
    std::vector<std::size_t> pnbs_in_border;
    std::vector<std::size_t> rest_pnbs;

    // (Optional) metadata
    std::string pattern_name;       // e.g., "carrylock-3R" or "sync-4.5R"
    std::string experiment_label;   // useful for printing/logging
    bool use_threshold_mode = true; // use neutrality threshold
    double min_neutrality = 0.0;
    double max_neutrality = 1.0;

    // Helpers
    bool has_pnbs() const { return !pnbs.empty(); }
  };

  void showPNBconfig(const PNBInfo &cfg, std::ostream &output)
  {
    output << "\n+----------------------------------[ PNB Config ]-------------------------------------+\n";

    // Neutrality measure
    if (cfg.neutrality_measure >= 0.0)
      output << "| Neutrality Measure:      " << std::fixed << std::setprecision(3)
             << (cfg.neutrality_measure) << "\n";

    // PNB file name and optionally the last value
    if (!cfg.pnb_file.empty())
    {
      output << "| PNB File:                    " << cfg.pnb_file << "\n";
      output << "| #PNBs:                       " << cfg.pnbs.size() << "\n";
    }

    if (cfg.potential_pnb_count)
      output << "| Potential PNB Count:      "
             << (cfg.potential_pnb_count) << "\n";

    // Pattern flag
    if (!cfg.pnb_search_flag)
    {
      output << "| Carrylock Flag:              " << (cfg.pnb_carrylock_flag ? "True" : "False") << "\n";
      output << "| Pattern Flag:                " << (cfg.pnb_pattern_flag ? "True" : "False") << "\n";
      output << "| Syncopation Flag:            " << (cfg.pnb_syncopation_flag ? "True" : "False") << "\n";
    }
    output << "+-------------------------------------------------------------------------------------+\n";
  }

  bool openPNBFile(const std::string &filename, PNBInfo &cfg)
  {
    std::ifstream file(filename);
    if (!file.is_open())
    {
      std::cerr << "⚠ Could not open PNB file: " << filename << "\n"
                << "   Expected format example:\n"
                << "   1 2 3 7 8 21 3 2 1\n"
                << "   (values can also be comma-separated)\n"
                << "   - Last 3 numbers = counts of [first_list, second_list, third_list]\n";
      return false;
    }

    std::vector<u16> data;
    std::string line;

    while (std::getline(file, line))
    {
      //  Allow comma-separated values
      std::replace(line.begin(), line.end(), ',', ' ');

      std::istringstream iss(line);
      int temp;
      while (iss >> temp)
      {
        if (temp < 0 || temp > 256)
        {
          std::cerr << "⚠ Invalid value in file: " << temp << "\n"
                    << "  Each PNB value must be between 0 and 256.\n"
                    << "   Example format:\n"
                    << "   1, 2, 3, 7, 8, 21, 3, 2, 1\n";
          return false;
        }
        data.push_back(static_cast<u16>(temp));
      }
    }
    file.close();

    if (data.size() < 3)
    {
      std::cerr << "⚠ PNB file too short — missing the 3-footer counts.\n"
                << "  Expected format:\n"
                << "   [PNBs...] [count_first] [count_second] [count_third]\n"
                << "   Example: 1 2 3 7 8 21 3 2 1\n";
      return false;
    }

    //  Read footer counts
    size_t m1 = data[data.size() - 3];
    size_t m2 = data[data.size() - 2];
    size_t m3 = data[data.size() - 1];
    size_t count = m1 + m2 + m3;

    //  Remove footer
    data.resize(data.size() - 3);

    if (data.size() < count)
    {
      std::cerr << "⚠ Size mismatch: expected at least " << count
                << " PNBs but file has only " << data.size() << ".\n"
                << "  Example correct format:\n"
                << "   1 2 3 7 8 21 3 2 1\n"
                << "   (6 PNB values + 3 footer counts)\n";
      return false;
    }

    // Always assign pnbs
    cfg.pnbs.assign(data.begin(), data.begin() + count);

    //  Conditionally split
    if (cfg.pnb_pattern_flag)
    {
      cfg.pnbs_in_pattern.assign(data.begin(), data.begin() + m1);
      cfg.pnbs_in_border.assign(data.begin() + m1, data.begin() + m1 + m2);
      cfg.rest_pnbs.assign(data.begin() + m1 + m2, data.begin() + count);
    }
    else
    {
      cfg.pnbs_in_pattern.clear();
      cfg.pnbs_in_border.clear();
      cfg.rest_pnbs.clear();
    }

    return true;
  }

  template <class T>
  std::tuple<std::vector<T>, std::vector<T>, std::vector<T>>
  splitConsecutive(const std::vector<T> &elems)
  {
    static_assert(std::is_integral_v<T>, "T must be integral");

    if (elems.empty())
      return {{}, {}, {}};

    std::vector<T> first, second, third;
    std::vector<T> cur;
    cur.reserve(elems.size());

    cur.push_back(elems[0]);
    for (std::size_t i = 1; i < elems.size(); ++i)
    {
      if (elems[i] == cur.back() + 1)
      {
        cur.push_back(elems[i]);
      }
      else
      {
        if (cur.size() >= 2)
        {
          first.insert(first.end(), cur.begin(), cur.end() - 1);
          second.push_back(cur.back());
        }
        else
        {
          third.push_back(cur[0]);
        }
        cur.clear();
        cur.push_back(elems[i]);
      }
    }
    // flush last block
    if (cur.size() >= 2)
    {
      first.insert(first.end(), cur.begin(), cur.end() - 1);
      second.push_back(cur.back());
    }
    else
    {
      third.push_back(cur[0]);
    }

    return {first, second, third};
  }

  template <class T>
  std::vector<T> buildMasterPNBList(std::vector<T> pnbs /* by value so we can sort */)
  {
    static_assert(std::is_integral_v<T>, "T must be integral");

    std::sort(pnbs.begin(), pnbs.end()); // like your Python `sorted(elements)`

    auto [first, second, third] = splitConsecutive(pnbs);

    std::vector<T> master;
    master.reserve(first.size() + second.size() + third.size() + 3);
    master.insert(master.end(), first.begin(), first.end());
    master.insert(master.end(), second.begin(), second.end());
    master.insert(master.end(), third.begin(), third.end());
    master.push_back(static_cast<T>(first.size()));
    master.push_back(static_cast<T>(second.size()));
    master.push_back(static_cast<T>(third.size()));
    return master;
  }

  template <class T>
  void writeListToFile(const std::vector<T> &v, const std::string &path)
  {
    std::ofstream out(path);
    for (std::size_t i = 0; i < v.size(); ++i)
    {
      out << v[i] << (i + 1 == v.size() ? '\n' : ' ');
    }
  }
}
