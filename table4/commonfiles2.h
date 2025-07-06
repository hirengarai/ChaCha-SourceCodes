/*
 * REFERENCE IMPLEMENTATION OF some common functions that is used in Salsa, ChaCha & Forrò cipher
 *
 * Filename: commonfiles2.h
 *
 * created: 23/9/23
 * updated: 29/6/25
 *
 * by Hiren
 * Research Fellow
 * NTU Singapore
 *
 * Synopsis:
 * This file contains some common functions that is used in Salsa, ChaCha and Forro scheme
 */
#include <algorithm> // sorting purpose
#include <bitset>    // binary representation
#include <cmath>     // pow function
#include <cstring>   // string
#include <fstream>   // files
#include <format>    // formatted output
#include <iomanip>   // decimal numbers upto certain places, std::setw function
#include <iostream>  // cin cout
#include <mutex>     // thread locking
#include <random>    // mt19937
#include <string>    // filename
#include <sstream>
#include <vector> // vector

// == -- -- -- -- -- -- -- -- -- -- ---= =

// using crypto::u8;
// using crypto::u32;

// typedef uint16_t u16;           // positive integer of 16 bits
// typedef uint32_t u32;           // positive integer of 32 bits
using ull = unsigned long long; // 32 - 64 bits memory

using u8 = std::uint8_t;        // positive integer of 8 bits
using u16 = std::uint_fast16_t; // positive integer of 16 bits
using u32 = std::uint_fast32_t; // positive integer of 32 bits
using u64 = std::uint64_t;      // positive integer of 64 bits

// constexpr size_t WORD_SIZE = word_bit_width<u32>();
constexpr size_t WORD_SIZE = 32;
constexpr u32 MOD = UINT32_MAX; // Maximum 32-bit unsigned integer (2^32 - 1)

constexpr size_t WORD_COUNT = 16; // state is formed by sixteen 32-bit words
constexpr size_t KEY_COUNT = 8;   // state is formed by eight 32-bit keyWords

constexpr size_t SALSA_IV_START = 6;
constexpr size_t SALSA_IV_END = 9;

constexpr size_t CHACHA_IV_START = 12;
constexpr size_t CHACHA_IV_END = 15;

constexpr size_t CHACHA_KEY_START = 4;
constexpr size_t CHACHA_KEY_END = 11;

constexpr size_t FORRO_KEY_START = 0;
constexpr size_t FORRO_KEY_END = 11;

#define get_bit(word, bit) (((word) >> (bit)) & 0x1)
#define set_bit(word, bit) ((word) |= (1u << (bit)))
#define clear_bit(word, bit) ((word) &= ~(1u << (bit)))
#define toggle_bit(word, bit) ((word) ^= (1u << (bit)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (sizeof(x) * 8 - (n))))

inline thread_local std::mt19937 gen{std::random_device{}()};

u32 GenerateRandom32Bits()
{
    // thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<u32> dis(0, MOD);
    return dis(gen);
}

u32 GenerateRandomNumber(u32 min_val, u32 max_val)
{
    // thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<u32> dis(min_val, max_val);
    return dis(gen);
}

// a function which generates a random boolean value based on whether output is > 0.5 or not
bool GenerateRandomBoolean()
{
    // thread_local std::mt19937 mt_engine(std::random_device{}());
    std::uniform_real_distribution<double> distribution(0.0, 1.0);
    return (distribution(gen) > 0.5);

    // thread_local std::mt19937 mt_engine(static_cast<unsigned>(time(NULL)));
    // std::uniform_real_distribution<double> distribution(0.0, 1.0);
    // return (distribution(mt_engine) > 0.5);

    // return (drand48() > 0.5);
}

// All the parameters are in this namespace
namespace CONFIGURATION
{
    struct Basic_Config
    {
        std::string cipher;
        std::string mode;
        double total_round = 0;
        bool total_halfround_flag = false;

    } basic_config;

    struct Distinguisher
    {
        u8 round; // Round number (can be 0, 1, ..., 7, etc.)
        u8 word;  // Word index in state (0 to 15)
        u8 bit;   // Bit index in word (0 to 31 for 32-bit word)
    } distinguisher;

    struct Diff_Config
    {
        double fwdround = 0.0;           // can now hold 3.5, 7.5 etc.
        std::vector<Distinguisher> ID;   // Formerly ID
        std::vector<Distinguisher> mask; // Formerly OD

        bool halfround_flag = false;
        u8 precision_digit = 0;
        bool chosenIV_flag = false;

        bool has_half_round() const
        {
            double intpart;
            return std::modf(fwdround, &intpart) > 0.0;
        }

        int rounded_round() const
        {
            return static_cast<int>(fwdround); // gives floor(fwdround)
        }

    } diff_config;

    struct Samples_Config
    {
        ull samples_per_thread = 0;
        ull samples_per_loop = 0;
        ull total_loop = 0;
    } samples_config;

    // parameters for PNB values
    // struct PNB_config
    // {
    //     std::string pnb_file;
    //     bool pnb_pattern_flag = true;

    //     u8 *pnbs = nullptr;
    //     u8 *pnbs_in_pattern = nullptr;
    //     u8 *pnbs_in_border = nullptr;
    //     u8 *rest_pnbs = nullptr;

    //     size_t pnbs_size = 0;
    //     size_t pnbs_in_pattern_size = 0;
    //     size_t pnbs_in_border_size = 0;
    //     size_t rest_pnbs_size = 0;
    // } pnb_config;

    struct PNB_Config
    {
        std::string pnb_file;
        double neutrality_measure = -1.0;
        bool pnb_pattern_flag = true;
        bool pnb_carrylock_flag = false;
        bool pnb_syncopation_flag = false;
        u16 potential_pnb_count = 0;

        std::vector<u16> pnbs;
        std::vector<u16> pnbs_in_pattern;
        std::vector<u16> pnbs_in_border;
        std::vector<u16> rest_pnbs;
    } pnb_config;

    struct Print_State_Config
    {
        u32 *state = nullptr;
        size_t size = WORD_COUNT;
        bool matrix_form = true;
        bool binary_form = false;
        bool hex_form = true;
    } print_state_config;

    struct HW_Config
    {
        u32 *state;
        bool state_flag = false;
        bool column_flag = true;
        bool diagonal_flag = false;
        bool row_flag = false;
        bool word_flag = false;

        u16 column_no = 0, diag_no = 0, row_no = 0, word_no = 0;

        u16 (*column)[4] = nullptr;
        u16 (*diagonal)[4] = nullptr;
        u16 (*row)[4] = nullptr;

    } hw_config;
}
// !+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!

namespace CHACHA
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
                x[index] = GenerateRandom32Bits(); // IV

            // x[12] = GenerateRandom32Bits();
            // x[13] = GenerateRandom32Bits();
            // x[14] = GenerateRandom32Bits();
            // x[15] = GenerateRandom32Bits();
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
} // namespace ChaCha

namespace SALSA
{
    u16 column[4][4] = {
        {0, 4, 8, 12}, {5, 9, 13, 1}, {10, 14, 2, 6}, {15, 3, 7, 11}};
    u16 row[4][4] = {{0, 1, 2, 3}, {5, 6, 7, 4}, {10, 11, 8, 9}, {15, 12, 13, 14}};
    void init_iv_const(u32 *x, bool randflag = true, u32 value = 0)
    {
        x[0] = 0x61707865;
        x[5] = 0x3120646e;
        x[10] = 0x79622d36;
        x[15] = 0x6b206574;
        if (randflag)
        {
            for (size_t index{SALSA_IV_START}; index <= SALSA_IV_END; ++index)
                x[index] = GenerateRandom32Bits(); // IV
        }
        else
        {
            for (size_t index{SALSA_IV_START}; index <= SALSA_IV_END; ++index)
                x[index] = value;
        }
    }
    void insertkey(u32 *x, u32 *k)
    {
        for (size_t index{1}; index <= 4; ++index)
            x[index] = k[index - 1];
        for (size_t index{11}; index <= 14; ++index)
            x[index] = k[index - 7];
    }
    // calculates the position of the index in the state matrix
    void calculateWORDandBIT(int index, u16 &WORD, u16 &BIT)
    {
        if ((index / 32) > 3)
        {
            WORD = (index / 32) + 7;
        }
        else
        {
            WORD = (index / 32) + 1;
        }
    }
}
// namespace Salsa

namespace FORRO
{
    u16 column[4][5] = {
        {0, 4, 8, 12, 3}, {1, 5, 9, 13, 0}, {2, 6, 10, 14, 1}, {3, 7, 11, 15, 2}};
    u16 diag[4][5] = {{0, 5, 10, 15, 3}, {1, 6, 11, 12, 0}, {2, 7, 8, 13, 1}, {3, 4, 9, 14, 2}};
    void init_iv_const(u32 *x, bool randflag = true, u32 value = 0)
    {
        x[6] = 0x746C6F76;
        x[7] = 0x61616461;
        x[14] = 0x72626173;
        x[15] = 0x61636E61;
        if (randflag)
        {
            x[4] = GenerateRandom32Bits();
            x[5] = GenerateRandom32Bits();
            x[12] = GenerateRandom32Bits();
            x[13] = GenerateRandom32Bits();
        }
        else
        {
            x[4] = value;
            x[5] = value;
            x[12] = value;
            x[13] = value;
        }
    }
    void insertkey(u32 *x, u32 *k)
    {
        for (size_t index{0}; index <= 3; ++index)
            x[index] = k[index];
        for (size_t index{8}; index <= 11; ++index)
            x[index] = k[index - 4];
    }
    void calculateWORDandBIT(int index, u16 &WORD, u16 &BIT)
    {
        if (index > 127)
        {
            WORD = (index / WORD_SIZE) + 4;
            BIT = index % WORD_SIZE;
        }
        else
        {
            WORD = (index / WORD_SIZE);
            BIT = index % WORD_SIZE;
        }
    }
} // namespace Forro

namespace OPERATIONS
{
    struct INIT_KEY
    {
        // randflag = true, means random key values, otherwise key = value
        void key_256bit(u32 *k, bool random_flag = true, u32 value = 0)
        {
            if (random_flag)
            {
                for (size_t index{0}; index < KEY_COUNT; ++index)
                    k[index] = GenerateRandom32Bits();
                // k[0] = GenerateRandom32Bits();
                // k[1] = GenerateRandom32Bits();
                // k[2] = GenerateRandom32Bits();
                // k[3] = GenerateRandom32Bits();
                // k[4] = GenerateRandom32Bits();
                // k[5] = GenerateRandom32Bits();
                // k[6] = GenerateRandom32Bits();
                // k[7] = GenerateRandom32Bits();
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
                    k[index] = GenerateRandom32Bits();
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
    } init_key;

    // x1 state is copied in x state
    void copy_state(u32 *x, u32 *x1, size_t size = WORD_COUNT)
    {
        for (size_t i{0}; i < size; ++i)
            x[i] = x1[i];
    }

    void inject_diff(u32 *x, u16 word, u16 bit)
    {
        toggle_bit(x[word], bit);
    }

    u32 bit_segment(u32 source, int start, int end)
    {
        u32 mask = ((1u << (end - start + 1)) - 1) << start;
        return source & mask;
    }

    std::string to_512bit_hex_string(u32 *x)
    {
        std::string result;
        result.reserve(8 * WORD_COUNT);
        for (size_t i{0}; i < WORD_COUNT; ++i)
            result += std::format("{:08x}", x[i]); // {} is the placeholder and : is the introduction of the formatting
        return result;
    }

    struct Bit_String_Format
    {
        static std::string to_hex_string(u32 *x, int word_count)
        {
            std::string result;
            result.reserve(8 * word_count); // Each u32 = 8 hex chars
            for (int i{0}; i < word_count; ++i)
                result += std::format("{:08x}", x[i]);
            return result;
        }

        static std::string to_binary_string(u32 *x, int word_count)
        {
            std::string result;
            result.reserve(WORD_SIZE * word_count); // Each u32 = 32 bits
            for (int i{0}; i < word_count; ++i)
                result += std::bitset<WORD_SIZE>(x[i]).to_string();
            return result;
        }
    };

    // xor of x and x1 is stored in y
    void xor_state(u32 *y, u32 *x, u32 *x1 = nullptr, size_t word_count = WORD_COUNT)
    {
        for (size_t i{0}; i < word_count; ++i)
            y[i] = x[i] ^ x1[i];
    }
    // sum of x and x1 is stored in x
    void add_state(u32 *x, u32 *x1, size_t size = WORD_COUNT)
    {
        for (size_t i{0}; i < size; ++i)
            x[i] += x1[i];
    }
    // sum of x and x1 is stored in z
    void add_state_oop(u32 *z, u32 *x, u32 *x1, size_t size = WORD_COUNT)
    {
        for (size_t i{0}; i < size; ++i)
            z[i] = x[i] + x1[i];
    }
    // subtraction of x1 from x is stored in x
    void subtract_state(u32 *x, u32 *x1, size_t word_count = WORD_COUNT)
    {
        for (size_t i{0}; i < word_count; ++i)
            x[i] -= x1[i];
    }
    // subtraction of x1 from x is stored in z
    void subtract_state_oop(u32 *z, u32 *x, u32 *x1, size_t word_count = WORD_COUNT)
    {
        for (size_t i{0}; i < word_count; ++i)
            z[i] = x[i] - x1[i];
    }

    template <typename T>
    void reset_value(T *arr, int size, const int value)
    {
        // std::fill(vec.begin(), vec.end(), value);
        std::fill(arr, arr + size, value);
    }

    void difference_bit_1(u32 *x, const std::vector<CONFIGURATION::Distinguisher> &OD, u16 &fwdBit)
    {
        // u8 Bit = 0;
        for (const auto &d : OD)
        {
            fwdBit ^= get_bit(x[d.word], d.bit); // d.round is ignored here, assuming x is for a single round
        }
        // return Bit;
    }

    void difference_bit(const std::vector<u32 *> &diffstates,
                        const std::vector<CONFIGURATION::Distinguisher> &mask,
                        u8 &fwdBit)
    {
        for (const auto &d : mask)
        {
            fwdBit ^= get_bit(diffstates[d.round][d.word], d.bit);
        }
    }

    // function to write the msg in cout and in file
    void write_out(std::ofstream *file, bool filesave, const std::string &msg, bool coutflag = true)
    {
        if (coutflag)
            std::cout << msg;
        if (filesave && file && file->is_open())
            *file << msg;
    }

    // calculate the median of an array
    double CalculateMedian(double *arr, size_t size)
    {
        // Copy the array to keep the original unchanged
        double *sortedArray = new double[size];
        std::copy(arr, arr + size, sortedArray);

        std::sort(sortedArray, sortedArray + size);

        if (size % 2 == 0)
        {
            // If the size is even, return the average of the middle two elements
            return static_cast<double>(sortedArray[size / 2 - 1] +
                                       sortedArray[size / 2]) /
                   2.0;
        }
        else
        {
            // If the size is odd, return the middle element
            return static_cast<double>(sortedArray[size / 2]);
        }
    }

    inline int hamming_weight(u32 x)
    {
        return __builtin_popcount(x); // Efficient on GCC/Clang
    }

    int compute_hamming_weight(const CONFIGURATION::HW_Config &cfg)
    {
        if (!cfg.state)
            return 0;

        int hw = 0;

        // Check for specific word
        if (cfg.word_flag && cfg.word_no < WORD_COUNT)
        {
            return __builtin_popcount(cfg.state[cfg.word_no]);
        }

        // Check full state
        if (cfg.state_flag)
        {
            for (size_t i = 0; i < WORD_COUNT; ++i)
                hw += __builtin_popcount(cfg.state[i]);
            return hw;
        }

        // Check column
        if (cfg.column_flag && cfg.column_no >= 0 && cfg.column_no < 4 && cfg.column != nullptr)
        {
            for (int i = 0; i < 4; ++i)
                hw += __builtin_popcount(cfg.state[cfg.column[cfg.column_no][i]]);
            return hw;
        }

        // Check diagonal
        if (cfg.diagonal_flag && cfg.diag_no >= 0 && cfg.diag_no < 4 && cfg.diagonal != nullptr)
        {
            for (int i = 0; i < 4; ++i)
                hw += __builtin_popcount(cfg.state[cfg.diagonal[cfg.diag_no][i]]);
            return hw;
        }

        // Check row
        if (cfg.row_flag && cfg.row_no >= 0 && cfg.row_no < 4 && cfg.row != nullptr)
        {
            for (int i = 0; i < 4; ++i)
                hw += __builtin_popcount(cfg.state[cfg.row[cfg.row_no][i]]);
            return hw;
        }

        return 0; // Default case
    }

    // x1 stores the count of set bits from each word from the state x
    void hw_state(u32 *x, u32 *x1)
    {
        for (size_t index{0}; index < WORD_COUNT; ++index)
            x1[index] = __builtin_popcount(x[index]);
    }

    // class ARRAYPRINT
    // {
    // public:
    //     void doubleprint(u16 (*arr)[2], size_t rows, size_t columns,
    //                      std::string sep)
    //     {
    //         for (int index{0}; index < rows; ++index)
    //         {
    //             std::cout << "(";
    //             for (int jindex{0}; jindex < 2; ++jindex)
    //             {
    //                 if (jindex == 1)
    //                     std::cout << (unsigned)arr[index][jindex] << ")";
    //                 else
    //                     std::cout << (unsigned)arr[index][jindex] << ", ";
    //             }
    //             if (rows == 1)
    //                 std::cout << "";
    //             if (index == rows - 1)
    //                 std::cout << "";
    //             else
    //                 std::cout << sep;
    //         }
    //         std::cout << "\n";
    //     }
    //     void singleprint(u16 *arr, size_t rows, std::string sep)
    //     {
    //         for (int index{0}; index < rows; ++index)
    //             std::cout << (unsigned)arr[index] << sep;
    //     }
    // } arrayprint;

    // 4 cross 4 matrix form print, by default set to matrix form printing, size set
    // to 0, set flag to false to not print in matrix form bin is set to false, to
    // print binary set it to true
    // void PrintState(CONFIGURATION::Print_Config &params)
    // {
    //     if (params.binaryform)
    //     {
    //         if (params.matrixform)
    //         {
    //             for (size_t index{0}; index < params.size; ++index)
    //             {
    //                 std::bitset<WORD_SIZE> temp(params.x[index]);
    //                 std::string bitsString = temp.to_string();

    //                 // Insert a gap after every 8 bits
    //                 for (size_t i = 8; i < bitsString.size(); i += 9)
    //                 {
    //                     bitsString.insert(i, " ");
    //                 }
    //                 std::cout << bitsString << " | ";
    //                 if (index > 0 && index % 4 == 3)
    //                     std::cout << "\n";
    //             }
    //             std::cout << "\n";
    //         }
    //         else
    //         {
    //             for (size_t index{0}; index < params.size; ++index)
    //             {
    //                 std::bitset<WORD_SIZE> temp(params.x[index]);
    //                 std::cout << temp << "  ";
    //             }
    //             std::cout << "\n";
    //         }
    //     }
    //     else if (params.matrixform)
    //     {
    //         if (params.hexform)
    //         {
    //             for (size_t index{0}; index < params.size; ++index)
    //             {
    //                 printf("%8x ", params.x[index]);
    //                 if (index > 0 && index % 4 == 3)
    //                     std::cout << "\n";
    //             }
    //             std::cout << "\n";
    //         }
    //         else
    //         {
    //             for (size_t index{0}; index < params.size; ++index)
    //             {
    //                 printf("%8d ", params.x[index]);
    //                 if (index > 0 && index % 4 == 3)
    //                     std::cout << "\n";
    //             }
    //             std::cout << "\n";
    //         }
    //     }
    //     else
    //     {
    //         for (size_t index{0}; index < params.size; ++index)
    //             printf("%u ", params.x[index]);
    //         std::cout << "\n";
    //     }
    // }
    // // print other states in hex mode, e.g key or IV
    // void PrintAnyArray(u32 *k, size_t size)
    // {
    //     for (int index{0}; index < size; ++index)
    //     {
    //         printf("%8x ", k[index]);
    //         if (index > 0 && index % 4 == 3)
    //             std::cout << "\n";
    //     }
    // }

    // // all the values of x are set to value, by defualt it is set to 0
    // void ResetState(u32 *x, u32 size, u32 value = -1)
    // {
    //     if (value == -1)
    //     {
    //         for (int i{0}; i < size; ++i)
    //             x[i] = 0x0;
    //     }
    //     else
    //     {
    //         for (int i{0}; i < size; ++i)
    //             x[i] = value;
    //     }
    // }

    // int hamming_weight(u32 x)
    // {
    //     return __builtin_popcount(x); // GCC/Clang builtin
    // }

    // int hamming_weight_count(u32 *x, u8 *column, size_t column_size)
    // {
    //     int temp{0};
    //     for (size_t index{0}; index < column_size; ++index)
    //         temp += __builtin_popcount(x[column[index]]);
    //     return temp;
    // }

    // Checks the conditions from the Syncopated technique
    u32 SynCondition(u32 *x, u16 (*COND)[2], size_t size, bool keyflag = false)
    {
        u32 temp{0};
        for (size_t j{0}; j < size; ++j)
            temp += ((get_bit(x[COND[j][0]], COND[j][1])) << j);
        if (keyflag)
            return ~temp & ((1 << size) - 1);
        return temp & ((1 << size) - 1);
    }

    // Difference of x and x1 is saved in x

    // void XORStates(u32 *x, u32 *x1 = nullptr, size_t size = WORD_COUNT)
    // {
    //     for (size_t i{0}; i < size; ++i)
    //     {
    //         x[i] ^= x1[i];
    //     }
    // }

    // XOR of the states x and x1 is stored in y

    // u16 DifferenceBit(u32 *x, u16 *ODword, u16 *ODbit, size_t size)
    // {
    //     u16 fwdBit{0};
    //     for (size_t index{0}; index < size; ++index)
    //         fwdBit ^= get_bit(x[ODword[index]], ODbit[index]);
    //     return fwdBit;
    // }

    // u16 DifferenceBit(u32 *x, u16 (*OD)[2], size_t size)
    // {
    //     u16 Bit{0};
    //     for (size_t row{0}; row < size; ++row)
    //     {
    //         for (size_t column{0}; column < 2; ++column)
    //         {
    //             Bit ^= get_bit(x[OD[row][column]], OD[row][column + 1]);
    //             column++;
    //         }
    //     }
    //     return Bit;
    // }

    // u8 DifferenceBit(u32 *x, const std::vector<Distinguisher> &distinguisher, const std::vector<std::vector<u32>> &states)
    // {
    //     u8 bit = 0;
    //     for (const auto &d : distinguisher)
    //     {
    //         bit ^= get_bit(states[d.round][d.word], d.bit);
    //     }
    //     return bit;
    // }

    // class CHACHA_SET_BITS_COUNTER
    // {
    // public:
    //     int Funhamming_weight_count(const CONFIGURATION::hamming_weight_counterDetailstrct &params)
    //     {
    //         int counter;
    //         if (params.columnflag) // column
    //         {
    //             u8 *col;
    //             switch (params.columnno)
    //             {
    //             case 1:
    //                 col = ChaCha::column[1];
    //                 break;
    //             case 2:
    //                 col = ChaCha::column[2];
    //                 break;
    //             case 3:
    //                 col = ChaCha::column[3];
    //                 break;
    //             default:
    //                 col = ChaCha::column[0];
    //                 break;
    //             }
    //             counter = hamming_weight_count(params.x, col, 4);
    //         }
    //         else // diag
    //         {
    //             u8 *diag;
    //             switch (params.diagno)
    //             {
    //             case 1:
    //                 diag = ChaCha::diag[1];
    //                 break;
    //             case 2:
    //                 diag = ChaCha::diag[2];
    //                 break;
    //             case 3:
    //                 diag = ChaCha::diag[3];
    //                 break;
    //             default:
    //                 diag = ChaCha::diag[0];
    //                 break;
    //             }
    //             counter = hamming_weight_count(params.x, diag, 4);
    //         }
    //         return counter;
    //     }
    // } chachahamming_weight_counter;

    // class SALSA_SET_BITS_COUNTER
    // {
    // public:
    //     int Funhamming_weight_count(const CONFIGURATION::hamming_weight_counterDetailstrct &params)
    //     {
    //         int counter;
    //         if (params.columnflag) // column
    //         {
    //             u16 *col;
    //             switch (params.columnno)
    //             {
    //             case 1:
    //                 col = Salsa::column[1];
    //                 break;
    //             case 2:
    //                 col = Salsa::column[2];
    //                 break;
    //             case 3:
    //                 col = Salsa::column[3];
    //                 break;
    //             default:
    //                 col = Salsa::column[0];
    //                 break;
    //             }
    // counter = hamming_weight_count(params.x, col, 4);
    //         }
    //         else // row
    //         {
    //             u16 *row;
    //             switch (params.rowno)
    //             {
    //             case 1:
    //                 row = Salsa::row[1];
    //                 break;
    //             case 2:
    //                 row = Salsa::row[2];
    //                 break;
    //             case 3:
    //                 row = Salsa::row[3];
    //                 break;
    //             default:
    //                 row = Salsa::row[0];
    //                 break;
    //             }
    //             counter = hamming_weight_count(params.x, row, 4);
    //         }
    //         return counter;
    //     }
    // } salsahamming_weight_counter;

    // class FORRO_SET_BITS_COUNTER
    // {
    // public:
    //     int Funhamming_weight_count(const CONFIGURATION::hamming_weight_counterDetailstrct &params)
    //     {
    //         int counter;
    //         if (params.columnflag) // column
    //         {
    //             u16 *col;
    //             switch (params.columnno)
    //             {
    //             case 1:
    //                 col = Forro::column[1];
    //                 break;
    //             case 2:
    //                 col = Forro::column[2];
    //                 break;
    //             case 3:
    //                 col = Forro::column[3];
    //                 break;
    //             default:
    //                 col = Forro::column[0];
    //                 break;
    //             }
    //             counter = hamming_weight_count(params.x, col, 4);
    //         }
    //         else // diagonal
    //         {
    //             u16 *diag;
    //             switch (params.rowno)
    //             {
    //             case 1:
    //                 diag = Forro::diag[1];
    //                 break;
    //             case 2:
    //                 diag = Forro::diag[2];
    //                 break;
    //             case 3:
    //                 diag = Forro::diag[3];
    //                 break;
    //             default:
    //                 diag = Forro::diag[0];
    //                 break;
    //             }
    //             counter = hamming_weight_count(params.x, diag, 4);
    //         }
    //         return counter;
    //     }
    // } forrohamming_weight_counter;

    // void PrintBasicDetails(CONFIGURATION::Basic_Config &params,
    //                        std::ostream &output)
    // {
    //     output << "+-----------------------------------------------------------------"
    //               "+\n";
    //     if (params.cipher != "")
    //         output << std::setw(6) << "Cipher Name: " << params.cipher << "\n";

    //     if (params.programtype != "")
    //         output << std::setw(6) << "Programe Type: " << params.programtype
    //                << "\n";

    //     if (params.totalround)
    //     {
    //         if (params.halfroundflag)
    //             output << std::setw(6)
    //                    << "# of total rounds: " << (unsigned)params.totalround + 0.5 << "\n";
    //         else
    //         {
    //             output << std::setw(6)
    //                    << "# of total rounds: " << (unsigned)params.totalround << "\n";
    //         }
    //     }

    //     // output <<
    //     // "+------------------------------------------------------------------------------------+\n";
    // }
    // void PrintDiffDetails(CONFIGURATION::Diff_Config &params,
    //                       std::ostream &output)
    // {
    //     if (params.fwdround)
    //     {
    //         if (params.halfroundflag)
    //         {
    //             output
    //                 << std::setw(6)
    //                 << "# of fwd rounds: " << (unsigned)params.fwdround + 0.5 << "\n";
    //         }
    //         else
    //         {
    //             output << std::setw(6)
    //                    << "# of fwd rounds: " << (unsigned)params.fwdround << "\n";
    //         }
    //     }

    // if (params.ID)
    // {
    //     output << std::setw(6) << "Input Differential: ";
    //     OPERATIONS::arrayprint.doubleprint(params.ID, params.IDsize, 2, "⊕");
    // }
    // if (params.mask)
    // {
    //     output << std::setw(6) << "Output Mask: ";
    //     OPERATIONS::arrayprint.doubleprint(params.mask, params.masksize, 2, "⊕");
    // }
    // if (params.precision_digit)
    //     output << "The degree of precision is upto " << params.precision_digit - 1
    //            << " digits after decimal\n";
    // // output <<
    // "+------------------------------------------------------------------------------------+\n";
    // }

    // void PrintPNBDetails(CONFIGURATION::PNBvalueDetailstrct &params,
    //                      std::ostream &output)
    // {
    //     if (params.PNBfile != "")
    //         output << std::setw(6) << "PNBs are from the file " << params.PNBfile
    //                << "\n";
    //     if (params.PNBlockflag)
    //     {
    //         output << std::setw(6) << "PNBs are in block mode"
    //                << "\n";
    //         output << std::setw(6)
    //                << "# of PNBs in block mode: " << params.PNBinblocksize
    //                << ", # of rest of the PNBs: " << params.restPNBsize
    //                << ", # of orphan PNBs: " << params.orphanPNBsize << "\n";
    //     }
    //     if (params.PNB)
    //         output << std::setw(6) << "# of PNBs: " << params.PNBsize << "\n";

    //     if (params.neutralitymeasure)
    //         output << "The neutrality measure is " << std::fixed << std::setprecision(3) << params.neutralitymeasure
    //                << "\n";
    //     // output <<
    //     // "+------------------------------------------------------------------------------------+\n";
    // }

    // void PrintSampleDetails(CONFIGURATION::samplesDetailstrct &params,
    //                         std::ostream &output)
    // {
    //     if (params.samplesperLoop)
    //         output << std::setw(6) << std::fixed << std::setprecision(2) << "Samples Per Loop: 2^{"
    //                << log2(params.samplesperLoop) << "}\n";
    //     if (params.totalLoop)
    //         output << std::setw(6) << std::fixed << std::setprecision(2) << "Total Loop Count: 2^{"
    //                << log2(params.totalLoop) << "}\n";
    //     if (params.samplesperThread)
    //         output << std::setw(6) << std::fixed << std::setprecision(2) << "Samples Per Thread: 2^{"
    //                << log2(params.samplesperThread) << "}\n";
    // }

    // void PrintBiasLoopEtc(std::ostream &output)
    // {
    //     output << "+----------------------+----------------------------------+---------------------------------+---------------------"
    //               "+\n";
    //     output << std::setw(15) << "Loop Count" << std::setw(5) << "            "
    //            << std::setw(15) << "Bias" << std::setw(13) << "          " << std::setw(33)
    //            << "Apprx. exec. time (seconds)" << std::setw(3) << ""
    //            << std::setw(13) << "Remarks" << std::setw(6) << "\n";
    //     output << "+----------------------+----------------------------------+---------------------------------+---------------------"
    //               "+\n";
    // }
};

namespace OUTPUT
{
    const int WIDTH_PNB = 9;
    const int WIDTH_INDEX = 11;
    const int WIDTH_COORD = 13;
    const int WIDTH_NM = 10;
    const int WIDTH_TIME = 15;

    std::string center(const std::string &text, int width)
    {
        int len = text.length();
        if (width > len)
        {
            int pad = (width - len) / 2;
            return std::string(pad, ' ') + text + std::string(width - len - pad, ' ');
        }
        return text.substr(0, width); // truncate
    }

    std::string valueWithPower(double val)
    {
        if (val == 0.0)
            return "0.0000 ~ 2^{ -∞ }";
        std::stringstream ss;
        ss << std::fixed << std::setprecision(5) << val;
        double power = static_cast<double>(log2(1.0 / fabs(val)));
        ss << " ~ 2^{" << std::fixed << std::setprecision(2) << -power << "}";
        return ss.str();
    }

    void print_border(std::ostream &output)
    {
        output << "+" << std::string(12, '-') << "+"
               << std::string(13, '-') << "+"
               << std::string(24, '-') << "+"
               << std::string(24, '-') << "+"
               << std::string(12, '-') << "+"
               << std::string(12, '-') << "+" << "\n";
    }

    void print_pnb_border(std::ostream &output)
    {
        output << "+"
               << std::string(WIDTH_PNB, '-') << "+"
               << std::string(WIDTH_INDEX, '-') << "+"
               << std::string(WIDTH_COORD, '-') << "+"
               << std::string(WIDTH_NM, '-') << "+"
               << std::string(WIDTH_TIME, '-') << "+"
               << "\n";
    }
    void print_header(std::ostream &output)
    {
        print_border(output);
        output << "|"
               << center("Loop Count", 12) << "|"
               << center("Probability", 13) << "|"
               << center("Bias", 24) << "|"
               << center("Correlation", 24) << "|"
               << center("Exec. Time", 12) << "|"
               << center("Remark", 12) << "|\n";
        print_border(output);
    }

    void print_pnb_header(std::ostream &output)
    {
        print_pnb_border(output);
        output << "|"
               << center("PNB #", WIDTH_PNB) << "|"
               << center("PNB Index", WIDTH_INDEX) << "|"
               << center("(Word, Bit)", WIDTH_COORD) << "|"
               << center("NM", WIDTH_NM) << "|"
               << center("Exec. Time", WIDTH_TIME) << "|"
               << "\n";
        print_pnb_border(output);
    }

    std::string format_time(int min, int sec, int milli)
    {
        std::stringstream ss;
        if (min > 0)
            ss << min << "m";
        if (sec > 0 || min > 0)
        {
            if (min > 0)
                ss << " ";
            ss << sec << "s";
        }
        if (milli > 0 || (min == 0 && sec == 0))
        {
            if (min > 0 || sec > 0)
                ss << " ";
            ss << milli << "ms";
        }
        return ss.str();
    }

    void print_pnb_row(int loop_count, int pnb_index, int word, int bit,
                       double nm, int min, int sec, int milli,
                       std::ostream &output)
    {
        std::stringstream coord;
        coord << "(" << word << ", " << bit << ")";

        std::string time_str = format_time(min, sec, milli);

        output << "|"
               << center(std::to_string(loop_count), WIDTH_PNB) << "|"
               << center(std::to_string(pnb_index), WIDTH_INDEX) << "|"
               << center(coord.str(), WIDTH_COORD) << "|"
               << center([](double val)
                         {
                std::ostringstream ss;
                ss << std::fixed << std::setprecision(4) << val;
                return ss.str(); }(nm), 10)
               << "|"
               << center(time_str, WIDTH_TIME) << "|"
               << "\n";
    }

    void output_result(int loop, double prob, double bias, double corr, double exec_time, bool remark_flag, int remark_count, std::ostream &output)
    {
        std::string remark = remark_flag ? "✅ (" + std::to_string(remark_count) + ")" : "❌";

        output << "|"
               << center(std::to_string(loop), 12) << "|"
               << center(std::to_string(prob).substr(0, 9), 13) << "|"
               << center(valueWithPower(bias), 24) << "|"
               << center(valueWithPower(fabs(corr)), 24) << "|"
               << center(std::to_string(exec_time).substr(0, 6) + "s", 12) << "|"
               << center(remark, 13) << "|\n";
    }

    void print_basic_config(const CONFIGURATION::Basic_Config &cfg, std::ostream &output)
    {
        output << "\n+-----------[ Basic Config ]------------+\n";
        if (!cfg.cipher.empty())
            output << "| Cipher:            " << cfg.cipher << "\n";
        if (!cfg.mode.empty())
            output << "| Mode:              " << cfg.mode << "\n";
        if (cfg.total_round > 0)
        {
            if (cfg.total_halfround_flag)

                output << "| Total Rounds:      " << cfg.total_round + 0.5 << "\n";

            else
                output << "| Total Rounds:      " << cfg.total_round << "\n";
        }
        output << "+--------------------------------------+\n";
    }

    void print_diff_config(CONFIGURATION::Diff_Config &cfg, std::ostream &output)
    {
        output << "\n+-----------[ Distinguisher Config ]-----------+\n";

        if (cfg.fwdround > 0.0)
            output << "| Forward Round:     " << cfg.fwdround << "\n";

        if (cfg.halfround_flag)
            output << "| Half-Round Flag:   ✅\n";

        // if (cfg.precision_digit)
        //     output << "| Precision Digits:  " << static_cast<int>(cfg.precision_digit) << "\n";

        if (cfg.chosenIV_flag)
            output << "| Chosen IV Mode:    ✅\n";

        if (!cfg.ID.empty())
        {
            output << "| Input Difference:  ";
            for (auto it = cfg.ID.begin(); it != cfg.ID.end(); ++it)
            {
                output << "(R" << +it->round << ", W" << +it->word << ", b" << +it->bit << ")";
                if (std::next(it) != cfg.ID.end())
                    output << " ⊕ ";
            }
            output << "\n";
            output << "|  ↳ Means flipping: ";
            for (const auto &d : cfg.ID)
            {
                output << "[bit " << +d.bit << " of word " << +d.word
                       << " in round " << +d.round << "] ";
            }
            output << "\n";
        }

        if (!cfg.mask.empty())
        {
            output << "| Output Mask:       ";
            for (const auto &d : cfg.mask)
            {
                output << "(R" << +d.round << ", W" << +d.word << ", b" << +d.bit << ") ";
            }
            output << "\n";
            output << "|  ↳ Correlation is computed as: ";
            for (auto it = cfg.mask.begin(); it != cfg.mask.end(); ++it)
            {
                output << "(R" << +it->round << ", W" << +it->word << ", b" << +it->bit << ")";
                if (std::next(it) != cfg.mask.end())
                    output << " ⊕ ";
            }
            output << "\n";
        }

        output << "+----------------------------------------------+\n";
    }

    void print_samples_config(const CONFIGURATION::Samples_Config &cfg, std::ostream &output)
    {
        output << "\n+-----------[ Sample Config ]-----------+\n";
        if (cfg.samples_per_thread > 0)
            output << "| Samples per Thread:    2^{" << log2(cfg.samples_per_thread) << "}\n";
        if (cfg.samples_per_loop > 0)
            output << "| Samples per Loop:      2^{" << log2(cfg.samples_per_loop) << "}\n";
        if (cfg.total_loop > 0)
            output << "| Total Loops:           2^{" << log2(cfg.total_loop) << "}\n";
        output << "+--------------------------------------+\n";
    }

    void print_pnb_config(const CONFIGURATION::PNB_Config &cfg, std::ostream &output)
    {
        output << "\n+-----------[ PNB Config ]-----------+\n";

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
        // // PNB file name if available
        // if (!cfg.pnb_file.empty())
        //     output << "| PNB File:                " << cfg.pnb_file << "\n";

        if (cfg.potential_pnb_count)
            output << "| Potential PNB Count:      "
                   << (cfg.potential_pnb_count) << "\n";

        // Pattern flag
        output << "| Pattern Flag:                " << (cfg.pnb_pattern_flag ? "True" : "False") << "\n";
        output << "| Syncopation Flag:            " << (cfg.pnb_syncopation_flag ? "True" : "False") << "\n";
        output << "| Carrylock Flag:              " << (cfg.pnb_carrylock_flag ? "True" : "False") << "\n";
        output << "+--------------------------------------+\n";
    }

    void print_state(const CONFIGURATION::Print_State_Config &cfg, std::ostream &os = std::cout)
    {
        if (!cfg.state || cfg.size == 0)
        {
            os << "⚠ No state data to print.\n";
            return;
        }

        const size_t words_per_row = 4;
        for (size_t i{0}; i < cfg.size; ++i)
        {
            if (cfg.matrix_form && i % words_per_row == 0)
                os << "| ";

            if (cfg.binary_form)
                os << std::bitset<WORD_SIZE>(cfg.state[i]) << " ";
            else if (cfg.hex_form)
                os << "0x" << std::setfill('0') << std::setw(8) << std::hex << cfg.state[i] << " ";
            else
                os << cfg.state[i] << " "; // decimal fallback

            if (cfg.matrix_form && (i + 1) % words_per_row == 0)
                os << "|\n";
        }

        if (cfg.matrix_form && cfg.size % words_per_row != 0)
            os << "|\n";

        os << std::dec << std::flush; // reset formatting
    }

    std::string format_time(const std::string &label)
    {
        time_t t = time(nullptr);
        tm *lt = localtime(&t);
        std::ostringstream oss;
        oss << "######## " << label << " on: "
            << lt->tm_mday << '/' << (lt->tm_mon + 1) << '/' << (lt->tm_year + 1900)
            << " at " << std::setfill('0') << std::setw(2) << lt->tm_hour << ':'
            << std::setw(2) << lt->tm_min << ':' << std::setw(2) << lt->tm_sec
            << " ########\n";
        return oss.str();
    }
}

class Timer
{
private:
    std::chrono::time_point<std::chrono::high_resolution_clock> start_wall;
    std::clock_t start_cpu;

public:
    Timer()
    {
        start_wall = std::chrono::high_resolution_clock::now();
        start_cpu = std::clock();
    }

    std::string start_message() const
    {
        std::time_t now_c = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::stringstream ss;
        ss << "\n######## Execution started on: " << std::put_time(std::localtime(&now_c), "%d/%m/%Y at %H:%M:%S") << " ########\n";
        return ss.str();
    }

    std::string end_message() const
    {
        auto end_wall = std::chrono::high_resolution_clock::now();
        std::clock_t end_cpu = std::clock();

        auto wall_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_wall - start_wall);

        auto minutes = std::chrono::duration_cast<std::chrono::minutes>(wall_duration);
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(wall_duration);
        auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(wall_duration);

        double cpu_time_ms = 1000.0 * (end_cpu - start_cpu) / CLOCKS_PER_SEC;

        std::time_t now_c = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::stringstream ss;
        ss << "\n######## Execution ended on: " << std::put_time(std::localtime(&now_c), "%d/%m/%Y at %H:%M:%S") << " ########\n";
        ss << "Wall time elapsed: "
           << minutes.count() << " minutes, ~ "
           << seconds.count() << " seconds, ~ "
           << milliseconds.count() << " milliseconds.\n";
        ss << "CPU time used:     " << cpu_time_ms << " milliseconds.\n";
        return ss.str();
    }
} timer;

bool OpenPNBFile(const std::string &filename, CONFIGURATION::PNB_Config &details)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        std::cerr << "⚠ Could not open PNB file: " << filename << "\n";
        return false;
    }

    std::vector<u16> data;
    int temp;
    while (file >> temp)
    {
        if (temp < 0 || temp > 255)
        {
            std::cerr << "⚠ Invalid value in file: " << temp << "\n";
            return false;
        }
        data.push_back(static_cast<u8>(temp));
    }
    file.close();

    if (data.empty())
    {
        std::cerr << "⚠ PNB file is empty.\n";
        return false;
    }

    if (details.pnb_pattern_flag)
    {
        if (data.size() < 3)
        {
            std::cerr << "⚠ Invalid PNB file: missing m1, m2, m3\n";
            return false;
        }

        size_t m1 = data[data.size() - 3];
        size_t m2 = data[data.size() - 2];
        size_t m3 = data[data.size() - 1];

        size_t total = m1 + m2 + m3;
        if (data.size() - 3 < total)
        {
            std::cerr << "⚠ PNB file too short for given sizes.\n";
            return false;
        }

        // Assign to config
        details.pnbs.assign(data.begin(), data.begin() + total);
        details.pnbs_in_pattern.assign(data.begin(), data.begin() + m1);
        details.pnbs_in_border.assign(data.begin() + m1, data.begin() + m1 + m2);
        details.rest_pnbs.assign(data.begin() + m1 + m2, data.begin() + total);
    }
    else
    {
        if (data.size() < 3)
        {
            std::cerr << "⚠ PNB file too short to read 3-size footer.\n";
            return false;
        }

        // Get last 3 values as counts
        size_t m1 = data[data.size() - 3];
        size_t m2 = data[data.size() - 2];
        size_t m3 = data[data.size() - 1];
        size_t count = m1 + m2 + m3;

        // Remove last 3 entries
        data.resize(data.size() - 3);

        if (data.size() < count)
        {
            std::cerr << "⚠ Size mismatch: expected at least " << count
                      << " PNBs, but got only " << data.size() << ".\n";
            return false;
        }

        // Take the first 'count' values as PNBs
        details.pnbs.assign(data.begin(), data.begin() + count);
        details.rest_pnbs.clear();       // Treat all as "rest"
        details.pnbs_in_pattern.clear(); // No pattern
        details.pnbs_in_border.clear();  // No border
    }

    return true;
}
