/*
 * REFERENCE IMPLEMENTATION OF some common utility functions
 *
 *
 * created: 13/10/25
 * updated: 12/11/25
 *
 *
 * Synopsis:
 * This file contains some common functions used in different scheme
 */
#include <algorithm>
#include <bitset>
#include <iomanip>
#include <iostream> // cin cout, unsigned integers
#include <fstream>  // files
#include <random>   // mt19937
#include <sstream>  //
#include <span>     // for outputstateinfo
#include <thread>   // thread
#include <vector>

using ull = unsigned long long; // 32 - 64 bits memory

using u8 = std::uint8_t;   // positive integer of 8 bits
using u16 = std::uint16_t; // positive integer of 16 bits
using u32 = std::uint32_t; // positive integer of 32 bits
using u64 = std::uint64_t; // positive integer of 64 bits
using u128 = __uint128_t;  // positive integer of 128 bits

#define GET_BIT(word, bit) (((word) >> (bit)) & 0x1)
#define SET_BIT(word, bit) ((word) |= (1ULL << (bit)))
#define UNSET_BIT(word, bit) ((word) &= ~(1ULL << (bit)))
#define TOGGLE_BIT(word, bit) ((word) ^= (1ULL << (bit)))

#define ROTATE_LEFT(x, n) (((x) << ((n) % (sizeof(x) * 8))) | ((x) >> ((sizeof(x) * 8) - ((n) % (sizeof(x) * 8)))))
#define ROTATE_RIGHT(x, n) (((x) >> ((n) % (sizeof(x) * 8))) | ((x) << ((sizeof(x) * 8) - ((n) % (sizeof(x) * 8)))))

inline thread_local std::mt19937 gen{std::random_device{}()};

template <typename T>
T RandomNumber(T min = 0, T max = std::numeric_limits<T>::max())
{
    std::uniform_int_distribution<T> dis(min, max);
    return dis(gen);
}

// a function which generates a random boolean value
bool RandomBoolean()
{
    std::bernoulli_distribution dis(0.5);
    return dis(gen);
}

namespace config
{
    enum class RoundGranularity : u8
    {
        Full = 1,
        Half = 2,
        Quarter = 4
    };

    inline bool is_valid_round(double r, RoundGranularity g)
    {
        const int step = static_cast<int>(g); // 1, 2, 4
        const double scaled = r * step;       // e.g. 7.5*2 = 15
        return std::fabs(scaled - std::round(scaled)) < 1e-9;
    }

    RoundGranularity detectGranularity(double r)
    {
        double frac = r - std::floor(r);
        if (std::fabs(frac * 4 - std::round(frac * 4)) < 1e-9)
            return RoundGranularity::Quarter;
        if (std::fabs(frac * 2 - std::round(frac * 2)) < 1e-9)
            return RoundGranularity::Half;
        return RoundGranularity::Full;
    }

    struct CipherInfo
    {
        std::string name;
        std::string description;
        int key_bits = 256;

        int nonce_bits = 96;
        int block_bits = 512;
        std::size_t words_in_state = 16;
        std::size_t word_size_bits = 32;

        std::string mode;
        double total_rounds = 0.0;
        RoundGranularity run_granularity = detectGranularity(total_rounds);

        //  Helpers
        bool totalRoundsAreFractional() const
        {
            double int_part;
            return std::modf(total_rounds, &int_part) > 0.0;
        }

        int roundedTotalRounds() const
        {
            return static_cast<int>(total_rounds);
        }

        bool isValidRoundCount() const { return is_valid_round(total_rounds, run_granularity); }
    };

    struct DifferentialInfo
    {
        double fwd_rounds = 0.0;               // total forward rounds (can be fractional)
        std::vector<std::pair<u16, u16>> id;   // input differences
        std::vector<std::pair<u16, u16>> mask; // output masks

        std::size_t output_precision = 0; // digits to print
        bool chosen_iv_flag = false;      // whether chosen IV is used
        RoundGranularity diff_granularity = detectGranularity(fwd_rounds);

        // Generic helpers
        bool fwdRoundsAreFractional() const
        {
            double ip;
            return std::modf(fwd_rounds, &ip) != 0.0;
        }
        int roundedFwdRounds() const { return static_cast<int>(fwd_rounds); }

        bool isValidForCipher(const CipherInfo &) const
        {
            return is_valid_round(fwd_rounds, diff_granularity);
        }
    };

    struct SamplesInfo
    {
        std::size_t samples_per_thread = 0;
        std::size_t samples_per_loop = 0;
        std::size_t total_loop_count = 0;

        const unsigned hw = std::thread::hardware_concurrency();
        std::size_t max_num_threads = hw ? hw - 1 : 1;

        std::string compiler_info = __VERSION__;
        std::string cpp_standard =
            (__cplusplus == 201703L) ? "C++17" : (__cplusplus == 202002L) ? "C++20"
                                             : (__cplusplus == 202302L)   ? "C++23"
                                                                          : "Unknown";

        std::size_t total_samples() const
        {
            return samples_per_loop * total_loop_count;
        }
    };

    /**
     * @brief Configuration for printing cipher internal state.
     *
     * Example:
     * ```cpp
     * uint32_t state[16] = {};
     * OutputStateConfig<uint32_t> cfg;
     * cfg.state = std::span<const uint32_t>(state, 16);
     * cfg.words_per_row = 8;  // print 8 words per row
     * ```
     *
     * 💡 Bonus tip:
     * You can easily view a subset of the state:
     * ```cpp
     * auto first_half = cfg.state.subspan(0, 8); // first 8 words
     * ```
     */
    template <typename T>
    struct OutputStateInfo
    {
        static_assert(std::is_integral_v<T> && std::is_unsigned_v<T>,
                      "State words must be an unsigned integral type");

        std::span<const T> state{};
        static constexpr std::size_t bit_size = sizeof(T) * 8;

        bool matrix_form = true;
        bool binary_form = false;
        std::string label = "State";

        std::size_t words_per_row = 4; // how many words per row when printing
        // bool ok() const noexcept
        // {
        //     return !state.empty() && (binary_form ^ hex_form);
        // }
    };

    template <class U>
    std::string formatWord(U v, bool hex = true, bool group = false, bool add_prefix = true)
    {
        static_assert(std::is_unsigned_v<U>, "U must be an unsigned integral type");
        const std::size_t Wbits = sizeof(U) * 8;
        std::string out;

        if (!hex)
        {
            if (add_prefix)
                out += "0b";
            if constexpr (sizeof(U) <= sizeof(ull))
            {
                std::string bits = std::bitset<sizeof(U) * 8>(static_cast<unsigned long long>(v)).to_string();
                if (group)
                {
                    for (std::size_t i = 0; i < bits.size(); ++i)
                    {
                        out.push_back(bits[i]);
                        if ((i + 1) % 8 == 0 && i + 1 != bits.size())
                            out.push_back(' ');
                    }
                }
                else
                {
                    out += bits;
                }
            }
            else
            {
                // manual for 128-bit (and beyond)
                for (std::size_t i = 0; i < Wbits; ++i)
                {
                    const std::size_t b = Wbits - 1 - i;
                    out.push_back(((v >> b) & U{1}) ? '1' : '0');
                    if (group && ((i + 1) % 8 == 0) && (i + 1 != Wbits))
                        out.push_back(' ');
                }
            }
            return out;
        }

        // hex path (works fine for 128-bit)
        if (add_prefix)
            out += "0x";
        const char *digits = "0123456789abcdef";
        const std::size_t H = Wbits / 4;
        for (std::size_t i = 0; i < H; ++i)
        {
            const std::size_t nib = (H - 1 - i) * 4;
            unsigned d = static_cast<unsigned>((v >> nib) & U{0xF});
            out.push_back(digits[d]);
            if (group && ((i + 1) % 2 == 0) && (i + 1 != H))
                out.push_back(' ');
        }
        return out;
    }
}

namespace ops
{
    template <typename T>
    void copyState(T *dst, const T *src, std::size_t start = 0, std::size_t end = 16)
    {
        if (!dst || !src)
            throw std::invalid_argument("copyState: null pointer");
        if (start > end)
            throw std::out_of_range("copyState: start > end");
        std::copy(src + start, src + end, dst + start); // OK for non-overlap
        // If you may copy within the same array and ranges overlap, prefer:
        // std::memmove(dst + start, src + start, (end - start) * sizeof(T));
    }

    template <typename T>
    void xorState(T *z, const T *x, const T *x1, size_t start = 0, size_t end = 16)
    {
        static_assert(std::is_unsigned_v<T>, "xor_state_oop requires an unsigned integer type");

        if (x1 == nullptr)
            throw std::invalid_argument("x1 pointer cannot be nullptr");

        if (start >= end)
            throw std::out_of_range("Invalid range: start must be < end");

        for (size_t i = start; i < end; ++i)
            z[i] = x[i] ^ x1[i];
    }
    template <typename T>
    void addState(T *z, const T *x, const T *x1, size_t start = 0, size_t end = 16)
    {
        static_assert(std::is_unsigned_v<T>,
                      "add_state_oop requires an unsigned integer type for modular wraparound.");

        if (!z || !x || !x1)
            throw std::invalid_argument("add_state_oop: z, x, and x1 pointers must be non-null");

        if (start >= end)
            throw std::out_of_range("add_state_oop: start must be less than end");

        for (size_t i = start; i < end; ++i)
            z[i] = x[i] + x1[i];
    }

    template <typename T>
    void minusState(T *z, const T *x, const T *x1,
                    size_t start = 0, size_t end = 16)
    {
        static_assert(std::is_unsigned_v<T>,
                      "subtract_state_oop requires an unsigned integer type for modular subtraction.");

        if (!z || !x || !x1)
            throw std::invalid_argument("subtract_state_oop: z, x, and x1 must be non-null");
        if (start >= end)
            throw std::out_of_range("subtract_state_oop: start must be less than end");

        for (size_t i = start; i < end; ++i)
            z[i] = x[i] - x1[i]; // wraparound subtraction (mod 2^w)
    }
    template <typename T>
    void resetState(T *arr, std::size_t start = 0, std::size_t end = 16, const T value = 0)
    {
        if (!arr)
            throw std::invalid_argument("resetState: null pointer");
        if (start >= end)
            throw std::out_of_range("resetState: start must be < end");

        std::fill(arr + start, arr + end, value);
    }
    /**
     * Extracts bits from position [start, end] (inclusive) from an unsigned integer.
     * Example: bitSegment(0b11101100, 2, 4) → 0b101  (extracts bits 4,3,2)
     */
    template <typename T>
    constexpr T bitSegment(T word, int start, int end)
    {
        static_assert(std::is_unsigned_v<T>, "bit_segment requires an unsigned integer type");

        const int width = end - start + 1;
        const int bit_size = std::numeric_limits<T>::digits;

        // Optional runtime safety checks (remove for max performance)
        if (start < 0 || end >= bit_size || start > end)
        {
            throw std::out_of_range("Invalid bit range in bit_segment()");
        }

        // Avoid UB when width == bit_size
        T mask = (width == bit_size) ? std::numeric_limits<T>::max()
                                     : ((T(1) << width) - 1);

        return (word >> start) & mask;
    }

    inline void write_message(std::ofstream *file,
                              bool filesave,
                              const std::string &msg,
                              bool coutflag = true)
    {
        if (coutflag)
            std::cout << msg;

        if (filesave && file && file->is_open())
            *file << msg;
    }

    template <typename T, std::size_t N>
    void stringToState(const std::string &str, T (&out)[N], bool hexflag = true)
    {
        static_assert(std::is_unsigned_v<T>, "T must be unsigned");
        constexpr std::size_t BITS = sizeof(T) * 8;
        constexpr std::size_t HEX_CH = BITS / 4;

        std::string s = str;

        if (!hexflag)
        {
            if (s.rfind("0b", 0) == 0 || s.rfind("0B", 0) == 0)
                s = s.substr(2);
            if (s.size() != BITS * N)
                throw std::runtime_error("Binary length mismatch");
            for (std::size_t i = 0; i < N; ++i)
            {
                std::string chunk = s.substr(i * BITS, BITS);
                std::bitset<BITS> bits(chunk);
                out[i] = static_cast<T>(bits.to_ullong());
            }
        }
        else
        {
            if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0)
                s = s.substr(2);
            if (s.size() != HEX_CH * N)
                throw std::runtime_error("Hex length mismatch");
            for (std::size_t i = 0; i < N; ++i)
            {
                std::string chunk = s.substr(i * HEX_CH, HEX_CH);
                out[i] = static_cast<T>(std::stoull(chunk, nullptr, 16));
            }
        }
    }

    template <typename T>
    std::string stateToString(const T *x, bool hexflag = true, std::size_t count = 4)
    {
        static_assert(std::is_unsigned_v<T>, "T must be unsigned");
        if (!x)
            throw std::invalid_argument("stateToString: null pointer");

        constexpr std::size_t BITS = sizeof(T) * 8;
        constexpr std::size_t HEX_PER_WORD = BITS / 4;

        if (!hexflag)
        {
            std::string result;
            result.reserve(2 + BITS * count);
            result += "0b";
            for (std::size_t i = 0; i < count; ++i)
                result += std::bitset<BITS>(x[i]).to_string();
            return result;
        }
        else
        {
            std::ostringstream oss;
            oss << "0x";
            for (std::size_t i = 0; i < count; ++i)
            {
                oss << std::hex << std::nouppercase
                    << std::setw(static_cast<int>(HEX_PER_WORD))
                    << std::setfill('0')
                    << static_cast<unsigned long long>(x[i]);
            }
            return oss.str();
        }
    }

    template <std::size_t N>
    bool matchBitsWithStars(const std::string &diff, const std::string &pat)
    {
        std::string d = diff;
        std::string p = pat;

        // --- Detect format (binary or hex) ---
        bool hex_mode = false;
        if ((d.rfind("0x", 0) == 0 || d.rfind("0X", 0) == 0) ||
            (p.rfind("0x", 0) == 0 || p.rfind("0X", 0) == 0))
            hex_mode = true;

        // --- Strip prefixes ---
        if (hex_mode)
        {
            if (d.rfind("0x", 0) == 0 || d.rfind("0X", 0) == 0)
                d = d.substr(2);
            if (p.rfind("0x", 0) == 0 || p.rfind("0X", 0) == 0)
                p = p.substr(2);

            // Convert hex to binary (each hex char = 4 bits)
            auto hexToBin = [](const std::string &hex)
            {
                std::string bin;
                bin.reserve(hex.size() * 4);
                for (char c : hex)
                {
                    unsigned val;
                    if (c >= '0' && c <= '9')
                        val = c - '0';
                    else if (c >= 'a' && c <= 'f')
                        val = c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F')
                        val = c - 'A' + 10;
                    else if (c == '*')
                    {
                        bin += "****";
                        continue;
                    }
                    else
                        throw std::runtime_error("Invalid hex char in pattern");
                    for (int i = 3; i >= 0; --i)
                        bin.push_back(((val >> i) & 1) ? '1' : '0');
                }
                return bin;
            };

            d = hexToBin(d);
            p = hexToBin(p);
        }
        else
        {
            if (d.rfind("0b", 0) == 0 || d.rfind("0B", 0) == 0)
                d = d.substr(2);
            if (p.rfind("0b", 0) == 0 || p.rfind("0B", 0) == 0)
                p = p.substr(2);
        }

        // --- Validation ---
        if (d.size() != N || p.size() != N)
            throw std::runtime_error("Both strings must be exactly " + std::to_string(N) + " bits after conversion.");

        // --- Matching ---
        for (std::size_t i = 0; i < N; ++i)
        {
            char pc = p[i];
            if (pc == '*')
                continue; // wildcard
            if (pc != '0' && pc != '1')
                throw std::runtime_error("Pattern contains invalid char (use 0/1/*).");
            if (d[i] != pc)
                return false;
        }
        return true;
    }

    template <class T>
    inline int hammingWeight(T x)
    {
        static_assert(std::is_unsigned_v<T>, "T must be an unsigned integer type");
        if constexpr (sizeof(T) <= 4)
            return __builtin_popcount(static_cast<unsigned>(x));
        else if constexpr (sizeof(T) <= 8)
            return __builtin_popcountll(static_cast<unsigned long long>(x));
        else
        {
            // 128-bit (and wider) – split into 64-bit chunks
            int hw = 0;
            constexpr int bits = std::numeric_limits<T>::digits;
            for (int off = 0; off < bits; off += 64)
                hw += __builtin_popcountll(static_cast<ull>((x >> off) & T{0xFFFFFFFFFFFFFFFFULL}));
            return hw;
        }
    }

    // array overload (prevents decay to pointer)
    template <class T, std::size_t N>
    inline int hammingWeight(const T (&arr)[N])
    {
        static_assert(std::is_unsigned_v<T>, "T must be an unsigned integer type");
        int hw = 0;
        for (std::size_t i = 0; i < N; ++i)
            hw += hammingWeight(arr[i]);
        return hw;
    }

    // out stores the count of set bits from each word from the state in
    template <typename T>
    void hammingState(const T *in, T *out, std::size_t size)
    {
        static_assert(std::is_unsigned_v<T>, "hw_state requires an unsigned integer type");
        for (std::size_t i = 0; i < size; ++i)
        {
            if constexpr (sizeof(T) <= 4)
                out[i] = __builtin_popcount(static_cast<unsigned>(in[i]));
            else
                out[i] = __builtin_popcountll(static_cast<unsigned long long>(in[i]));
        }
    }
}

namespace display
{
    constexpr int WIDTH_PNB = 9;
    constexpr int WIDTH_INDEX = 11;
    constexpr int WIDTH_COORD = 13;
    constexpr int WIDTH_NM = 10;
    constexpr int WIDTH_TIME = 12;
    constexpr int WIDTH_LOOP = 12;
    constexpr int WIDTH_PROB = 28;
    constexpr int WIDTH_BIAS = 23;
    constexpr int WIDTH_CORR = 23;
    constexpr int WIDTH_REM = 14;

    // ------------------------------------------------------
    // Visible width helper (UTF-8 codepoint count ≈ width 1)
    // NOTE: This is a simplification; CJK/emoji may misalign.
    // ------------------------------------------------------
    inline int visibleWidth(const std::string &text)
    {
        int width = 0;
        for (size_t i = 0; i < text.size();)
        {
            unsigned char c = static_cast<unsigned char>(text[i]);
            if (c >= 0xF0 && i + 3 < text.size())
            {
                width += 1;
                i += 4;
            } // 4-byte UTF-8
            else if (c >= 0xE0 && i + 2 < text.size())
            {
                width += 1;
                i += 3;
            } // 3-byte UTF-8
            else if (c >= 0xC0 && i + 1 < text.size())
            {
                width += 1;
                i += 2;
            } // 2-byte UTF-8
            else
            {
                width += 1;
                i += 1;
            } // ASCII / invalid fallback
        }
        return width;
    }

    // ------------------------------------------------------
    // Center text to width (no truncation for Unicode)
    // ------------------------------------------------------
    inline std::string center(std::string_view text, int width)
    {
        const int len = visibleWidth(std::string(text));
        if (width <= len)
            return std::string(text);
        const int pad = (width - len) / 2;
        const int pad2 = (width - len) - pad;
        return std::string(pad, ' ') + std::string(text) + std::string(pad2, ' ');
    }

    // ------------------------------------------------------
    // Format value alongside its power-of-two magnitude:
    //   "p ~ 2^{log2(p)}"
    // Uses abs for exponent; sign shown in decimal term.
    // ------------------------------------------------------
    inline std::string fmtValueAsPower2(double val, int precision = 5)
    {
        if (val == 0.0)
        {
            std::ostringstream z;
            z << std::fixed << std::setprecision(precision) << 0.0;
            return z.str() + " ~ 2^{ -∞ }";
        }
        const double absv = std::fabs(val);
        const double e = std::log2(absv); // e.g., -7 for 2^-7
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(precision) << val
           << " ~ 2^{" << std::setprecision(2) << e << "}";
        return ss.str();
    }

    // ------------------------------------------------------
    // Duration formatting: milliseconds -> "Hh Mm Ss ms"
    // ------------------------------------------------------
    inline std::string fmtDurationMS(int duration_ms)
    {
        int total_sec = duration_ms / 1000;
        int milli = duration_ms % 1000;
        int hour = total_sec / 3600;
        int min = (total_sec / 60) % 60;
        int sec = total_sec % 60;

        std::ostringstream ss;
        if (hour)
            ss << hour << "h ";
        if (min)
            ss << min << "m ";
        if (sec)
            ss << sec << "s ";
        if (milli || (!hour && !min && !sec))
            ss << milli << "ms";
        return ss.str();
    }

    // ------------------------------------------------------
    // Timestamp banner (thread-safe localtime)
    // ------------------------------------------------------
    inline std::string fmtTime(const std::string &label)
    {
        using namespace std::chrono;
        auto now = system_clock::now();
        std::time_t t = system_clock::to_time_t(now);
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        std::ostringstream oss;
        oss << "######## " << label << " on: "
            << std::put_time(&tm, "%d/%m/%Y at %H:%M:%S")
            << " ########\n";
        return oss.str();
    }

    // ------------------------------------------------------
    // Borders & headers
    // ------------------------------------------------------
    inline void printBiasBorder(std::ostream &out)
    {
        out << "+" << std::string(WIDTH_LOOP, '-') << "+"
            << std::string(WIDTH_PROB, '-') << "+"
            << std::string(WIDTH_BIAS, '-') << "+"
            << std::string(WIDTH_CORR, '-') << "+"
            << std::string(WIDTH_TIME, '-') << "+"
            << std::string(WIDTH_REM, '-') << "+\n";
    }

    inline void printPNBborder(std::ostream &out)
    {
        out << "+"
            << std::string(WIDTH_PNB, '-') << "+"
            << std::string(WIDTH_INDEX, '-') << "+"
            << std::string(WIDTH_COORD, '-') << "+"
            << std::string(WIDTH_NM, '-') << "+"
            << std::string(WIDTH_TIME, '-') << "+"
            << "\n";
    }

    inline void printBiasHeader(std::ostream &out)
    {
        printBiasBorder(out);
        out << "|"
            << center("Loop #", WIDTH_LOOP) << "|"
            << center("Probability", WIDTH_PROB) << "|"
            << center("Bias", WIDTH_BIAS) << "|"
            << center("Correlation", WIDTH_CORR) << "|"
            << center("Exec. Time", WIDTH_TIME) << "|"
            << center("Remark", WIDTH_REM) << "|\n";
        printBiasBorder(out);
    }

    inline void printPNBheader(std::ostream &out)
    {
        printPNBborder(out);
        out << "|"
            << center("PNB #", WIDTH_PNB) << "|"
            << center("PNB Index", WIDTH_INDEX) << "|"
            << center("(Word, Bit)", WIDTH_COORD) << "|"
            << center("NM", WIDTH_NM) << "|"
            << center("Exec. Time", WIDTH_TIME) << "|"
            << "\n";
        printPNBborder(out);
    }

    // ------------------------------------------------------
    // Rows
    // ------------------------------------------------------
    inline void outputBias(int loop, double prob, double bias, double corr,
                           int duration_ms, bool remark_flag, int remark_count,
                           std::ostream &out, bool hide_bias_corr = false)
    {
        const std::string remark = remark_flag ? "✓ (" + std::to_string(remark_count) + ")" : "x";
        const std::string time_str = fmtDurationMS(duration_ms);

        out << "|"
            << center(std::to_string(loop), WIDTH_LOOP) << "|"
            << center(fmtValueAsPower2(prob, 10), WIDTH_PROB) << "|";

        if (!hide_bias_corr)
        {
            out << center(fmtValueAsPower2(std::fabs(bias)), WIDTH_BIAS) << "|"
                << center(fmtValueAsPower2(std::fabs(corr)), WIDTH_CORR) << "|";
        }
        else
        {
            out << center("-", WIDTH_BIAS) << "|"
                << center("-", WIDTH_CORR) << "|";
        }

        out << center(time_str, WIDTH_TIME) << "|"
            << center(remark, WIDTH_REM) << "|\n";
    }

    void showBasicConfig(const config::CipherInfo &cfg, std::ostream &output)
    {
        output << "\n+----------------------------------[ Basic Config ]-----------------------------------+\n";
        if (!cfg.name.empty())
            output << "| Cipher:            " << cfg.name << "-" << cfg.key_bits << "\n";
        if (!cfg.mode.empty())
            output << "| Mode:              " << cfg.mode << "\n";
        if (cfg.total_rounds > 0.0)
            output << "| Total Rounds:      " << cfg.total_rounds << "\n";
        output << "+-------------------------------------------------------------------------------------+\n";
                
    }

    void showDiffConfig(const config::DifferentialInfo &cfg, std::ostream &output)
    {
        output << "\n+------------------------------[ Distinguisher Config ]-------------------------------+\n";

        if (cfg.fwd_rounds > 0.0)
            output << "| Forward Round:     " << cfg.fwd_rounds << "\n";

        if (cfg.chosen_iv_flag)
            output << "| Chosen IV Mode:    " << cfg.chosen_iv_flag <<"\n";

        if (!cfg.id.empty())
        {
            output << "| Input Difference:  ";
            for (auto it = cfg.id.begin(); it != cfg.id.end(); ++it)
            {
                const auto [w, b] = *it;
                output << "(W" << w << ", b" << b << ")";
                if (std::next(it) != cfg.id.end())
                    output << " ⊕ ";
            }
            output << "\n";

            output << "|  ↳ Means flipping: ";
            for (const auto &[w, b] : cfg.id)
                output << "[bit " << b << " of word " << w << "] ";
            output << "\n";
        }

        if (!cfg.mask.empty())
        {
            output << "| Output Mask:       ";
            for (const auto &[w, b] : cfg.mask)
                output << "(W" << w << ", b" << b << ") ";
            output << "\n";

            output << "|  ↳ Correlation is computed by the parity of ";
            for (auto it = cfg.mask.begin(); it != cfg.mask.end(); ++it)
            {
                const auto [w, b] = *it;
                output << "(bit " << b << " of word " << w << ")";
                if (std::next(it) != cfg.mask.end())
                    output << " ⊕ ";
            }
            output << "\n";
        }

        output << "+-------------------------------------------------------------------------------------+\n";
                
    }

    void showSamplesConfig(const config::SamplesInfo &cfg, std::ostream &output)
    {
        output << "\n+-------------------------------[ Samples Config ]------------------------------------+\n";
        output << "| # threads:              " << cfg.max_num_threads << "\n";
        if (cfg.samples_per_thread > 0)
            output << "| Samples per Thread:    2^{" << log2(cfg.samples_per_thread) << "}\n";
        if (cfg.samples_per_loop > 0)
            output << "| Samples per Loop:      2^{" << log2(cfg.samples_per_loop) << "}\n";
        if (cfg.total_loop_count > 0)
            output << "| Total Loops:           2^{" << log2(cfg.total_loop_count) << "}\n";
        output << "+-------------------------------------------------------------------------------------+\n";
    }

    template <typename T>
    inline void showState(const config::OutputStateInfo<T> &cfg, std::ostream &os = std::cout)
    {
        // if (!cfg.ok())
        // {
        //     os << "⚠ No state data to print or invalid format selection.\n";
        //     return;
        // }

        // Optional label
        if (!cfg.label.empty())
            os << "\n"
               << cfg.label << " (" << cfg.state.size() << " words):\n";

        // Save & restore stream flags/fill
        const auto old_flags = os.flags();
        const auto old_fill = os.fill();

        constexpr std::size_t BITS = std::numeric_limits<T>::digits; // bit width of T
        const int HEXW = static_cast<int>((BITS + 3) / 4);           // hex chars per word

        for (std::size_t i = 0; i < cfg.state.size(); ++i)
        {
            if (cfg.matrix_form && (i % cfg.words_per_row == 0))
                os << "|";

            if (cfg.binary_form)
            {
                os << config::formatWord(cfg.state[i], false, true) << '|';

                // bitset size is a compile-time constant; works because BITS is constexpr
                // std::bitset<BITS> bits(cfg.state[i]);
                // os << bits.to_string() << ' ';
            }
            else
            { // hex_form
                os << "0x" << std::hex << std::nouppercase
                   << std::setw(HEXW) << std::setfill('0')
                   << static_cast<unsigned long long>(cfg.state[i]) << '|';
            }

            if (cfg.matrix_form && ((i + 1) % cfg.words_per_row == 0))
                os << "\n";
        }
        if (cfg.matrix_form && (cfg.state.size() % cfg.words_per_row != 0))
            os << "\n";

        // restore stream state
        os.fill(old_fill);
        os.flags(old_flags);
    }
}

/**
 * @brief Lightweight timer with thread-safe timestamps and precise elapsed time.
 *
 * Uses std::steady_clock for durations (monotonic, not affected by NTP/clock jumps)
 * and std::system_clock only for human-readable start/end timestamps.
 *
 * Example:
 *   Timer t;
 *   std::cout << t.start_message();
 *   // ... work ...
 *   std::cout << t.end_message();
 */
class Timer
{
private:
    using steady_clock = std::chrono::steady_clock;
    using system_clock = std::chrono::system_clock;

    steady_clock::time_point start_wall_;
    std::clock_t start_cpu_;

    static std::tm safe_localtime(std::time_t t)
    {
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &t);
#else
        localtime_r(&t, &tm);
#endif
        return tm;
    }

public:
    /// Start immediately.
    Timer() : start_wall_(steady_clock::now()), start_cpu_(std::clock()) {}

    /// Reset the starting points.
    void reset()
    {
        start_wall_ = steady_clock::now();
        start_cpu_ = std::clock();
    }

    /// Elapsed wall time in milliseconds since construction/reset.
    long long elapsed_ms() const
    {
        auto now = steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now - start_wall_).count();
    }

    /// Elapsed CPU time (process) in milliseconds since construction/reset.
    double cpu_ms() const
    {
        std::clock_t now = std::clock();
        return 1000.0 * (now - start_cpu_) / CLOCKS_PER_SEC;
    }

    /// Pretty start banner with current local time.
    std::string start_message() const
    {
        return display::fmtTime("Execution started");
    }

    /// Pretty end banner including wall & CPU duration since start/reset.
    std::string end_message() const
    {
        const long long wall_ms = elapsed_ms();
        const double cpu = cpu_ms();

        std::ostringstream ss;
        ss << display::fmtTime("Execution ended");
        ss << "Wall time elapsed: " << display::fmtDurationMS(wall_ms) << "\n";
        ss << "CPU time used:     " << std::fixed << std::setprecision(3) << cpu << " ms\n";
        return ss.str();
    }
};
