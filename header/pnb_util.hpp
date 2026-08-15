/*
 * Filename: pnb_util.hpp
 *
 * PNB (Probabilistic Neutral Bits) helpers: load PNB indices from file or
 * vector, optionally categorize into pattern / border / isolated buckets,
 * and materialize per-bucket bitmasks for randomization.
 *
 * Example:
 *
 *   #include "common_utility/pnb_util.hpp"
 *   #include "common_utility/random_util.hpp"
 *   #include "chacha.hpp"
 *
 *   // 1. Stage PNB indices (sort + dedupe + categorize done in one call):
 *   pnb::Config cfg;
 *   cfg.all               = {0, 5, 10, 15, 31, 32, 33};
 *   cfg.use_pattern_split = true;     // fills pattern / border / isolated
 *   pnb::load_from_vector(cfg);       // or pnb::load_from_file("pnbs.txt", cfg)
 *
 *   // 2. Build per-bucket bitmasks via the cipher's calc_word_bit:
 *   pnb::Masks<u32> masks(cfg, &chacha::calculate_word_bit<u32>);
 *
 *   // 3. Randomize only the key bits flagged in masks.all:
 *   u32 state[16] = { ... };
 *   for (std::size_t w = 0; w < 16; ++w) {
 *       const u32 r = random_util::random_number<u32>();
 *       state[w] = (state[w] & ~masks.all[w]) | (r & masks.all[w]);
 *   }
 *
 *   // Buckets masks.pattern / masks.border / masks.isolated are populated
 *   // when cfg.use_pattern_split is true; randomize each bucket independently
 *   // when an attack treats the categories differently.
 */

#pragma once

#include <algorithm>
#include <array>
#include <concepts>
#include <fstream>
#include <iostream>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include "core_types.hpp"

namespace pnb
{
    // ------- Configuration -------

    struct Config
    {
        std::string file_path;
        bool use_pattern_split = false; // Split cfg.all into pattern/border/isolated

        std::vector<u16> all;      // All PNB indices (sorted, unique)
        std::vector<u16> pattern;  // Consecutive-run members except the last
        std::vector<u16> border;   // Last member of each consecutive run
        std::vector<u16> isolated; // Singleton PNBs
    };

    enum class LoadStatus
    {
        Ok,       // PNBs loaded successfully
        NotFound, // File could not be opened
        Empty,    // File opened but contained no PNBs
        Invalid   // File contained an out-of-range value
    };

    // ------- Categorization -------

    /// Splits a sorted index list into pattern / border / isolated buckets.
    /// Example: [1,2,3, 7,8, 12] -> pattern:[1,2, 7], border:[3,8], isolated:[12]
    inline std::tuple<std::vector<u16>, std::vector<u16>, std::vector<u16>>
    categorize(const std::vector<u16> &indices)
    {
        if (indices.empty())
            return {{}, {}, {}};

        std::vector<u16> pattern, border, isolated, run;
        run.reserve(indices.size());

        auto flush_run = [&]()
        {
            if (run.size() >= 2)
            {
                pattern.insert(pattern.end(), run.begin(), run.end() - 1);
                border.push_back(run.back());
            }
            else if (!run.empty())
            {
                isolated.push_back(run[0]);
            }
            run.clear();
        };

        run.push_back(indices[0]);
        for (std::size_t i = 1; i < indices.size(); ++i)
        {
            if (indices[i] == run.back() + 1)
                run.push_back(indices[i]);
            else
            {
                flush_run();
                run.push_back(indices[i]);
            }
        }
        flush_run();

        return {pattern, border, isolated};
    }

    namespace detail
    {
        /// Sort, dedupe, and (optionally) categorize cfg.all into the buckets.
        /// Shared between load_from_file and load_from_vector.
        inline void finalize(Config &cfg)
        {
            std::sort(cfg.all.begin(), cfg.all.end());
            cfg.all.erase(std::unique(cfg.all.begin(), cfg.all.end()), cfg.all.end());

            if (cfg.use_pattern_split)
            {
                auto [pat, bor, iso] = categorize(cfg.all);
                cfg.pattern  = std::move(pat);
                cfg.border   = std::move(bor);
                cfg.isolated = std::move(iso);
            }
            else
            {
                cfg.pattern.clear();
                cfg.border.clear();
                cfg.isolated.clear();
            }
        }
    }

    // ------- Bitmask Generation -------

    template <std::unsigned_integral T, std::size_t NumWords = 16>
    struct Masks
    {
        static_assert(sizeof(T) <= 8, "pnb::Masks<T>: T must be at most 64-bit");

        using CalcPosition = void (*)(u16 index, u16 &word, u16 &bit);

        std::array<T, NumWords> pattern{};
        std::array<T, NumWords> border{};
        std::array<T, NumWords> isolated{};
        std::array<T, NumWords> all{};

        Masks() = default;
        Masks(const Config &cfg, CalcPosition calc) { build(cfg, calc); }

        void build(const Config &cfg, CalcPosition calc)
        {
            if (!calc)
                throw std::invalid_argument("pnb::Masks::build: calc function is null");

            pattern.fill(0);
            border.fill(0);
            isolated.fill(0);
            all.fill(0);

            constexpr u16 word_bits = static_cast<u16>(sizeof(T) * 8);

            auto set_bit = [&](u16 idx, std::array<T, NumWords> &mask_arr)
            {
                u16 word = 0, bit = 0;
                calc(idx, word, bit);

                if (word >= NumWords)
                    throw std::out_of_range(
                        "pnb::Masks::build: calc returned word >= NumWords");
                if (bit >= word_bits)
                    throw std::out_of_range(
                        "pnb::Masks::build: calc returned bit >= sizeof(T)*8");

                mask_arr[word] |= (static_cast<T>(1) << bit);
            };

            for (u16 idx : cfg.pattern)  set_bit(idx, pattern);
            for (u16 idx : cfg.border)   set_bit(idx, border);
            for (u16 idx : cfg.isolated) set_bit(idx, isolated);
            for (u16 idx : cfg.all)      set_bit(idx, all);
        }
    };

    // ------- Loading PNBs -------

    /// Load PNBs from a file (whitespace or comma-separated integers).
    /// Each value must be in [0, max_key_size). Default 256 covers all
    /// current ciphers' 256-bit keys (raise if working with longer keys).
    inline LoadStatus load_from_file(const std::string &filename,
                                     Config &cfg,
                                     int max_key_size  = 256,
                                     std::ostream &err = std::cerr)
    {
        std::ifstream file(filename);
        if (!file.is_open())
        {
            err << "[pnb] could not open file: " << filename << "\n";
            return LoadStatus::NotFound;
        }

        std::vector<u16> values;
        std::string line;

        while (std::getline(file, line))
        {
            std::replace(line.begin(), line.end(), ',', ' ');
            std::istringstream iss(line);
            int v;
            while (iss >> v)
            {
                if (v < 0 || v >= max_key_size)
                {
                    err << "[pnb] invalid value " << v
                        << " in " << filename
                        << " (expected [0, " << max_key_size << "))\n";
                    return LoadStatus::Invalid;
                }
                values.push_back(static_cast<u16>(v));
            }
        }

        if (values.empty())
        {
            err << "[pnb] no values in " << filename << "\n";
            return LoadStatus::Empty;
        }

        cfg.all = std::move(values);
        detail::finalize(cfg);
        return LoadStatus::Ok;
    }

    /// Finalize cfg.all in place (sort, dedupe, optionally categorize).
    inline LoadStatus load_from_vector(Config &cfg)
    {
        if (cfg.all.empty())
            return LoadStatus::Empty;
        detail::finalize(cfg);
        return LoadStatus::Ok;
    }
}
