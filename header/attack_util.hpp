/*
 * Filename: attack_util.hpp
 *
 * Cryptanalysis-attack helpers: parameter structs for sampling and for
 * differential / linear trail experiments.
 */

#pragma once

#include <limits>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "core_types.hpp"

namespace attack_util
{
    // ---------- thread-safe sampling distribution ---------

    struct SamplingParams
    {
        std::size_t samples_per_thread_ = 0;
        std::size_t num_batches_        = 0;

        // Uses hardware_concurrency to leave 1 core free for the OS
        std::size_t max_num_threads_ = []()
        {
            unsigned hw = std::thread::hardware_concurrency();
            return hw > 1 ? hw - 1 : 1;
        }();

        /// Returns total samples per batch across all threads.
        std::size_t samples_per_batch() const
        {
            if (samples_per_thread_ == 0)
                return 0;
            constexpr std::size_t max_val = std::numeric_limits<std::size_t>::max();
            if (max_num_threads_ > max_val / samples_per_thread_)
                return max_val;
            return samples_per_thread_ * max_num_threads_;
        }

        /// Returns the absolute total samples for the entire run.
        std::size_t total_samples() const
        {
            const std::size_t batch = samples_per_batch();
            if (batch == 0 || num_batches_ == 0)
                return 0;
            constexpr std::size_t max_val = std::numeric_limits<std::size_t>::max();
            if (batch > max_val / num_batches_)
                return max_val;
            return batch * num_batches_;
        }
    };

    // ---------- attack boundary data ---------

    using BitPos = std::pair<u16, u16>;

    struct AttackParams
    {
        double round_start_ = 0.0;
        double round_end_   = 0.0;

        // Coordinate-based bit positions for programmatic manipulation
        std::vector<BitPos> input_diff_bits_;
        std::vector<BitPos> output_diff_bits_;

        // String-based bit patterns for parsing from OCP/autoguess files
        std::string input_diff_str_;
        std::string output_diff_str_;

        std::vector<BitPos> output_mask_bits_;
        std::string         output_mask_str_; // e.g. "0x0000000002000000" for bit 25
    };
}
