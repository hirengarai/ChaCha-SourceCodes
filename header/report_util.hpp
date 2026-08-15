/*
 * Filename: report_util.hpp
 *
 * Helpers for cipher design-check / experiment runs:
 *   - Section separator and state hex printer (formatting)
 *   - Wall+steady run timer and duration formatter (timing)
 *   - Compiler / C++ standard introspection (environment)
 *
 * One include gives a script everything it needs to produce a readable run
 * report from start to finish.
 */

#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <iomanip>
#include <ios>
#include <iostream>
#include <sstream>
#include <string>

namespace report_util
{
    // ---------- formatting ----------

    inline constexpr const char *SEP =
        ":=:=:=:=:=:=:=:=::=:=:=:=:=:=:=:=::=:=:=:=:=:=:=:=::=:=:=:=:=:=:=:=:\n";

    /// Hex-dump `count` words from `state` in rows of `cols_per_row`.
    /// Width is auto-derived from sizeof(T); cast widens to unsigned long long
    /// so u8 prints as a number rather than a character glyph.
    template <typename T>
    inline void print_state_hex(const T *state,
                                std::size_t count,
                                std::size_t cols_per_row,
                                const std::string &label = "")
    {
        if (!label.empty())
            std::cout << label << "\n";

        const std::ios::fmtflags saved_flags = std::cout.flags();
        const char saved_fill                = std::cout.fill('0');
        const int hex_width                  = sizeof(T) * 2;

        std::cout << std::hex;
        for (std::size_t i = 0; i < count; ++i)
        {
            std::cout << "0x" << std::setw(hex_width)
                      << static_cast<unsigned long long>(state[i]);
            const bool last_in_row  = ((i + 1) % cols_per_row == 0);
            const bool last_overall = (i + 1 == count);
            if (last_in_row || last_overall)
                std::cout << "\n";
            else
                std::cout << " ";
        }

        std::cout.flags(saved_flags);
        std::cout.fill(saved_fill);
    }

    // ---------- duration formatting ----------

    /// Converts milliseconds into a readable h/m/s/ms string format.
    inline std::string format_duration(std::chrono::milliseconds duration)
    {
        long long total_ms = std::max(0LL, static_cast<long long>(duration.count()));

        if (total_ms < 1000)
            return std::to_string(total_ms) + "ms";

        long long hours = total_ms / 3600000;
        total_ms %= 3600000;
        long long minutes = total_ms / 60000;
        total_ms %= 60000;
        long long seconds = total_ms / 1000;
        long long millis  = total_ms % 1000;

        std::ostringstream oss;
        if (hours > 0)
            oss << hours << "h ";
        if (minutes > 0)
            oss << minutes << "m ";
        if (seconds > 0)
            oss << seconds << "s ";
        if (millis > 0)
            oss << millis << "ms";

        std::string result = oss.str();
        if (!result.empty() && result.back() == ' ')
            result.pop_back();
        return result;
    }

    // ---------- run timer ----------

    struct RunTimer
    {
        std::chrono::system_clock::time_point wall_start_{std::chrono::system_clock::now()};
        std::chrono::steady_clock::time_point prog_start_{std::chrono::steady_clock::now()};

        static std::tm local_time(std::time_t t)
        {
            std::tm tm{};
#ifdef _WIN32
            localtime_s(&tm, &t);
#else
            localtime_r(&t, &tm);
#endif
            return tm;
        }

        /// Prints the formatted start time to the provided stream.
        void print_start(const char *format = "%Y-%m-%d %H:%M:%S",
                         std::ostream &os   = std::cout) const
        {
            auto t  = std::chrono::system_clock::to_time_t(wall_start_);
            auto tm = local_time(t);
            os << "///---///---///--- Commencing entropy hunt on: "
               << std::put_time(&tm, format) << " ---///---///---///\n";
        }

        /// Returns the elapsed execution time in milliseconds.
        std::chrono::milliseconds elapsed() const
        {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - prog_start_);
        }

        /// Prints the formatted end time AND total elapsed duration to the provided stream.
        void print_end(const char *format = "%Y-%m-%d %H:%M:%S",
                       std::ostream &os   = std::cout) const
        {
            auto now = std::chrono::system_clock::now();
            auto t   = std::chrono::system_clock::to_time_t(now);
            auto tm  = local_time(t);
            os << "///---///---///--- State space exhausted on: "
               << std::put_time(&tm, format) << " ---///---///---///\n";
            os << "///---///---///--- Time lost to the cipher : "
               << format_duration(elapsed()) << " ---///---///---///\n";
        }
    };

    // ---------- compiler & C++ standard ----------

    /// Returns a string identifying the compiler and its version.
    inline std::string compiler_info()
    {
#if defined(_MSC_VER)
        return "MSVC " + std::to_string(_MSC_VER);
#elif defined(__VERSION__)
        return __VERSION__;
#else
        return "Unknown compiler";
#endif
    }

    /// Prints the compiler version and C++ standard to the provided stream.
    inline void print_environment(std::ostream &os = std::cout)
    {
        os << "Compiler: " << compiler_info() << "\n";

        std::string standard = "Unknown";
        if (__cplusplus == 201703L)
            standard = "C++17";
        else if (__cplusplus == 202002L)
            standard = "C++20";
        else if (__cplusplus == 202302L)
            standard = "C++23";

        os << "Standard: " << standard << "\n";
    }
}
