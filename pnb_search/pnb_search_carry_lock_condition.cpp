/*
 * Filename: pnb_search_carry_lock_condition.cpp
 *
 * Synopsis:
 * Multi-threaded PNB (Probabilistic Neutral Bits) search for ChaCha with a
 * per-bit CARRY-LOCK rejection. For each candidate key bit (key_word,
 * key_bit), the forward path is rerun until the carry-lock conditions hold
 * for that single bit position:
 *   (1) bit `key_bit` of sumstate[w]  is set
 *   (2) bit `key_bit` of dsumstate[w] is set
 *   (3) (sumstate[w]  mod 2^key_bit) >= (strdx0[w]  mod 2^key_bit)
 *   (4) (dsumstate[w] mod 2^key_bit) >= (dstrdx0[w] mod 2^key_bit)
 * where w = key_word + chacha::KEY_START. Conditions (3) and (4) are
 * skipped when key_bit == 0. For a 128-bit key the same four checks are
 * additionally enforced on the mirror word w + 4 (the duplicated half).
 * After acceptance the key bit is flipped, modular subtraction yields
 * minusstate, the backward path is run, and parity match is counted.
 *
 *
 * CLI:
 *   ./pnb_search_carry_lock_condition [neutrality_threshold]
 *   Example: ./pnb_search_carry_lock_condition 0.0
 */

#include "../header/attack_util.hpp"
#include "../header/chacha.hpp"
#include "../header/core_types.hpp"
#include "../header/report_util.hpp"
#include "../header/state_ops.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <future>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

using namespace std;

// --------- Control Panel ---------
using TargetWord = u32;

constexpr size_t KEY_SIZE_BITS        = 256;
constexpr double TOTAL_ROUNDS         = 7.5;
constexpr double DISTINGUISHING_ROUND = 4.5;

using BitPos = std::pair<u16, u16>;
const vector<BitPos> INPUT_DIFF_BITS  = {{13, 6}};
// const vector<BitPos> OUTPUT_MASK_BITS = {{2, 0}, {8, 0}, {7, 7}};
const vector<BitPos> OUTPUT_MASK_BITS = {{2, 0}, {6, 12}, {7, 19}, {8,0}, {10,0},{11,7}, {12,0}};

const attack_util::SamplingParams SAMPLES = {
    .samples_per_thread_ = 1ULL << 17};

constexpr double DEFAULT_NEUTRALITY_THRESHOLD = 0.0;

vector<u16> SKIP_KEY_BITS = {};

// ------- System Variables -------
constexpr size_t BITS_PER_WORD = sizeof(TargetWord) * 8;
constexpr size_t STATE_WORDS   = chacha::STATE_WORDS;
constexpr size_t KEY_COUNT     = (KEY_SIZE_BITS == 128) ? 4 : 8;
constexpr size_t KEY_BUF_WORDS = 8; // ChaCha key buffer is always 8 words

using BiasEntry = pair<u16, double>;

struct RoundPlan
{
    int  dist_full_rounds;
    bool dist_half_present;
    int  after_dist_start;
    int  enc_full_rounds;
    bool enc_half_present;
};

constexpr bool half_is_even(int full_rounds)
{
    return (full_rounds + 1) % 2 == 0;
}

double                                  active_neutrality_threshold = DEFAULT_NEUTRALITY_THRESHOLD;
static atomic<u64>                      progress{0};
static chrono::steady_clock::time_point progress_start;
static RoundPlan                        round_plan;

static RoundPlan make_round_plan(double total_rounds, double dist_round);
double           matchcount(int key_bit, int key_word);
inline bool      skip_this(u16 idx, const vector<u16> &skip_bits);
static void      print_progress(u64 done, u64 total);
static inline bool passes_carrylock(const TargetWord *sumstate,
                                    const TargetWord *dsumstate,
                                    const TargetWord *strdx0,
                                    const TargetWord *dstrdx0,
                                    int key_word, int key_bit,
                                    bool check_mirror);

int main(int argc, char *argv[])
{
    std::ios_base::sync_with_stdio(false);
    cout.tie(NULL);

    report_util::RunTimer timer;
    timer.print_start();

    if (argc >= 2)
    {
        try
        {
            active_neutrality_threshold = std::stod(argv[1]);
            if (active_neutrality_threshold < 0.0 || active_neutrality_threshold > 1.0)
            {
                cerr << "Neutrality must be in [0,1]. Using default.\n";
                active_neutrality_threshold = DEFAULT_NEUTRALITY_THRESHOLD;
            }
        }
        catch (...)
        {
            cerr << "Invalid neutrality input. Using default.\n";
            active_neutrality_threshold = DEFAULT_NEUTRALITY_THRESHOLD;
        }
    }

    round_plan = make_round_plan(TOTAL_ROUNDS, DISTINGUISHING_ROUND);

    std::sort(SKIP_KEY_BITS.begin(), SKIP_KEY_BITS.end());
    const u64 total_work =
        KEY_COUNT * BITS_PER_WORD - static_cast<u16>(SKIP_KEY_BITS.size());

    cout << chacha::ChaChaTraits<TargetWord>::name
         << " PNB Search (carry-lock conditions)\n";
    cout << report_util::SEP;
    cout << "Key size                 : " << KEY_SIZE_BITS << " bits\n";
    cout << "Word size                : " << BITS_PER_WORD << " bits\n";
    cout << "Total rounds             : " << TOTAL_ROUNDS << "\n";
    cout << "Distinguishing round     : " << DISTINGUISHING_ROUND << "\n";

    auto fmt_bitpos = [](const vector<BitPos> &v) -> string
    {
        string s = "{";
        for (size_t i = 0; i < v.size(); ++i)
        {
            if (i) s += ", ";
            s += "(" + to_string(v[i].first) + "," + to_string(v[i].second) + ")";
        }
        return s + "}";
    };
    cout << "ID bits                  : " << fmt_bitpos(INPUT_DIFF_BITS) << "\n";
    cout << "Output mask bits         : " << fmt_bitpos(OUTPUT_MASK_BITS) << "\n";
    cout << "Samples/key-bit          : 2^{" << fixed << setprecision(2)
         << static_cast<double>(log2(SAMPLES.samples_per_batch())) << "}\n";
    cout << "# Threads                : " << SAMPLES.max_num_threads_ << "\n";
    cout << "Neutrality threshold     : " << active_neutrality_threshold << "\n";
    cout << "# key bits               : " << total_work << "\n";
    cout << "Mode                     : carry-lock (rejection sampling on +/-)"
         << "\n";
    cout << report_util::SEP << "\n";

    progress_start = chrono::steady_clock::now();
    vector<BiasEntry> all_pnbs, all_nonpnbs;
    all_pnbs.reserve(KEY_SIZE_BITS);
    all_nonpnbs.reserve(KEY_SIZE_BITS);

    vector<future<double>> future_results;
    future_results.reserve(SAMPLES.max_num_threads_);

    for (size_t key_word{0}; key_word < KEY_COUNT; ++key_word)
    {
        for (size_t key_bit{0}; key_bit < BITS_PER_WORD; ++key_bit)
        {
            u16 global_idx = static_cast<u16>(key_word * BITS_PER_WORD + key_bit);
            if (skip_this(global_idx, SKIP_KEY_BITS))
                continue;

            double sum = 0.0;
            future_results.clear();

            for (u16 t{0}; t < SAMPLES.max_num_threads_; ++t)
                future_results.emplace_back(async(launch::async, matchcount,
                                                  static_cast<int>(key_bit),
                                                  static_cast<int>(key_word)));

            try
            {
                for (auto &f : future_results)
                    sum += f.get();
            }
            catch (const exception &e)
            {
                cerr << "Thread error: " << e.what() << "\n";
            }

            double neutrality_corr =
                (2.0 * static_cast<double>(sum) / SAMPLES.samples_per_batch()) - 1.0;

            if (fabs(neutrality_corr) >= active_neutrality_threshold)
                all_pnbs.push_back({global_idx, neutrality_corr});
            else
                all_nonpnbs.push_back({global_idx, neutrality_corr});

            progress.fetch_add(1, memory_order_relaxed);
            print_progress(progress.load(), total_work);
        }
    }
    cerr << "\n";

    auto sort_by_index = [](auto &v)
    {
        sort(v.begin(), v.end(),
             [](const auto &a, const auto &b) { return a.first < b.first; });
        v.erase(unique(v.begin(), v.end(),
                       [](const auto &x, const auto &y) { return x.first == y.first; }),
                v.end());
    };
    sort_by_index(all_pnbs);
    sort_by_index(all_nonpnbs);

    cout << all_pnbs.size() << " PNBs (sorted by index):\n{";
    for (size_t i = 0; i < all_pnbs.size(); ++i)
        cout << all_pnbs[i].first << (i + 1 != all_pnbs.size() ? ", " : "");
    cout << "}\n";

    timer.print_end();
    return 0;
}

double matchcount(int key_bit, int key_word)
{
    u64 thread_match_count = 0;

    TargetWord x0[STATE_WORDS],     strdx0[STATE_WORDS],     key[KEY_BUF_WORDS];
    TargetWord dx0[STATE_WORDS],    dstrdx0[STATE_WORDS],    DiffState[STATE_WORDS];
    TargetWord sumstate[STATE_WORDS],  minusstate[STATE_WORDS];
    TargetWord dsumstate[STATE_WORDS], dminusstate[STATE_WORDS];

    u8 fwd_parity = 0, bwd_parity = 0;

    constexpr bool check_mirror = (KEY_SIZE_BITS == 128);

    for (size_t loop = 0; loop < SAMPLES.samples_per_thread_; ++loop)
    {
        bwd_parity = 0;

        // Rejection loop: rerun the forward path until the carry-lock
        // conditions on (key_word, key_bit) are satisfied.
        while (true)
        {
            fwd_parity = 0;

            chacha::init_iv_const<TargetWord>(x0);

            if constexpr (KEY_SIZE_BITS == 128)
                chacha::init_key<4, TargetWord>(key);
            else
                chacha::init_key<8, TargetWord>(key);

            chacha::insert_key<TargetWord>(x0, key);

            state_ops::copy_state(strdx0, x0);
            state_ops::copy_state(dx0,    x0);

            for (const auto &d : INPUT_DIFF_BITS)
                dx0[d.first] ^= (static_cast<TargetWord>(1) << d.second);

            state_ops::copy_state(dstrdx0, dx0);

            for (int i = 1; i <= round_plan.dist_full_rounds; ++i)
            {
                chacha::Forward<TargetWord>::round_function(x0,  i);
                chacha::Forward<TargetWord>::round_function(dx0, i);
            }

            if (round_plan.dist_half_present)
            {
                if (half_is_even(round_plan.dist_full_rounds))
                {
                    chacha::Forward<TargetWord>::apply_even_arx(x0, 2);
                    chacha::Forward<TargetWord>::apply_even_arx(dx0, 2);
                }
                else
                {
                    chacha::Forward<TargetWord>::apply_odd_arx(x0, 2);
                    chacha::Forward<TargetWord>::apply_odd_arx(dx0, 2);
                }
            }

            state_ops::xor_state(x0, dx0, DiffState);
            for (const auto &d : OUTPUT_MASK_BITS)
                fwd_parity ^= ((DiffState[d.first] >> d.second) & 1U);

            if (round_plan.dist_half_present)
            {
                if (half_is_even(round_plan.dist_full_rounds))
                {
                    chacha::Forward<TargetWord>::finish_even_arx(x0, 2);
                    chacha::Forward<TargetWord>::finish_even_arx(dx0, 2);
                }
                else
                {
                    chacha::Forward<TargetWord>::finish_odd_arx(x0, 2);
                    chacha::Forward<TargetWord>::finish_odd_arx(dx0, 2);
                }
            }

            for (int i = round_plan.after_dist_start; i <= round_plan.enc_full_rounds; ++i)
            {
                chacha::Forward<TargetWord>::round_function(x0,  i);
                chacha::Forward<TargetWord>::round_function(dx0, i);
            }

            if (round_plan.enc_half_present)
            {
                if (half_is_even(round_plan.enc_full_rounds))
                {
                    chacha::Forward<TargetWord>::apply_even_arx(x0, 2);
                    chacha::Forward<TargetWord>::apply_even_arx(dx0, 2);
                }
                else
                {
                    chacha::Forward<TargetWord>::apply_odd_arx(x0, 2);
                    chacha::Forward<TargetWord>::apply_odd_arx(dx0, 2);
                }
            }

            state_ops::add_state(x0,  strdx0,  sumstate);
            state_ops::add_state(dx0, dstrdx0, dsumstate);

            if (passes_carrylock(sumstate, dsumstate, strdx0, dstrdx0,
                                 key_word, key_bit, check_mirror))
                break;
        } // end rejection loop

        key[key_word] ^= (static_cast<TargetWord>(1) << key_bit);
        if constexpr (KEY_SIZE_BITS == 128)
            key[key_word + 4] ^= (static_cast<TargetWord>(1) << key_bit);

        chacha::insert_key<TargetWord>(strdx0,  key);
        chacha::insert_key<TargetWord>(dstrdx0, key);

        state_ops::subtract_state(sumstate,  strdx0,  minusstate);
        state_ops::subtract_state(dsumstate, dstrdx0, dminusstate);

        if (round_plan.enc_half_present)
        {
            if (half_is_even(round_plan.enc_full_rounds))
            {
                chacha::Backward<TargetWord>::apply_even_arx(minusstate, 2);
                chacha::Backward<TargetWord>::apply_even_arx(dminusstate, 2);
            }
            else
            {
                chacha::Backward<TargetWord>::apply_odd_arx(minusstate, 2);
                chacha::Backward<TargetWord>::apply_odd_arx(dminusstate, 2);
            }
        }

        for (int i = round_plan.enc_full_rounds; i >= round_plan.after_dist_start; --i)
        {
            chacha::Backward<TargetWord>::round_function(minusstate,  i);
            chacha::Backward<TargetWord>::round_function(dminusstate, i);
        }

        if (round_plan.dist_half_present)
        {
            if (half_is_even(round_plan.dist_full_rounds))
            {
                chacha::Backward<TargetWord>::finish_even_arx(minusstate, 2);
                chacha::Backward<TargetWord>::finish_even_arx(dminusstate, 2);
            }
            else
            {
                chacha::Backward<TargetWord>::finish_odd_arx(minusstate, 2);
                chacha::Backward<TargetWord>::finish_odd_arx(dminusstate, 2);
            }
        }

        state_ops::xor_state(minusstate, dminusstate, DiffState);
        for (const auto &d : OUTPUT_MASK_BITS)
            bwd_parity ^= ((DiffState[d.first] >> d.second) & 1U);

        thread_match_count += (fwd_parity == bwd_parity);
    }

    return static_cast<double>(thread_match_count);
}

inline bool skip_this(u16 idx, const vector<u16> &skip_bits)
{
    return binary_search(skip_bits.begin(), skip_bits.end(), idx);
}

static RoundPlan make_round_plan(double total_rounds, double dist_round)
{
    RoundPlan plan{};

    plan.dist_full_rounds  = static_cast<int>(dist_round);
    plan.dist_half_present = (dist_round - plan.dist_full_rounds) > 0.0;
    plan.after_dist_start  = plan.dist_half_present
                                 ? plan.dist_full_rounds + 2
                                 : plan.dist_full_rounds + 1;

    plan.enc_full_rounds  = static_cast<int>(total_rounds);
    plan.enc_half_present = (total_rounds - plan.enc_full_rounds) > 0.0;

    return plan;
}

// Per-bit carry-lock acceptance test for the (key_word, key_bit) under
// measurement. See the file-level synopsis for the four conditions per
// word; the mirror word w + 4 is checked when check_mirror is true.
static inline bool passes_carrylock(const TargetWord *sumstate,
                                    const TargetWord *dsumstate,
                                    const TargetWord *strdx0,
                                    const TargetWord *dstrdx0,
                                    int key_word, int key_bit,
                                    bool check_mirror)
{
    const u16        word        = static_cast<u16>(key_word + chacha::KEY_START);
    const u16        mirror_word = static_cast<u16>(word + 4);
    const TargetWord bit_mask    = static_cast<TargetWord>(1) << key_bit;
    const TargetWord seg_mask    = (key_bit == 0)
                                       ? static_cast<TargetWord>(0)
                                       : static_cast<TargetWord>(
                                             (static_cast<TargetWord>(1) << key_bit) - 1);

    auto check_word = [&](u16 wi) -> bool
    {
        if (!(sumstate[wi]  & bit_mask)) return false;
        if (!(dsumstate[wi] & bit_mask)) return false;
        if (key_bit == 0) return true;
        if ((sumstate[wi]  & seg_mask) < (strdx0[wi]  & seg_mask)) return false;
        if ((dsumstate[wi] & seg_mask) < (dstrdx0[wi] & seg_mask)) return false;
        return true;
    };

    if (!check_word(word)) return false;
    if (check_mirror && mirror_word < STATE_WORDS)
        return check_word(mirror_word);
    return true;
}

static void print_progress(u64 done, u64 total)
{
    constexpr int BAR_WIDTH = 40;
    double frac    = static_cast<double>(done) / static_cast<double>(total);
    int    filled  = static_cast<int>(frac * BAR_WIDTH);
    auto   now     = chrono::steady_clock::now();
    double elapsed = chrono::duration<double>(now - progress_start).count();

    cerr << "\r[";
    for (int i = 0; i < BAR_WIDTH; ++i)
        cerr << (i < filled ? '#' : '.');
    cerr << "] " << done << "/" << total;

    auto fmt_hms = [](int s) -> string
    {
        ostringstream os;
        os << setfill('0') << setw(2) << s / 3600
           << "h" << setw(2) << (s % 3600) / 60
           << "m" << setw(2) << s % 60 << "s";
        return os.str();
    };

    if (done > 0 && done < total)
    {
        int eta_s = static_cast<int>(elapsed / frac - elapsed);
        cerr << "  ETA " << fmt_hms(eta_s);
    }
    else if (done == total)
    {
        cerr << "  Done in " << fmt_hms(static_cast<int>(elapsed));
    }
    cerr << flush;
}
