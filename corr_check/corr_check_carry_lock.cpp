/*
 *
 * Synopsis:
 * Backward-bias (epsilon_a) measurement for ChaCha using EXACT per-block
 * carry-lock conditions on the supplied PNB set.
 *
 * Block-wise carry-lock rule:
 *   The PNB list is grouped into consecutive runs ("blocks") of length
 *   >= 2; isolated PNBs are NOT constrained. For each block
 *   {a, a+1, ..., b} that lies inside a single state word w, with bit
 *   positions [bit_lo..bit_hi] = (a%32 .. b%32), require:
 *     (1) every bit of sumstate[w]  in [bit_lo..bit_hi] is set
 *     (2) every bit of dsumstate[w] in [bit_lo..bit_hi] is set
 *     (3) (sumstate[w]  mod 2^bit_lo) >= (strdx0[w]  mod 2^bit_lo)
 *     (4) (dsumstate[w] mod 2^bit_lo) >= (dstrdx0[w] mod 2^bit_lo)
 *   Conditions (3) and (4) are skipped when bit_lo == 0. Together they
 *   force no carry to propagate into or through the block, so modular
 *   addition agrees with XOR at every PNB position inside the block.
 *   Samples failing any block's conditions are rejected and the forward
 *   path is rerun.
 *
 *   For a 128-bit key the same four checks are also enforced on the
 *   mirror word w + 4 (the duplicated key half). Runs that straddle a
 *   word boundary are split into per-word sub-blocks.
 *
 * Configuration:
 *   USE_PATTERN_SPLIT  - if true, PNB randomization uses the pattern /
 *                        border / isolated categories from pnb_util;
 *                        otherwise every PNB is toggled uniformly.
 *
 * CLI:
 *   ./correlation_check_block_carrylock
 */

#include "../header/attack_util.hpp"
#include "../header/bit_ops.hpp"
#include "../header/chacha.hpp"
#include "../header/core_types.hpp"
#include "../header/log_util.hpp"
#include "../header/pnb_util.hpp"
#include "../header/random_util.hpp"
#include "../header/report_util.hpp"
#include "../header/state_ops.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <future>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <thread>
#include <vector>

using namespace std;

// ------- Control Panel -------
// #define ENABLE_LOG
[[maybe_unused]] constexpr const char *LOG_NAME = "";

using TargetWord = u32;

constexpr size_t KEY_SIZE_BITS        = 256;
constexpr double TOTAL_ROUNDS         = 7.5;
constexpr double DISTINGUISHING_ROUND = 3.5;

using BitPos = std::pair<u16, u16>;
const vector<BitPos> INPUT_DIFF_BITS  = {{13, 6}};
const vector<BitPos> OUTPUT_MASK_BITS = {{2, 0}};

const attack_util::SamplingParams SAMPLES = {
    .samples_per_thread_ = 1ULL << 15,
    .num_batches_        = 1ULL << 8};

const vector<u16> PNB_INLINE = {};

const string   PNB_FILE_PATH     = "../chacha7.5_pnbs/key4seg1.txt";
constexpr bool USE_PATTERN_SPLIT = false;

// ---- Mode selector (mutually exclusive) ----
//   USE_CARRYLOCK_CON = true   -> proper +/-, BLOCK carry-lock conditions
//                                 enforced via rejection sampling.
//   USE_CARRYLOCK_XOR = true   -> XOR replaces +/-, NO conditions.
//   Both false                 -> plain +/-, NO conditions (baseline).
constexpr bool USE_CARRYLOCK_CON = false;
constexpr bool USE_CARRYLOCK_XOR = true;
static_assert(!(USE_CARRYLOCK_CON && USE_CARRYLOCK_XOR),
              "USE_CARRYLOCK_CON and USE_CARRYLOCK_XOR are mutually exclusive");

// ------- System Variables -------
constexpr size_t BITS_PER_WORD = sizeof(TargetWord) * 8;
constexpr size_t STATE_WORDS   = chacha::STATE_WORDS;
constexpr size_t KEY_COUNT     = (KEY_SIZE_BITS == 128) ? 4 : 8;

// Convert double rounds to purely integer atomic "qr steps" immediately
constexpr int rounds_to_steps(double r) {
  return static_cast<int>(r * 4.0 + 0.1);
}
constexpr int TOTAL_STEPS = rounds_to_steps(TOTAL_ROUNDS);
constexpr int DIST_STEPS = rounds_to_steps(DISTINGUISHING_ROUND);

struct RoundPlan {
  int full_rounds_before_dist_round;
  int arx_steps_before_dist_round;
  bool dist_round_is_even;

  int resume_round_index;

  int total_full_rounds;
  int total_arx_steps;
  bool end_is_even_round;
};

constexpr bool round_is_even(int round_index) { return round_index % 2 == 0; }

static RoundPlan timeline;
pnb::Config pnb_config;
pnb::Masks<TargetWord, BITS_PER_WORD> precomp_pnb;


// One precomputed block: every PNB in [bit_lo..bit_hi] of `word`, plus
// mirror entries (mword == STATE_WORDS when not applicable).
struct BlockEntry {
  u16        word;
  u16        bit_lo;
  u16        bit_hi;
  u16        mword;     // mirror word for 128-bit key, else STATE_WORDS
  TargetWord bit_mask;  // OR of (1 << b) for b in [bit_lo..bit_hi]
  TargetWord seg_mask;  // (1 << bit_lo) - 1, or 0 when bit_lo == 0
};

// static RoundPlan                       round_plan;
// pnb::Config                            pnb_config;
// pnb::Masks<TargetWord, BITS_PER_WORD>  precomp_pnb;
std::vector<BlockEntry>                block_entries;

// Live progress counters (reset per batch). Workers update with relaxed
// atomics; a monitor thread polls and prints to stderr.
static std::atomic<u64>   g_accepted{0};
static std::atomic<u64>   g_attempts{0};
static std::atomic<bool>  g_stop_monitor{false};

static RoundPlan make_attack_timeline(int total_steps, int dist_steps);

// static RoundPlan make_round_plan(double total_rounds, double dist_round);
static void      build_block_entries();
static void      progress_monitor(u64 target_samples,
                                  size_t batch_idx, size_t num_batches);
double           bwbias();

int main() {
  std::ios_base::sync_with_stdio(false);
  cout.tie(NULL);

#ifdef ENABLE_LOG
  gLogger.enable(*LOG_NAME ? LOG_NAME : LOG_NAME);
#endif

  report_util::RunTimer timer;
  timer.print_start();

  timeline = make_attack_timeline(TOTAL_STEPS, DIST_STEPS);

  pnb_config.use_pattern_split = USE_PATTERN_SPLIT;

  // PNB source is exclusive: exactly one of PNB_INLINE / PNB_FILE_PATH
  // must be set. Both populated => ambiguous; both empty => no source.
  const bool has_inline = !PNB_INLINE.empty();
  const bool has_file   = !PNB_FILE_PATH.empty();
  if (has_inline && has_file) {
    cerr << "[ERROR] Both PNB_INLINE and PNB_FILE_PATH are set. "
            "Provide exactly one source.\n";
    return 1;
  }
  if (!has_inline && !has_file) {
    cerr << "[ERROR] No PNB source configured.\n";
    return 1;
  }

  if (has_inline) {
    pnb_config.file_path = "[inline]";
    pnb_config.all       = PNB_INLINE;
    if (pnb::load_from_vector(pnb_config) != pnb::LoadStatus::Ok) {
      cerr << "[ERROR] Inline PNB list is invalid.\n";
      return 1;
    }
  } else {
    pnb_config.file_path = PNB_FILE_PATH;
    if (pnb::load_from_file(pnb_config.file_path, pnb_config, KEY_SIZE_BITS) !=
        pnb::LoadStatus::Ok) {
      cerr << "[ERROR] Could not load PNB file: " << pnb_config.file_path
           << "\n";
      return 1;
    }
  }

  precomp_pnb.build(pnb_config, chacha::calculate_word_bit<TargetWord>);
  build_block_entries();

  if constexpr (USE_CARRYLOCK_CON) {
    if (block_entries.empty()) {
      cerr << "[ERROR] USE_CARRYLOCK_CON is on but the PNB list has no "
              "consecutive run of length >= 2; no block conditions to "
              "check.\n";
      return 1;
    }
  }

  cout << chacha::ChaChaTraits<TargetWord>::name
       << " Backward Bias Check (block-wise carry-lock)\n";
  cout << report_util::SEP;
  cout << "Key size                 : " << KEY_SIZE_BITS << " bits\n";
  cout << "Word size                : " << BITS_PER_WORD << " bits\n";
  cout << "Total rounds             : " << TOTAL_ROUNDS << "\n";
  cout << "Distinguishing round     : " << DISTINGUISHING_ROUND << "\n";

  auto fmt_bitpos = [](const vector<BitPos> &v) -> string {
    string s = "{";
    for (size_t i = 0; i < v.size(); ++i) {
      if (i) s += ", ";
      s += "(" + to_string(v[i].first) + "," + to_string(v[i].second) + ")";
    }
    return s + "}";
  };
  cout << "ID bits                  : " << fmt_bitpos(INPUT_DIFF_BITS) << "\n";
  cout << "Output mask bits         : " << fmt_bitpos(OUTPUT_MASK_BITS) << "\n";


  cout << "Samples/batch            : 2^{" << fixed << setprecision(2)
       << static_cast<double>(log2(SAMPLES.samples_per_batch())) << "}\n";
  cout << "# Threads                : " << SAMPLES.max_num_threads_ << "\n";
  cout << "# Batches                : 2^"
       << static_cast<int>(log2(SAMPLES.num_batches_)) << "\n";

  auto fmt_pnb_list = [](const vector<u16> &v) -> string {
    string s = "{";
    for (size_t i = 0; i < v.size(); ++i) {
      if (i) s += ", ";
      s += to_string(v[i]);
    }
    return s + "}";
  };
  if (!PNB_INLINE.empty())
    cout << "PNB source               : [inline] "
         << fmt_pnb_list(pnb_config.all) << " (Count: " << pnb_config.all.size()
         << ")\n";
  else
    cout << "PNB source               : [file] " << pnb_config.file_path
         << " (Count: " << pnb_config.all.size() << ")\n";

  cout << "Pattern split            : " << (USE_PATTERN_SPLIT ? "ON" : "OFF")
       << "\n";

  const char *mode =
      USE_CARRYLOCK_CON ? "CONDITIONS (proper +/-, block rejection)"
    : USE_CARRYLOCK_XOR ? "XOR (XOR replaces +/-, no conditions)"
                        : "PLAIN (proper +/-, no conditions)";
  cout << "Mode                     : " << mode << "\n";

  if constexpr (USE_CARRYLOCK_CON) {
    cout << "Carry-lock blocks        : (" << block_entries.size() << ") {";
    for (size_t i = 0; i < block_entries.size(); ++i) {
      const auto &e = block_entries[i];
      cout << "(w=" << e.word << ", bits " << e.bit_lo << ".." << e.bit_hi << ")";
      if (i + 1 != block_entries.size()) cout << ", ";
    }
    cout << "}\n";
  }

  cout << report_util::SEP << "\n";

  constexpr int W_SAMPLES = 12, W_BIAS = 23, W_CORR = 23, W_TIME = 10;
  cout << std::left << std::setw(W_SAMPLES) << "# Samples"
       << "  " << std::setw(W_BIAS) << "Bias (~2^)"
       << "  " << std::setw(W_CORR) << "Correlation (~2^)"
       << "  " << std::setw(W_TIME) << "Time(ms)"
       << "\n"
       << string(W_SAMPLES, '-') << "  " << string(W_BIAS, '-')
       << "  " << string(W_CORR, '-') << "  " << string(W_TIME, '-') << "\n";

  vector<future<double>> future_results;
  future_results.reserve(SAMPLES.max_num_threads_);

  double SUM            = 0.0;
  u64    samples_so_far = 0;

  for (size_t batch = 0; batch < SAMPLES.num_batches_; ++batch) {
    auto loopstart = chrono::high_resolution_clock::now();

    // Reset per-batch counters and spin up the progress monitor.
    g_accepted.store(0, std::memory_order_relaxed);
    g_attempts.store(0, std::memory_order_relaxed);
    g_stop_monitor.store(false, std::memory_order_relaxed);
    std::thread monitor(progress_monitor,
                        SAMPLES.samples_per_batch(),
                        batch + 1, SAMPLES.num_batches_);

    future_results.clear();
    for (u16 t = 0; t < SAMPLES.max_num_threads_; ++t)
      future_results.emplace_back(async(launch::async, bwbias));

    for (auto &f : future_results)
      SUM += f.get();

    // Stop the monitor and erase its progress line before printing the row.
    g_stop_monitor.store(true, std::memory_order_relaxed);
    monitor.join();
    // ANSI \033[K clears from cursor to end of line regardless of length;
    // a fixed-width space wipe leaks the tail when the line is longer.
    cerr << "\r\033[K" << std::flush;

    samples_so_far += SAMPLES.samples_per_batch();
    double prob        = SUM / static_cast<double>(samples_so_far);
    double bias        = prob - 0.5;
    double correlation = 2.0 * bias;

    double bias_log2 =
        (bias == 0.0) ? -numeric_limits<double>::infinity() : log2(fabs(bias));
    double corr_log2 = (correlation == 0.0)
                           ? -numeric_limits<double>::infinity()
                           : log2(fabs(correlation));

    auto loopend = chrono::high_resolution_clock::now();
    u32  dur_ms  = static_cast<u32>(
        chrono::duration_cast<chrono::milliseconds>(loopend - loopstart)
            .count());

    char s_samples[12], s_bias[32], s_corr[32], s_time[12];
    snprintf(s_samples, sizeof(s_samples), "2^{%.2f}",
             log2(static_cast<double>(samples_so_far)));
    snprintf(s_bias, sizeof(s_bias), "%.6f ~ 2^{%.2f}", bias, bias_log2);
    snprintf(s_corr, sizeof(s_corr), "%.6f ~ 2^{%.2f}", correlation, corr_log2);
    snprintf(s_time, sizeof(s_time), "%u", dur_ms);

    cout << std::left << std::setw(W_SAMPLES) << s_samples << "  "
         << std::setw(W_BIAS) << s_bias << "  " << std::setw(W_CORR) << s_corr
         << "  " << std::setw(W_TIME) << s_time << "\n"
         << std::flush;
  }
  cout << report_util::SEP;

  timer.print_end();
  return 0;
}

// Per-sample block carry-lock acceptance test.
static inline bool passes_block_carrylock(const TargetWord *sumstate,
                                          const TargetWord *dsumstate,
                                          const TargetWord *strdx0,
                                          const TargetWord *dstrdx0) {
  for (const auto &e : block_entries) {
    // (1) and (2): every PNB bit in [bit_lo..bit_hi] of the primary word
    //              is set in both sumstate and dsumstate.
    if ((sumstate[e.word]  & e.bit_mask) != e.bit_mask) return false;
    if ((dsumstate[e.word] & e.bit_mask) != e.bit_mask) return false;
    // (3) and (4): low bit_lo bits of sum/dsum >= same bits of key/dkey.
    if (e.seg_mask) {
      if ((sumstate[e.word]  & e.seg_mask) < (strdx0[e.word]  & e.seg_mask))
        return false;
      if ((dsumstate[e.word] & e.seg_mask) < (dstrdx0[e.word] & e.seg_mask))
        return false;
    }
    // Mirror word (only set for 128-bit keys; STATE_WORDS sentinel skips).
    if (e.mword < STATE_WORDS) {
      if ((sumstate[e.mword]  & e.bit_mask) != e.bit_mask) return false;
      if ((dsumstate[e.mword] & e.bit_mask) != e.bit_mask) return false;
      if (e.seg_mask) {
        if ((sumstate[e.mword]  & e.seg_mask) <
            (strdx0[e.mword]  & e.seg_mask))
          return false;
        if ((dsumstate[e.mword] & e.seg_mask) <
            (dstrdx0[e.mword] & e.seg_mask))
          return false;
      }
    }
  }
  return true;
}

double bwbias() {
  u64 thread_match_count = 0;

  TargetWord x0[STATE_WORDS], strdx0[STATE_WORDS], key[KEY_COUNT];
  TargetWord dx0[STATE_WORDS], dstrdx0[STATE_WORDS], DiffState[STATE_WORDS];
  TargetWord sumstate[STATE_WORDS], minusstate[STATE_WORDS];
  TargetWord dsumstate[STATE_WORDS], dminusstate[STATE_WORDS];

  u8 fwd_parity, bwd_parity;

  for (u64 loop = 0; loop < SAMPLES.samples_per_thread_; ++loop) {
    bwd_parity = 0;

    // Rejection loop: rerun the forward path until every PNB block's
    // carry-lock conditions are satisfied.
    while (true) {
      g_attempts.fetch_add(1, std::memory_order_relaxed);
      fwd_parity = 0;

      chacha::init_iv_const<TargetWord>(x0);

      if constexpr (KEY_SIZE_BITS == 128)
        chacha::init_key<4, TargetWord>(key);
      else
        chacha::init_key<8, TargetWord>(key);

      chacha::insert_key<TargetWord>(x0, key);

      state_ops::copy_state(strdx0, x0);
      state_ops::copy_state(dx0, x0);

      for (const auto &d : INPUT_DIFF_BITS)
        dx0[d.first] ^= (static_cast<TargetWord>(1) << d.second);

      state_ops::copy_state(dstrdx0, dx0);

      for (int i = 1; i <= timeline.full_rounds_before_dist_round; ++i) {
        chacha::Forward<TargetWord>::round_function(x0, i);
        chacha::Forward<TargetWord>::round_function(dx0, i);
      }

      if (timeline.arx_steps_before_dist_round > 0) {
        if (timeline.dist_round_is_even) {
          chacha::Forward<TargetWord>::apply_even_arx(
              x0, timeline.arx_steps_before_dist_round);
          chacha::Forward<TargetWord>::apply_even_arx(
              dx0, timeline.arx_steps_before_dist_round);
        } else {
          chacha::Forward<TargetWord>::apply_odd_arx(
              x0, timeline.arx_steps_before_dist_round);
          chacha::Forward<TargetWord>::apply_odd_arx(
              dx0, timeline.arx_steps_before_dist_round);
        }
      }

      state_ops::xor_state(x0, dx0, DiffState);
      for (const auto &d : OUTPUT_MASK_BITS)
        fwd_parity ^= ((DiffState[d.first] >> d.second) & 1U);

      if (timeline.arx_steps_before_dist_round > 0) {
        int remaining_steps = 4 - timeline.arx_steps_before_dist_round;
        if (timeline.dist_round_is_even) {
          chacha::Forward<TargetWord>::finish_even_arx(x0, remaining_steps);
          chacha::Forward<TargetWord>::finish_even_arx(dx0, remaining_steps);
        } else {
          chacha::Forward<TargetWord>::finish_odd_arx(x0, remaining_steps);
          chacha::Forward<TargetWord>::finish_odd_arx(dx0, remaining_steps);
        }
      }

      for (int i = timeline.resume_round_index; i <= timeline.total_full_rounds;
           ++i) {
        chacha::Forward<TargetWord>::round_function(x0, i);
        chacha::Forward<TargetWord>::round_function(dx0, i);
      }

      if (timeline.total_arx_steps > 0) {
        if (timeline.end_is_even_round) {
          chacha::Forward<TargetWord>::apply_even_arx(x0,
                                                      timeline.total_arx_steps);
          chacha::Forward<TargetWord>::apply_even_arx(dx0,
                                                      timeline.total_arx_steps);
        } else {
          chacha::Forward<TargetWord>::apply_odd_arx(x0,
                                                     timeline.total_arx_steps);
          chacha::Forward<TargetWord>::apply_odd_arx(dx0,
                                                     timeline.total_arx_steps);
        }
      }

      if constexpr (USE_CARRYLOCK_XOR) {
        // XOR shortcut: replace modular addition with XOR. No conditions.
        state_ops::xor_state(x0, strdx0, sumstate);
        state_ops::xor_state(dx0, dstrdx0, dsumstate);
        break;
      } else {
        state_ops::add_state(x0,  strdx0,  sumstate);
        state_ops::add_state(dx0, dstrdx0, dsumstate);

        if constexpr (USE_CARRYLOCK_CON) {
          if (passes_block_carrylock(sumstate, dsumstate, strdx0, dstrdx0))
            break;
          // else: re-run with a fresh key / IV
        } else {
          break; // PLAIN baseline: accept every sample
        }
      }
    } // end rejection loop

    g_accepted.fetch_add(1, std::memory_order_relaxed);

    constexpr bool key_128 = (KEY_SIZE_BITS == 128);

    if (pnb_config.use_pattern_split) {
      for (size_t w = 0; w < STATE_WORDS; ++w) {
        TargetWord mask = static_cast<TargetWord>(precomp_pnb.pattern[w]);
        if (!mask) continue;
        strdx0[w]  &= ~mask;
        dstrdx0[w] &= ~mask;
        if constexpr (key_128) {
          if (w + 4 < STATE_WORDS) {
            strdx0[w + 4]  &= ~mask;
            dstrdx0[w + 4] &= ~mask;
          }
        }
      }
      for (size_t w = 0; w < STATE_WORDS; ++w) {
        TargetWord mask = static_cast<TargetWord>(precomp_pnb.border[w]);
        if (!mask) continue;
        strdx0[w]  |= mask;
        dstrdx0[w] |= mask;
        if constexpr (key_128) {
          if (w + 4 < STATE_WORDS) {
            strdx0[w + 4]  |= mask;
            dstrdx0[w + 4] |= mask;
          }
        }
      }
      for (size_t w = 0; w < STATE_WORDS; ++w) {
        TargetWord mask = static_cast<TargetWord>(precomp_pnb.isolated[w]);
        if (!mask) continue;
        TargetWord flip = random_util::random_number<TargetWord>() & mask;
        strdx0[w]  ^= flip;
        dstrdx0[w] ^= flip;
        if constexpr (key_128) {
          if (w + 4 < STATE_WORDS) {
            strdx0[w + 4]  ^= flip;
            dstrdx0[w + 4] ^= flip;
          }
        }
      }
    } else {
      for (size_t w = 0; w < STATE_WORDS; ++w) {
        TargetWord mask = static_cast<TargetWord>(precomp_pnb.all[w]);
        if (!mask) continue;
        TargetWord flip = random_util::random_number<TargetWord>() & mask;
        strdx0[w]  ^= flip;
        dstrdx0[w] ^= flip;
        if constexpr (key_128) {
          if (w + 4 < STATE_WORDS) {
            strdx0[w + 4]  ^= flip;
            dstrdx0[w + 4] ^= flip;
          }
        }
      }
    }

    if constexpr (USE_CARRYLOCK_XOR) {
      // XOR shortcut on the backward side too (mirrors the forward XOR).
      state_ops::xor_state(sumstate,  strdx0,  minusstate);
      state_ops::xor_state(dsumstate, dstrdx0, dminusstate);
    } else {
      state_ops::subtract_state(sumstate,  strdx0,  minusstate);
      state_ops::subtract_state(dsumstate, dstrdx0, dminusstate);
    }

    if (timeline.total_arx_steps > 0) {
      if (timeline.end_is_even_round) {
        chacha::Backward<TargetWord>::apply_even_arx(minusstate,
                                                     timeline.total_arx_steps);
        chacha::Backward<TargetWord>::apply_even_arx(dminusstate,
                                                     timeline.total_arx_steps);
      } else {
        chacha::Backward<TargetWord>::apply_odd_arx(minusstate,
                                                    timeline.total_arx_steps);
        chacha::Backward<TargetWord>::apply_odd_arx(dminusstate,
                                                    timeline.total_arx_steps);
      }
    }

    for (int i = timeline.total_full_rounds; i >= timeline.resume_round_index;
         --i) {
      chacha::Backward<TargetWord>::round_function(minusstate, i);
      chacha::Backward<TargetWord>::round_function(dminusstate, i);
    }


    if (timeline.arx_steps_before_dist_round > 0) {
      int remaining_steps = 4 - timeline.arx_steps_before_dist_round;
      if (timeline.dist_round_is_even) {
        chacha::Backward<TargetWord>::finish_even_arx(minusstate,
                                                      remaining_steps);
        chacha::Backward<TargetWord>::finish_even_arx(dminusstate,
                                                      remaining_steps);
      } else {
        chacha::Backward<TargetWord>::finish_odd_arx(minusstate,
                                                     remaining_steps);
        chacha::Backward<TargetWord>::finish_odd_arx(dminusstate,
                                                     remaining_steps);
      }
    }

    state_ops::xor_state(minusstate, dminusstate, DiffState);
    for (const auto &d : OUTPUT_MASK_BITS)
      bwd_parity ^= ((DiffState[d.first] >> d.second) & 1U);

    thread_match_count += (fwd_parity == bwd_parity);
  }

  return static_cast<double>(thread_match_count);
}

static RoundPlan make_attack_timeline(int total_steps, int dist_steps) {
  RoundPlan plan{};

  plan.full_rounds_before_dist_round = dist_steps / 4;
  plan.arx_steps_before_dist_round = dist_steps % 4;
  plan.dist_round_is_even =
      round_is_even(plan.full_rounds_before_dist_round + 1);

  plan.resume_round_index = plan.full_rounds_before_dist_round +
                            (plan.arx_steps_before_dist_round > 0 ? 2 : 1);

  plan.total_full_rounds = total_steps / 4;
  plan.total_arx_steps = total_steps % 4;
  plan.end_is_even_round = round_is_even(plan.total_full_rounds + 1);

  return plan;
}

// Live progress line written to stderr while a batch is in flight. Stops
// when main flips g_stop_monitor; each batch row that follows on stdout
// overwrites the cleared line.
static void progress_monitor(u64 target_samples,
                             size_t batch_idx, size_t num_batches) {
  using namespace std::chrono;
  const auto poll_period = milliseconds(500);
  const auto t0          = steady_clock::now();

  auto fmt_hms = [](double s) {
    int total = static_cast<int>(s);
    int h = total / 3600;
    int m = (total / 60) % 60;
    int sec = total % 60;
    char buf[16];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d", h, m, sec);
    return std::string(buf);
  };

  auto fmt_log2 = [](double x) -> std::string {
    if (x <= 0.0) return std::string("---");
    char buf[24];
    snprintf(buf, sizeof(buf), "2^%.2f", log2(x));
    return std::string(buf);
  };

  while (!g_stop_monitor.load(std::memory_order_relaxed)) {
    std::this_thread::sleep_for(poll_period);
    // Re-check after waking: main may have flipped the flag during the
    // sleep, in which case we must exit without printing another line
    // (otherwise it interleaves with the row print).
    if (g_stop_monitor.load(std::memory_order_relaxed)) break;

    const u64 acc = g_accepted.load(std::memory_order_relaxed);
    const u64 att = g_attempts.load(std::memory_order_relaxed);
    const double elapsed =
        duration<double>(steady_clock::now() - t0).count();
    const double att_rate =
        elapsed > 0 ? static_cast<double>(att) / elapsed : 0.0;
    const double p_acc =
        att > 0 ? static_cast<double>(acc) / static_cast<double>(att) : 0.0;
    const double eta_sec =
        (acc > 0 && acc < target_samples)
            ? elapsed * (static_cast<double>(target_samples - acc) /
                         static_cast<double>(acc))
            : 0.0;

    char line[320];
    snprintf(line, sizeof(line),
             "[batch %zu/%zu] acc=%llu/%llu  attempts=%s (%s/s)  "
             "P_acc=%s  elapsed=%s  ETA=%s",
             batch_idx, num_batches,
             static_cast<unsigned long long>(acc),
             static_cast<unsigned long long>(target_samples),
             fmt_log2(static_cast<double>(att)).c_str(),
             fmt_log2(att_rate).c_str(),
             fmt_log2(p_acc).c_str(),
             fmt_hms(elapsed).c_str(),
             fmt_hms(eta_sec).c_str());
    std::cerr << "\r" << line << std::string(8, ' ') << std::flush;
  }
}

// Walks the sorted PNB list, identifies consecutive runs of length >= 2,
// and emits one BlockEntry per (run, state-word) intersection. Singleton
// PNBs are skipped. A run that straddles a 32-bit word boundary becomes
// two entries, one per word.
static void build_block_entries() {
  block_entries.clear();

  const auto &all = pnb_config.all; // sorted, deduped by pnb_util
  if (all.size() < 2) return;

  constexpr bool key_128 = (KEY_SIZE_BITS == 128);

  size_t i = 0;
  while (i < all.size()) {
    size_t j = i;
    while (j + 1 < all.size() && all[j + 1] == static_cast<u16>(all[j] + 1))
      ++j;

    // Skip singletons (isolated PNBs).
    if (j == i) {
      i = j + 1;
      continue;
    }

    // Run is all[i..j]. Map endpoints to (word, bit) and split by word.
    u16 first = all[i];
    while (first <= all[j]) {
      u16 w_lo = 0, b_lo = 0;
      chacha::calculate_word_bit<TargetWord>(first, w_lo, b_lo);

      // Largest bit in the run that still lives in word w_lo.
      u16 last = all[j];
      {
        u16 w_last = 0, b_last = 0;
        chacha::calculate_word_bit<TargetWord>(last, w_last, b_last);
        if (w_last != w_lo) {
          // Trim to the end of word w_lo: bit BITS_PER_WORD - 1.
          last = static_cast<u16>(first + (BITS_PER_WORD - 1 - b_lo));
        }
      }
      u16 w_hi = 0, b_hi = 0;
      chacha::calculate_word_bit<TargetWord>(last, w_hi, b_hi);

      BlockEntry e{};
      e.word   = w_lo;
      e.bit_lo = b_lo;
      e.bit_hi = b_hi;
      e.mword  = static_cast<u16>(STATE_WORDS); // default: no mirror
      if constexpr (key_128) {
        const size_t mw = static_cast<size_t>(w_lo) + 4;
        if (mw < STATE_WORDS) e.mword = static_cast<u16>(mw);
      }
      const u16 width = static_cast<u16>(b_hi - b_lo + 1);
      const TargetWord run_mask =
          (width == BITS_PER_WORD)
              ? static_cast<TargetWord>(~static_cast<TargetWord>(0))
              : static_cast<TargetWord>((static_cast<TargetWord>(1) << width) - 1U);
      e.bit_mask = run_mask << b_lo;
      e.seg_mask = (b_lo == 0)
                       ? static_cast<TargetWord>(0)
                       : static_cast<TargetWord>(
                             (static_cast<TargetWord>(1) << b_lo) - 1U);
      block_entries.push_back(e);

      first = static_cast<u16>(last + 1);
    }
    i = j + 1;
  }
}
