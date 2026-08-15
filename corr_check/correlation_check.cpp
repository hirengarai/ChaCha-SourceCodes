/*
 * Filename: chacha_bwdbiastest.cpp
 *
 * Synopsis:
 * Backward-bias (epsilon_a) measurement for ChaCha given a list of PNBs.
 * Refactored to operate securely on atomic ARX Steps (Quarter Rounds).
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
constexpr double DISTINGUISHING_ROUND = 4;

using BitPos = std::pair<u16, u16>;
const vector<BitPos> INPUT_DIFF_BITS = {{13, 6}};
const vector<BitPos> OUTPUT_MASK_BITS = {{2, 0}, {8, 0}, {7, 7}};

const attack_util::SamplingParams SAMPLES = {.samples_per_thread_ = 1ULL << 17,
                                             .num_batches_ = 1ULL << 10};

const vector<u16> PNB_INLINE = {};

const string PNB_FILE_PATH = "../chacha7.5_pnbs/pnb25.txt";
constexpr bool USE_PATTERN_SPLIT = false;
constexpr bool USE_CARRYLOCK = true; // XOR-condition
constexpr bool USE_SYNCOPATION = false;

// ------- System Variables -------
constexpr size_t BITS_PER_WORD = sizeof(TargetWord) * 8;
constexpr size_t STATE_WORDS = chacha::STATE_WORDS;
constexpr size_t KEY_COUNT = (KEY_SIZE_BITS == 128) ? 4 : 8;

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
std::vector<BitPos> synco_checks;

static RoundPlan make_attack_timeline(int total_steps, int dist_steps);
static void build_synco_checks();
double bwbias();

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

  const bool has_inline = !PNB_INLINE.empty();
  const bool has_file = !PNB_FILE_PATH.empty();
  if (has_inline && has_file) {
    cerr << "[ERROR] Both PNB_INLINE and PNB_FILE_PATH are set.\n";
    return 1;
  }
  if (!has_inline && !has_file) {
    cerr << "[ERROR] No PNB source configured.\n";
    return 1;
  }

  if (has_inline) {
    pnb_config.file_path = "[inline]";
    pnb_config.all = PNB_INLINE;
    if (pnb::load_from_vector(pnb_config) != pnb::LoadStatus::Ok) {
      cerr << "[ERROR] Inline PNB list is invalid.\n";
      return 1;
    }
  } else {
    pnb_config.file_path = PNB_FILE_PATH;
    if (pnb::load_from_file(pnb_config.file_path, pnb_config, KEY_SIZE_BITS) !=
        pnb::LoadStatus::Ok) {
      cerr << "[ERROR] Could not load PNB file.\n";
      return 1;
    }
  }

  precomp_pnb.build(pnb_config, chacha::calculate_word_bit<TargetWord>);
  build_synco_checks();

  cout << report_util::SEP;
  cout << chacha::ChaChaTraits<TargetWord>::name << " Backward Bias Check\n";
  cout << "Key size                 : " << KEY_SIZE_BITS << " bits\n";
  cout << "Word size                : " << BITS_PER_WORD << " bits\n";
  cout << "Total rounds             : " << TOTAL_ROUNDS << "\n";
  cout << "Distinguishing round     : " << DISTINGUISHING_ROUND << "\n";

  auto fmt_bitpos = [](const vector<BitPos> &v) -> string {
    string s = "{";
    for (size_t i = 0; i < v.size(); ++i) {
      if (i)
        s += ", ";
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
      if (i)
        s += ", ";
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

  cout << "Carry-lock conditions    : " << (USE_CARRYLOCK ? "ON" : "OFF") << "\n";
  cout << "Pattern split            : " << (USE_PATTERN_SPLIT ? "ON" : "OFF") << "\n";
  cout << "Synco conditions         : " << (USE_SYNCOPATION ? "ON" : "OFF") << "\n";


  cout << report_util::SEP << "\n";

  constexpr int W_SAMPLES = 12, W_BIAS = 23, W_CORR = 23, W_TIME = 10;
  cout << std::left << std::setw(W_SAMPLES) << "# Samples"
       << "  " << std::setw(W_BIAS) << "Bias (~2^)"
       << "  " << std::setw(W_CORR) << "Correlation (~2^)"
       << "  " << std::setw(W_TIME) << "Time(ms)" << "\n"
       << std::string(W_SAMPLES, '-') << "  " << std::string(W_BIAS, '-')
       << "  " << std::string(W_CORR, '-') << "  " << std::string(W_TIME, '-')
       << "\n";

  vector<future<double>> future_results;
  future_results.reserve(SAMPLES.max_num_threads_);

  double SUM = 0.0;
  u64 samples_so_far = 0;

  for (size_t batch = 0; batch < SAMPLES.num_batches_; ++batch) {
    auto loopstart = chrono::high_resolution_clock::now();

    future_results.clear();
    for (u16 t = 0; t < SAMPLES.max_num_threads_; ++t)
      future_results.emplace_back(async(launch::async, bwbias));

    for (auto &f : future_results)
      SUM += f.get();

    samples_so_far += SAMPLES.samples_per_batch();
    double prob = SUM / static_cast<double>(samples_so_far);
    double bias = prob - 0.5;
    double correlation = 2.0 * bias;

    double bias_log2 =
        (bias == 0.0) ? -numeric_limits<double>::infinity() : log2(fabs(bias));
    double corr_log2 = (correlation == 0.0)
                           ? -numeric_limits<double>::infinity()
                           : log2(fabs(correlation));

    auto loopend = chrono::high_resolution_clock::now();
    u32 dur_ms = static_cast<u32>(
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
         << "  " << std::setw(W_TIME) << s_time << "\n";
  }
  cout << report_util::SEP;

  timer.print_end();
  return 0;
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

    while (true) {
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

      // --- Phase 1: Forward Distinguishing ---
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

      // Check Mask at Distinguishing Boundary
      state_ops::xor_state(x0, dx0, DiffState);
      for (const auto &d : OUTPUT_MASK_BITS)
        fwd_parity ^= ((DiffState[d.first] >> d.second) & 1U);

      // --- Phase 2: Resume broken round ---
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

      // --- Phase 3: Forward Encoding ---
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

      if constexpr (USE_CARRYLOCK) {
        state_ops::xor_state(x0, strdx0, sumstate);
        state_ops::xor_state(dx0, dstrdx0, dsumstate);
        break;
      } else {
        state_ops::add_state(x0, strdx0, sumstate);
        state_ops::add_state(dx0, dstrdx0, dsumstate);
        break;
      }
    }

    // --- PNB Injection ---
    constexpr bool key_128 = (KEY_SIZE_BITS == 128);
    for (size_t w = 0; w < STATE_WORDS; ++w) {
      TargetWord mask = static_cast<TargetWord>(precomp_pnb.all[w]);
      if (!mask)
        continue;
      TargetWord flip = random_util::random_number<TargetWord>() & mask;
      strdx0[w] ^= flip;
      dstrdx0[w] ^= flip;
      if constexpr (key_128) {
        if (w + 4 < STATE_WORDS) {
          strdx0[w + 4] ^= flip;
          dstrdx0[w + 4] ^= flip;
        }
      }
    }

    state_ops::subtract_state(sumstate, strdx0, minusstate);
    state_ops::subtract_state(dsumstate, dstrdx0, dminusstate);

    if constexpr (USE_CARRYLOCK) {
      state_ops::xor_state(sumstate, strdx0, minusstate);
      state_ops::xor_state(dsumstate, dstrdx0, dminusstate);
    }

    // --- Phase 4: Backward Undo Encoding ---
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

    // --- Phase 5: Backward Undo Resumed Distinguishing Round ---
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

    thread_match_count += (bwd_parity == fwd_parity);
  }

  return static_cast<double>(thread_match_count);
}

static RoundPlan make_attack_timeline(int total_steps, int dist_steps) {
  RoundPlan plan{};

  plan.full_rounds_before_dist_round = dist_steps / 4;
  plan.arx_steps_before_dist_round = dist_steps % 4;
  plan.dist_round_is_even = round_is_even(plan.full_rounds_before_dist_round + 1);

  plan.resume_round_index =
      plan.full_rounds_before_dist_round + (plan.arx_steps_before_dist_round > 0 ? 2 : 1);

  plan.total_full_rounds = total_steps / 4;
  plan.total_arx_steps = total_steps % 4;
  plan.end_is_even_round = round_is_even(plan.total_full_rounds + 1);

  return plan;
}

// Scans the sorted PNB list for consecutive runs of length >= 2 and emits
// one (word, bit) syncopation check per run, located at (border + 1) where
// border is the last PNB of the run. Cross-word successors are skipped.
// Length-1 (isolated) PNBs contribute no check.
static void build_synco_checks() {
  synco_checks.clear();

  const auto &all = pnb_config.all; // sorted, deduped
  if (all.size() < 2)
    return;

  size_t i = 0;
  while (i < all.size()) {
    size_t j = i;
    while (j + 1 < all.size() && all[j + 1] == static_cast<u16>(all[j] + 1))
      ++j;

    const size_t run_len = j - i + 1;
    if (run_len >= 2) {
      const u16 border = all[j];
      const u16 next = static_cast<u16>(border + 1);

      u16 w_b = 0, b_b = 0, w_n = 0, b_n = 0;
      chacha::calculate_word_bit<TargetWord>(border, w_b, b_b);
      chacha::calculate_word_bit<TargetWord>(next, w_n, b_n);

      if (w_n == w_b)
        synco_checks.emplace_back(w_n, b_n);
    }
    i = j + 1;
  }
}
