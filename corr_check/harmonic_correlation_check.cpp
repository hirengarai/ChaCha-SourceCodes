/*
 *
 * Synopsis:
 * Backward-bias (epsilon_a) measurement for ChaCha with HARMONIC carry-lock
 * conditions, using paired PNB randomization.
 *
 * Carry-lock rule (harmonic):
 *   (a) PNB-bit constraint: for every PNB at (word w, bit b),
 *       sumstate[w] AND dsumstate[w] must both have bit b set.
 *       For a 128-bit key the same bit in the mirror word (w+4) is also
 *       required.
 *   (b) Min-bit segment constraint: for each word w that contains at least
 *       one PNB, let m = min PNB bit in w. The low m bits of sumstate[w]
 *       must be >= the low m bits of strdx0[w] (and the same for dsumstate
 *       vs dstrdx0).
 *   Samples failing either condition are resampled.
 *
 * PNB randomization (harmonic pairs):
 *   The PNB list is interpreted in INSERTION ORDER (no sort/dedupe). Bit
 *   pnb_list[i] is paired with bit pnb_list[i + N/2]; a single fair coin
 *   flip toggles both bits at once. If the list size is odd the middle
 *   element is left untouched and a warning is printed.
 *
 * PNB file format:
 *   Whitespace/comma-separated integers in [0, 256). The legacy footer of
 *   three block-length counts (e.g. trailing "4, 2, 0") is stripped when
 *   STRIP_LEGACY_FOOTER is true.
 *
 */

#include "../header/chacha.hpp"
#include "../header/attack_util.hpp"
#include "../header/bit_ops.hpp"
#include "../header/core_types.hpp"
#include "../header/log_util.hpp"
#include "../header/random_util.hpp"
#include "../header/report_util.hpp"
#include "../header/state_ops.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std;

// ------- Control Panel -------
// #define ENABLE_LOG
[[maybe_unused]] constexpr const char *LOG_NAME = "";

using TargetWord = u32;

constexpr size_t KEY_SIZE_BITS        = 256;
constexpr double TOTAL_ROUNDS         = 7.5;
constexpr double DISTINGUISHING_ROUND = 4.0;

using BitPos = std::pair<u16, u16>;
const vector<BitPos> INPUT_DIFF_BITS  = {{13, 6}};
const vector<BitPos> OUTPUT_MASK_BITS = {{2, 0}, {8, 0}, {7, 7}};

const attack_util::SamplingParams SAMPLES = {
    .samples_per_thread_ = 1ULL << 10,
    .num_batches_        = 1ULL << 10};

const vector<u16> PNB_INLINE = {};

const string   PNB_FILE_PATH       = "../harmonic_pair.txt";
constexpr bool STRIP_LEGACY_FOOTER = true;

// ------- System Variables -------
constexpr size_t BITS_PER_WORD = sizeof(TargetWord) * 8;
constexpr size_t STATE_WORDS   = chacha::STATE_WORDS;
constexpr size_t KEY_COUNT     = (KEY_SIZE_BITS == 128) ? 4 : 8;

struct RoundPlan {
  int  dist_full_rounds;
  bool dist_half_present;
  int  after_dist_start;
  int  enc_full_rounds;
  bool enc_half_present;
};

constexpr bool half_is_even(int full_rounds) {
  return (full_rounds + 1) % 2 == 0;
}

struct HarmonicPair {
  BitPos a;
  BitPos b;
};

static RoundPlan          round_plan;
std::vector<u16>          pnb_list;       // PNBs in file order (NOT sorted)
std::vector<HarmonicPair> pnb_pairs;      // (pnb_list[i], pnb_list[i+half])

// Per-word precomputed tables for the harmonic carry-lock check.
// pnb_bit_mask[w]   = OR of (1 << bit) for every PNB sitting in word w
//                     (and, for a 128-bit key, in mirror word w-4 -> w).
// pnb_min_bit[w]    = lowest PNB bit in word w, or BITS_PER_WORD if none.
std::array<TargetWord, STATE_WORDS> pnb_bit_mask;
std::array<u16,        STATE_WORDS> pnb_min_bit;

static RoundPlan make_round_plan(double total_rounds, double dist_round);
static bool      load_pnb_file(const string &path, std::vector<u16> &out);
static void      build_harmonic_tables();
static bool      passes_harmonic_carrylock(const TargetWord *sumstate,
                                           const TargetWord *dsumstate,
                                           const TargetWord *strdx0,
                                           const TargetWord *dstrdx0);
double           bwbias();

int main() {
  std::ios_base::sync_with_stdio(false);
  cout.tie(NULL);

#ifdef ENABLE_LOG
  gLogger.enable(*LOG_NAME ? LOG_NAME : "harmonic_run.log");
#endif

  report_util::RunTimer timer;
  timer.print_start();

  round_plan = make_round_plan(TOTAL_ROUNDS, DISTINGUISHING_ROUND);

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
    cerr << "[ERROR] No PNB source configured. Set PNB_INLINE or "
            "PNB_FILE_PATH.\n";
    return 1;
  }

  string pnb_source_label;
  if (has_inline) {
    pnb_list         = PNB_INLINE;
    pnb_source_label = "[inline]";
  } else {
    if (!load_pnb_file(PNB_FILE_PATH, pnb_list))
      return 1;
    pnb_source_label = string("[file] ") + PNB_FILE_PATH;
  }

  if (pnb_list.empty()) {
    cerr << "[ERROR] PNB list is empty after load.\n";
    return 1;
  }
  if (pnb_list.size() % 2 != 0) {
    cerr << "[WARN] PNB count is odd (" << pnb_list.size() << "); the "
            "middle element will not be paired for harmonic randomization.\n";
  }

  build_harmonic_tables();

  cout << chacha::ChaChaTraits<TargetWord>::name
       << " Harmonic Backward Bias Check\n";
  cout << report_util::SEP;
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
  cout << "PNB source               : " << pnb_source_label << " "
       << fmt_pnb_list(pnb_list) << " (Count: " << pnb_list.size() << ")\n";

  auto fmt_pairs = [](const vector<HarmonicPair> &v) -> string {
    string s = "{";
    for (size_t i = 0; i < v.size(); ++i) {
      if (i)
        s += ", ";
      s += "[(" + to_string(v[i].a.first) + "," + to_string(v[i].a.second) +
           ")<->(" + to_string(v[i].b.first) + "," + to_string(v[i].b.second) +
           ")]";
    }
    return s + "}";
  };
  cout << "Harmonic pairs           : " << fmt_pairs(pnb_pairs)
       << " (Count: " << pnb_pairs.size() << ")\n";
  cout << "Carry-lock mode          : harmonic (per-bit set + min-bit "
          "segment >=)\n";

  cout << report_util::SEP << "\n";

  constexpr int W_SAMPLES = 12, W_BIAS = 23, W_CORR = 23, W_TIME = 10;
  cout << std::left << std::setw(W_SAMPLES) << "# Samples"
       << "  " << std::setw(W_BIAS) << "Bias (~2^)"
       << "  " << std::setw(W_CORR) << "Correlation (~2^)"
       << "  " << std::setw(W_TIME) << "Time(ms)"
       << "\n"
       << std::string(W_SAMPLES, '-') << "  " << std::string(W_BIAS, '-')
       << "  " << std::string(W_CORR, '-') << "  " << std::string(W_TIME, '-')
       << "\n";

  vector<future<double>> future_results;
  future_results.reserve(SAMPLES.max_num_threads_);

  double SUM            = 0.0;
  u64    samples_so_far = 0;

  for (size_t batch = 0; batch < SAMPLES.num_batches_; ++batch) {
    auto loopstart = chrono::high_resolution_clock::now();

    future_results.clear();
    for (u16 t = 0; t < SAMPLES.max_num_threads_; ++t)
      future_results.emplace_back(async(launch::async, bwbias));

    for (auto &f : future_results)
      SUM += f.get();

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

  u8 fwd_parity = 0, bwd_parity = 0;

  for (u64 loop = 0; loop < SAMPLES.samples_per_thread_; ++loop) {
    bwd_parity = 0;

    // Rejection loop: re-runs the forward path until the harmonic
    // carry-lock conditions hold on (sumstate, dsumstate) wrt (strdx0,
    // dstrdx0).
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

      for (int i = 1; i <= round_plan.dist_full_rounds; ++i) {
        chacha::Forward<TargetWord>::round_function(x0, i);
        chacha::Forward<TargetWord>::round_function(dx0, i);
      }

      if (round_plan.dist_half_present) {
        if (half_is_even(round_plan.dist_full_rounds)) {
          chacha::Forward<TargetWord>::half1_even(x0);
          chacha::Forward<TargetWord>::half1_even(dx0);
        } else {
          chacha::Forward<TargetWord>::half1_odd(x0);
          chacha::Forward<TargetWord>::half1_odd(dx0);
        }
      }

      state_ops::xor_state(x0, dx0, DiffState);
      for (const auto &d : OUTPUT_MASK_BITS)
        fwd_parity ^= ((DiffState[d.first] >> d.second) & 1U);

      if (round_plan.dist_half_present) {
        if (half_is_even(round_plan.dist_full_rounds)) {
          chacha::Forward<TargetWord>::half2_even(x0);
          chacha::Forward<TargetWord>::half2_even(dx0);
        } else {
          chacha::Forward<TargetWord>::half2_odd(x0);
          chacha::Forward<TargetWord>::half2_odd(dx0);
        }
      }

      for (int i = round_plan.after_dist_start; i <= round_plan.enc_full_rounds;
           ++i) {
        chacha::Forward<TargetWord>::round_function(x0, i);
        chacha::Forward<TargetWord>::round_function(dx0, i);
      }

      if (round_plan.enc_half_present) {
        if (half_is_even(round_plan.enc_full_rounds)) {
          chacha::Forward<TargetWord>::half1_even(x0);
          chacha::Forward<TargetWord>::half1_even(dx0);
        } else {
          chacha::Forward<TargetWord>::half1_odd(x0);
          chacha::Forward<TargetWord>::half1_odd(dx0);
        }
      }

      state_ops::add_state(x0, strdx0, sumstate);
      state_ops::add_state(dx0, dstrdx0, dsumstate);

      if (passes_harmonic_carrylock(sumstate, dsumstate, strdx0, dstrdx0))
        break;
    } // end rejection loop

    // Harmonic-pair PNB randomization: a single coin flip toggles both
    // members of the pair simultaneously in strdx0 and dstrdx0.
    for (const auto &p : pnb_pairs) {
      if (random_util::random_boolean()) {
        const TargetWord m1 = static_cast<TargetWord>(1) << p.a.second;
        const TargetWord m2 = static_cast<TargetWord>(1) << p.b.second;
        strdx0[p.a.first] ^= m1;
        dstrdx0[p.a.first] ^= m1;
        strdx0[p.b.first] ^= m2;
        dstrdx0[p.b.first] ^= m2;
      }
    }

    state_ops::subtract_state(sumstate, strdx0, minusstate);
    state_ops::subtract_state(dsumstate, dstrdx0, dminusstate);

    if (round_plan.enc_half_present) {
      if (half_is_even(round_plan.enc_full_rounds)) {
        chacha::Backward<TargetWord>::half2_even(minusstate);
        chacha::Backward<TargetWord>::half2_even(dminusstate);
      } else {
        chacha::Backward<TargetWord>::half2_odd(minusstate);
        chacha::Backward<TargetWord>::half2_odd(dminusstate);
      }
    }

    for (int i = round_plan.enc_full_rounds; i >= round_plan.after_dist_start;
         --i) {
      chacha::Backward<TargetWord>::round_function(minusstate, i);
      chacha::Backward<TargetWord>::round_function(dminusstate, i);
    }

    if (round_plan.dist_half_present) {
      if (half_is_even(round_plan.dist_full_rounds)) {
        chacha::Backward<TargetWord>::half1_even(minusstate);
        chacha::Backward<TargetWord>::half1_even(dminusstate);
      } else {
        chacha::Backward<TargetWord>::half1_odd(minusstate);
        chacha::Backward<TargetWord>::half1_odd(dminusstate);
      }
    }

    state_ops::xor_state(minusstate, dminusstate, DiffState);
    for (const auto &d : OUTPUT_MASK_BITS)
      bwd_parity ^= ((DiffState[d.first] >> d.second) & 1U);

    thread_match_count += (bwd_parity == fwd_parity);
  }

  return static_cast<double>(thread_match_count);
}

static RoundPlan make_round_plan(double total_rounds, double dist_round) {
  RoundPlan plan{};

  plan.dist_full_rounds  = static_cast<int>(dist_round);
  plan.dist_half_present = (dist_round - plan.dist_full_rounds) > 0.0;
  plan.after_dist_start  = plan.dist_half_present ? plan.dist_full_rounds + 2
                                                  : plan.dist_full_rounds + 1;

  plan.enc_full_rounds  = static_cast<int>(total_rounds);
  plan.enc_half_present = (total_rounds - plan.enc_full_rounds) > 0.0;

  return plan;
}

// Reads PNBs from a whitespace/comma-separated file in INSERTION order
// (no sort, no dedupe). Validates each value lies in [0, KEY_SIZE_BITS).
// If STRIP_LEGACY_FOOTER is true, the trailing 3 tokens (legacy block-
// length counts) are dropped.
static bool load_pnb_file(const string &path, std::vector<u16> &out) {
  out.clear();
  std::ifstream file(path);
  if (!file.is_open()) {
    cerr << "[ERROR] Could not open PNB file: " << path << "\n";
    return false;
  }
  std::vector<int> raw;
  std::string      line;
  while (std::getline(file, line)) {
    std::replace(line.begin(), line.end(), ',', ' ');
    std::istringstream iss(line);
    int                v;
    while (iss >> v)
      raw.push_back(v);
  }
  if (raw.empty()) {
    cerr << "[ERROR] PNB file " << path << " contains no values.\n";
    return false;
  }

  size_t end = raw.size();
  if constexpr (STRIP_LEGACY_FOOTER) {
    if (end >= 3)
      end -= 3;
    else {
      cerr << "[ERROR] PNB file " << path
           << " has fewer than 3 tokens; cannot strip legacy footer.\n";
      return false;
    }
  }

  out.reserve(end);
  for (size_t i = 0; i < end; ++i) {
    const int v = raw[i];
    if (v < 0 || v >= static_cast<int>(KEY_SIZE_BITS)) {
      cerr << "[ERROR] PNB value " << v << " in " << path
           << " is out of range [0, " << KEY_SIZE_BITS << ").\n";
      return false;
    }
    out.push_back(static_cast<u16>(v));
  }
  return true;
}

// Pre-computes:
//   - pnb_pairs:    (pnb_list[i], pnb_list[i+half]) as (word, bit) pairs.
//   - pnb_bit_mask: union mask of every PNB bit, per state word
//                   (with mirror-word entries for a 128-bit key).
//   - pnb_min_bit:  lowest PNB bit per word, or BITS_PER_WORD if none.
static void build_harmonic_tables() {
  pnb_pairs.clear();
  pnb_bit_mask.fill(0);
  pnb_min_bit.fill(static_cast<u16>(BITS_PER_WORD));

  constexpr bool key_128 = (KEY_SIZE_BITS == 128);

  auto record = [&](u16 idx, u16 &out_w, u16 &out_b) {
    u16 w = 0, b = 0;
    chacha::calculate_word_bit<TargetWord>(idx, w, b);
    pnb_bit_mask[w] |= (static_cast<TargetWord>(1) << b);
    if (b < pnb_min_bit[w])
      pnb_min_bit[w] = b;
    if constexpr (key_128) {
      const size_t mw = static_cast<size_t>(w) + 4;
      if (mw < STATE_WORDS) {
        pnb_bit_mask[mw] |= (static_cast<TargetWord>(1) << b);
        if (b < pnb_min_bit[mw])
          pnb_min_bit[mw] = b;
      }
    }
    out_w = w;
    out_b = b;
  };

  // Build per-bit tables (used by carry-lock check) over the entire list.
  for (u16 idx : pnb_list) {
    u16 w = 0, b = 0;
    record(idx, w, b);
  }

  // Build harmonic pairs over the first half of the list.
  const size_t half = pnb_list.size() / 2;
  pnb_pairs.reserve(half);
  for (size_t i = 0; i < half; ++i) {
    u16 w1 = 0, b1 = 0, w2 = 0, b2 = 0;
    chacha::calculate_word_bit<TargetWord>(pnb_list[i],          w1, b1);
    chacha::calculate_word_bit<TargetWord>(pnb_list[i + half],   w2, b2);
    pnb_pairs.push_back({BitPos{w1, b1}, BitPos{w2, b2}});
  }
}

// Harmonic carry-lock acceptance test (see file header for definition).
static bool passes_harmonic_carrylock(const TargetWord *sumstate,
                                      const TargetWord *dsumstate,
                                      const TargetWord *strdx0,
                                      const TargetWord *dstrdx0) {
  for (size_t w = 0; w < STATE_WORDS; ++w) {
    const TargetWord m = pnb_bit_mask[w];
    if (!m)
      continue;

    // (a) Every PNB bit must be set in BOTH sumstate and dsumstate.
    if ((sumstate[w]  & m) != m) return false;
    if ((dsumstate[w] & m) != m) return false;

    // (b) Min-bit segment constraint: low pnb_min_bit[w] bits of sum*
    //     must be >= the same segment of strd*.
    const u16 mb = pnb_min_bit[w];
    if (mb == 0)
      continue;
    const TargetWord seg_mask = (static_cast<TargetWord>(1) << mb) - 1U;
    if ((sumstate[w]  & seg_mask) < (strdx0[w]  & seg_mask)) return false;
    if ((dsumstate[w] & seg_mask) < (dstrdx0[w] & seg_mask)) return false;
  }
  return true;
}
