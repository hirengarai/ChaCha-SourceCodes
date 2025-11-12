/*
 * REFERENCE IMPLEMENTATION OF all the backward bias (epsilon_a) searching programme in multi-threaded manner, the carrylock, synco or pattern
 *
 *
 * created: 24/09/23
 * updated: 12/11/25
 *
 *
 * Synopsis:
 * This file contains the various types of backward bias searching programme for the stream cipher ChaCha.
 * running command: g++ filename && ./a.out or g++ -std=c++23 -flto -O3 filename -o output && ./output
 * necessary files to run the prog: upchacha.hpp, upcommonfiles2.hpp, one txt file containg the PNBs in block mode (e.g if {2,3,4,7,21,22} is a 6 pnb set then the .txt file should have it like 2, 3, 21, 4, 22, 7, 3, 2, 1
 * the last three elements are the length of the portions (it is for pattern purpose).
 */

#include "chacha.hpp" // chacha round functions
#include <cmath>        // pow function
#include <ctime>        // time
#include <chrono>       // execution time duration
#include <fstream>      // storing output in a file
#include <future>       // multithreading
#include <sstream>
#include <sys/time.h> // execution time started
#include <thread>     // multithreading

using namespace std;

config::CipherInfo basic_config;
config::DifferentialInfo diff_config;
config::SamplesInfo samples_config;
chacha::PNBInfo pnb_config;

double bwbias();

int main()
{
    Timer timer;
    cout << timer.start_message();

    basic_config.name = "ChaCha";
    basic_config.key_bits = 256;
    basic_config.mode = "Backward Bias Check";
    basic_config.total_rounds = 7.5;

    diff_config.fwd_rounds = 4;
    diff_config.id = {{13, 6}};
    diff_config.mask = {{2, 0}, {8, 0}, {7, 7}};

    samples_config.samples_per_thread = 1ULL << 20;
    samples_config.samples_per_loop = samples_config.samples_per_thread * samples_config.max_num_threads;
    samples_config.total_loop_count = 1ULL << 15;

    diff_config.output_precision = 4;

    // ===-------------------------------------------------------------------===
    pnb_config.pnb_file = "segment1.txt";
    pnb_config.pnb_pattern_flag = false;
    pnb_config.pnb_carrylock_flag = false;
    pnb_config.pnb_syncopation_flag = false;
    // ===-------------------------------------------------------------------===

    bool success = openPNBFile(pnb_config.pnb_file, pnb_config);

    if (!success)
    {
        std::cerr << "Error: Could not load PNB pattern file.\n";
        return 1;
    }

    display::showBasicConfig(basic_config, cout);
    display::showDiffConfig(diff_config, cout);
    display::showSamplesConfig(samples_config, cout);
    chacha::showPNBconfig(pnb_config, cout);

    // ---------------------------FILE CREATION------------------------------------------------------------------------------
    bool file_save_flag = false;
    // ---------------------------FILE CREATION------------------------------------------------------------------------------

    // thread portion started
    cout << basic_config.mode << " Started . . . (>>> Launching multi-threaded scenario . . .) \n";
    cout << "+--------------------------------------------------------------------------------------------------------------------------------+\n";

    display::printBiasHeader(cout);

    vector<future<double>> future_results;
    future_results.reserve(samples_config.max_num_threads);

    const u16 continuitycount{1000};
    u16 apprxbiascounter{0}, apprxbiasindex{0};
    double apprxbiaslist[continuitycount], loop{0}, SUM{0}, prob, correlation, prev_correlation{0}, precisionlimit = pow(10, -diff_config.output_precision);
    bool closeflag = false;
    while (loop < samples_config.total_loop_count)
    {
        auto loopstart = chrono::high_resolution_clock::now();
        future_results.clear();
        for (int i{0}; i < samples_config.max_num_threads; ++i)
            future_results.emplace_back(async(launch::async, bwbias));

        for (auto &f : future_results)
            SUM += f.get();

        prob = SUM / (++loop * (samples_config.samples_per_loop));
        correlation = 2 * prob - 1.0;

        closeflag = false;
        if (loop > 1 && fabs(correlation - prev_correlation) <= precisionlimit)
        {
            apprxbiaslist[apprxbiascounter] = correlation;
            apprxbiascounter++;
            closeflag = true;
        }
        else
        {
            apprxbiascounter = 0; // reset on discontinuity
            closeflag = false;
        }

        prev_correlation = correlation; // update for next iteration
        auto loopend = chrono::high_resolution_clock::now();

        stringstream row;
        auto dur_mil = chrono::duration_cast<chrono::milliseconds>(loopend - loopstart).count();
        auto dur_seconds = chrono::duration_cast<chrono::seconds>(loopend - loopstart).count();
            display::outputBias(loop, prob, prob - 0.5, correlation, dur_mil, closeflag, apprxbiascounter, cout);
    }

    if (loop == samples_config.total_loop_count)
        cout << "Bias does not converge \n";

    cout << timer.end_message();
    return 0;
}

double bwbias()
{
    chacha::InitKey init_key;

    u64 threadloop{0}, thread_match_count{0};
    u32 x0[WORD_COUNT], strdx0[WORD_COUNT], key[KEY_COUNT], dx0[WORD_COUNT], dstrdx0[WORD_COUNT], DiffState[WORD_COUNT], sumstate[WORD_COUNT], minusstate[WORD_COUNT], dsumstate[WORD_COUNT], dminusstate[WORD_COUNT];
    u16 fwd_parity, bwd_parity, WORD, BIT;

    const int rounded_total_rounds = basic_config.roundedTotalRounds();
    const int rounded_fwd_rounds = diff_config.roundedFwdRounds();
    const bool rounded_total_rounds_odd = (rounded_total_rounds % 2 != 0);
    const bool rounded_fwd_rounds_odd = (rounded_fwd_rounds % 2 != 0);
    const bool has_half = diff_config.fwdRoundsAreFractional();

    const int fwd_post_round = has_half ? rounded_fwd_rounds + 2 : rounded_fwd_rounds + 1;
    const int bwd_rounds = has_half ? rounded_fwd_rounds + 1 : rounded_fwd_rounds;

    while (threadloop < samples_config.samples_per_thread)
    {
        bwd_parity = 0;
        while (1)
        {
            fwd_parity = 0;
            chacha::init_iv_const(x0);
            if (basic_config.key_bits == 128)
                init_key.key_128bit(key);
            else
                init_key.key_256bit(key);

            chacha::insert_key(x0, key);

            ops::copyState(strdx0, x0);
            ops::copyState(dx0, x0);
            // ----------------------------------DIFF.INJECTION--------------------------------------------------------------
            for (const auto &d : diff_config.id)
                TOGGLE_BIT(dx0[d.first], d.second);
            ops::copyState(dstrdx0, dx0);
            // ---------------------------FW ROUND STARTS--------------------------------------------------------------------
            for (int i{1}; i <= rounded_fwd_rounds; ++i)
            {
                frward.RoundFunction(x0, i);
                frward.RoundFunction(dx0, i);
            }
            if (has_half)
            {
                if (rounded_fwd_rounds_odd)
                {
                    frward.Half_1_EvenRF(x0);
                    frward.Half_1_EvenRF(dx0);
                }
                else
                {
                    frward.Half_1_OddRF(x0);
                    frward.Half_1_OddRF(dx0);
                }
            }

            ops::xorState(DiffState, x0, dx0);

            for (const auto &d : diff_config.mask)
                fwd_parity ^= GET_BIT(DiffState[d.first], d.second);

            if (diff_config.fwdRoundsAreFractional())
            {
                if (rounded_fwd_rounds_odd)
                {
                    frward.Half_2_EvenRF(x0);
                    frward.Half_2_EvenRF(dx0);
                }
                else
                {
                    frward.Half_2_OddRF(x0);
                    frward.Half_2_OddRF(dx0);
                }
            }

            for (int i{fwd_post_round}; i <= rounded_total_rounds; ++i)
            {
                frward.RoundFunction(x0, i);
                frward.RoundFunction(dx0, i);
            }

            if (basic_config.totalRoundsAreFractional())
            {
                if (rounded_total_rounds_odd)
                {
                    frward.Half_1_EvenRF(x0);
                    frward.Half_1_EvenRF(dx0);
                }
                else
                {
                    frward.Half_1_OddRF(x0);
                    frward.Half_1_OddRF(dx0);
                }
            }
            // ---------------------------FW ROUND ENDs-----------------------------------------------------------------------

            // modular addition of states

            ops::addState(sumstate, x0, strdx0);
            ops::addState(dsumstate, dx0, dstrdx0);

            if (pnb_config.pnb_carrylock_flag)
            {

                // u16 w, bstart, bend;

                // u32 mask = 0;
                // size_t n = pnb_config.pnbs.size();

                // if (n >= 32)
                //     mask = 0xFFFFFFFF;
                // else
                //     mask = (1u << n) - 1;

                // w = pnb_config.pnbs.front() / WORD_SIZE + 4;
                // bstart = pnb_config.pnbs.at(0) % WORD_SIZE;
                // bend = pnb_config.pnbs.back() % WORD_SIZE;

                // // bool bit1 = GET_BIT(sumstate[w], b);
                // // bool bit2 = GET_BIT(dsumstate[w], b);

                // // bool sbit1 = GET_BIT(sumstate[w + 4], b);
                // // bool sbit2 = GET_BIT(dsumstate[w + 4], b);

                // u32 pnbseg = ops::bitSegment(sumstate[w], bstart, bend);
                // u32 dpnbseg = ops::bitSegment(dsumstate[w], bstart, bend);

                // u32 seg = ops::bitSegment(sumstate[w], 0, bstart - 1);
                // u32 dseg = ops::bitSegment(dsumstate[w], 0, bstart - 1);

                // u32 strseg = ops::bitSegment(strdx0[w], 0, bstart - 1);
                // u32 dstrseg = ops::bitSegment(dstrdx0[w], 0, bstart - 1);

                // // u32 sseg = ops::bitSegment(sumstate[w + 4], 0, b - 1);
                // // u32 dsseg = ops::bitSegment(dsumstate[w + 4], 0, b - 1);

                // // u32 sstrseg = ops::bitSegment(strdx0[w + 4], 0, b - 1);
                // // u32 dsstrseg = ops::bitSegment(dstrdx0[w + 4], 0, b - 1);

                // bool w1 = (seg >= strseg) && (dseg >= dstrseg);

                // bool w2 = (pnbseg == mask && dpnbseg == mask);

                // if (w1 && w2)


                ops::xorState(sumstate, x0, strdx0);
                ops::xorState(dsumstate, dx0, dstrdx0);
                break;
            }
            else if (pnb_config.pnb_syncopation_flag)
            {
                u16 zcond = GET_BIT(sumstate[6], 9); 
                u16 dzcond = GET_BIT(dsumstate[6], 9);
                u16 kcond = GET_BIT(strdx0[6], 9);

                if ((zcond ^ kcond) && (dzcond ^ kcond))
                    break;
            }
            else
                break;
        }

        // randomise the PNBs
        if (pnb_config.pnb_pattern_flag)
        {
            for (size_t i{0}; i < pnb_config.pnbs_in_pattern.size(); ++i)
            {
                chacha::calculate_word_bit(pnb_config.pnbs_in_pattern[i], WORD, BIT);
                UNSET_BIT(strdx0[WORD], BIT);
                UNSET_BIT(dstrdx0[WORD], BIT);

                if (basic_config.key_bits == 128)
                {
                    UNSET_BIT(strdx0[WORD + 4], BIT);
                    UNSET_BIT(dstrdx0[WORD + 4], BIT);
                }
            }
            for (size_t i{0}; i < pnb_config.pnbs_in_border.size(); ++i)
            {
                chacha::calculate_word_bit(pnb_config.pnbs_in_border[i], WORD, BIT);
                SET_BIT(strdx0[WORD], BIT);
                SET_BIT(dstrdx0[WORD], BIT);
                if (basic_config.key_bits == 128)
                {
                    SET_BIT(strdx0[WORD + 4], BIT);
                    SET_BIT(dstrdx0[WORD + 4], BIT);
                }
            }
            for (size_t i{0}; i < pnb_config.rest_pnbs.size(); ++i)
            {
                chacha::calculate_word_bit(pnb_config.rest_pnbs[i], WORD, BIT);
                if (RandomBoolean())
                {
                    TOGGLE_BIT(strdx0[WORD], BIT);
                    TOGGLE_BIT(dstrdx0[WORD], BIT);
                }
                if (basic_config.key_bits == 128)
                {
                    TOGGLE_BIT(strdx0[WORD + 4], BIT);
                    TOGGLE_BIT(dstrdx0[WORD + 4], BIT);
                }
            }
        }
        else
        {
            for (size_t i{0}; i < pnb_config.pnbs.size(); ++i)
            {
                chacha::calculate_word_bit(pnb_config.pnbs[i], WORD, BIT);

                if (RandomBoolean())
                {
                    TOGGLE_BIT(strdx0[WORD], BIT);
                    TOGGLE_BIT(dstrdx0[WORD], BIT);
                }
                if (basic_config.key_bits == 128)
                {
                    TOGGLE_BIT(strdx0[WORD + 4], BIT);
                    TOGGLE_BIT(dstrdx0[WORD + 4], BIT);
                }
            }
        }

        // modular subtraction of states
        ops::minusState(minusstate, sumstate, strdx0);
        ops::minusState(dminusstate, dsumstate, dstrdx0);

        if (pnb_config.pnb_carrylock_flag)
        {
            ops::xorState(minusstate, sumstate, strdx0);
            ops::xorState(dminusstate, dsumstate, dstrdx0);
        }

        // ---------------------------BW ROUND STARTS--------------------------------------------------------------------
        if (basic_config.totalRoundsAreFractional())
        {
            if (rounded_total_rounds_odd)
            {
                bckward.Half_2_EvenRF(minusstate);
                bckward.Half_2_EvenRF(dminusstate);
            }
            else
            {
                bckward.Half_2_OddRF(minusstate);
                bckward.Half_2_OddRF(dminusstate);
            }
        }
        for (int i{rounded_total_rounds}; i > bwd_rounds; i--)
        {
            bckward.RoundFunction(minusstate, i);
            bckward.RoundFunction(dminusstate, i);
        }

        if (diff_config.fwdRoundsAreFractional())
        {
            if (rounded_fwd_rounds_odd)
            {
                bckward.Half_1_EvenRF(minusstate);
                bckward.Half_1_EvenRF(dminusstate);
            }
            else
            {
                bckward.Half_1_OddRF(minusstate);
                bckward.Half_1_OddRF(dminusstate);
            }
        }
        // ---------------------------BW ROUND ENDS----------------------------------------------------------------------

        ops::xorState(DiffState, minusstate, dminusstate);

        for (const auto &d : diff_config.mask)
            bwd_parity ^= GET_BIT(DiffState[d.first], d.second);

        if (bwd_parity == fwd_parity)
            thread_match_count++;
        threadloop++;
    }
    return static_cast<double>(thread_match_count);
}
