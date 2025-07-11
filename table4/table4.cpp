/*
 * REFERENCE IMPLEMENTATION OF backward bias (epsilon_a) searching programme in multi-threaded manner in cpp
 *
 *
 * created: 24/9/23
 * updated: 29/6/25
 *
 *
 *
 *
 * Synopsis:
 * This file contains the backward bias searching programme for the stream cipher ChaCha.
 * running command: g++ bwbiasthreaded.cpp && ./a.out or g++ -std=c++23 -flto -O3 table.cpp -o output && ./output
 * necessary files to run the prog: commonfiles2.h, chacha.h, one txt file containg the PNBs in block mode without comma and bracket (e.g if {2,3,4,7,21,22} is a 6 pnb set then the .txt file = 2 3 21 4 22 7 3 2 1
 * the last three elements are the lengths of the three types pnbs)
 */

#include "chacha.h" // chacha round functions
#include <cmath>    // pow function
#include <ctime>    // time
#include <chrono>   // execution time duration
#include <fstream>  // storing output in a file
#include <future>   // multithreading
#include <sstream>
#include <sys/time.h> // execution time started
#include <thread>     // multithreading

using namespace std;
using namespace CHACHA;
using namespace CONFIGURATION;
using namespace OPERATIONS;
using namespace OUTPUT;

double bwbias();

int main()
{
    cout << timer.start_message();

    basic_config.cipher = "ChaCha-256";
    basic_config.mode = "Backward Bias Determiantion";
    basic_config.total_round = 7;
    basic_config.total_halfround_flag = true;

    diff_config.fwdround = 4; // can now hold 3.5, 7.5 etc.

    const u16 max_num_threads = 11;

    samples_config.samples_per_thread = 1ULL << 20;

    samples_config.samples_per_loop = samples_config.samples_per_thread * max_num_threads;
    samples_config.total_loop = 1ULL << 15; // Number of times the inner loop will run

    diff_config.ID = {{0, 13, 6}};
    diff_config.mask = {{4, 2, 0}, {4, 7, 7}, {4, 8, 0}};

    diff_config.precision_digit = 4;

    // ===-------------------------------------------------------------------===
    pnb_config.pnb_search_flag = false;
    pnb_config.pnb_file = "key2block1_pattern.txt";
    pnb_config.pnb_pattern_flag = false;
    pnb_config.pnb_carrylock_flag = true;
    pnb_config.pnb_syncopation_flag = false;
    // ===-------------------------------------------------------------------===

    bool success = OpenPNBFile(pnb_config.pnb_file, pnb_config);

    if (!success)
    {
        std::cerr << "Error: Could not load PNB pattern file.\n";
        return 1;
    }

    print_basic_config(basic_config, cout);
    print_diff_config(diff_config, cout);
    print_samples_config(samples_config, cout);
    print_pnb_config(pnb_config, cout);

    // ---------------------------FILE CREATION------------------------------------------------------------------------------
    bool file_save_flag = false;
    cout << "file_save_flag: " << file_save_flag << "\n";
    // ---------------------------FILE CREATION------------------------------------------------------------------------------

    cout << "# of threads: " << max_num_threads << "\n";
    cout << "Bias Calculation Started . . . (Shh! It's a multi-threaded programme and will take some time !)\n";
    cout << "Have patience with a cup of tea . . .\n";
    cout << "\n+------------------------------------------------------------------------------------+\n";

    print_header(cout);

    future<double> futureCounts[max_num_threads];

    const u16 continuitycount{1000};
    u16 apprxbiascounter{0}, apprxbiasindex{0};
    double apprxbiaslist[continuitycount], loop{0}, SUM{0}, prob, correlation, prev_correlation{0}, precisionlimit = pow(10, -diff_config.precision_digit);
    bool closeflag = false;
    while (loop < samples_config.total_loop)
    {
        auto loopstart = std::chrono::high_resolution_clock::now();
        for (int i{0}; i < max_num_threads; ++i)
            futureCounts[i] = std::async(std::launch::async, bwbias);

        for (auto &f : futureCounts)
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
        auto dur_mil = std::chrono::duration_cast<std::chrono::milliseconds>(loopend - loopstart).count();
        auto dur_seconds = std::chrono::duration_cast<std::chrono::seconds>(loopend - loopstart).count();

        output_result(loop, prob, prob - 0.5, correlation, dur_mil, closeflag, loop - 1, cout);
    }

    if (loop == samples_config.total_loop)
        cout << "Bias does not converge \n";

    cout << timer.end_message();
    return 0;
}

double bwbias()
{
    double threadloop{0}, thread_match_count{0};
    u32 x0[WORD_COUNT], strdx0[WORD_COUNT], key[KEY_COUNT], dx0[WORD_COUNT], dstrdx0[WORD_COUNT], DiffState[WORD_COUNT], sumstate[WORD_COUNT], minusstate[WORD_COUNT], dsumstate[WORD_COUNT], dminusstate[WORD_COUNT], condition, dcondition, kcondition, seg, dseg, strseg, dstrseg, temp;
    u16 fwdBit, bwdBit, WORD, BIT;

    const int full_fwd_rounds = diff_config.rounded_round();
    const int total_fwd_rounds = static_cast<int>(basic_config.total_round);

    while (threadloop < samples_config.samples_per_thread)
    {

        while (1)
        {
            fwdBit = 0;
            bwdBit = 0;

            init_iv_const(x0);
            init_key.key_256bit(key);
            insert_key(x0, key);

            copy_state(strdx0, x0);
            copy_state(dx0, x0);
            // ----------------------------------DIFF.INJECTION--------------------------------------------------------------
            for (const auto &d : diff_config.ID)
                inject_diff(dx0, d.word, d.bit);
            copy_state(dstrdx0, dx0);
            // ---------------------------FW ROUND STARTS--------------------------------------------------------------------
            for (int i{1}; i <= full_fwd_rounds; ++i)
            {
                frward.RoundFunction(x0, i);
                frward.RoundFunction(dx0, i);
            }

            xor_state_oop(DiffState, x0, dx0);

            // difference_bit_1(DiffState, diff_config.mask, fwdBit);

            fwdBit ^= get_bit(DiffState[2], 0);
            fwdBit ^= get_bit(DiffState[8], 0);
            fwdBit ^= get_bit(DiffState[7], 7);

            for (int i{full_fwd_rounds + 1}; i <= total_fwd_rounds; ++i)
            {
                frward.RoundFunction(x0, i);
                frward.RoundFunction(dx0, i);
            }
            if (basic_config.total_halfround_flag)
            {
                if (total_fwd_rounds % 2)
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
            add_state_oop(sumstate, x0, strdx0);
            add_state_oop(dsumstate, dx0, dstrdx0);

            if (pnb_config.pnb_carrylock_flag)
            {
                seg = bit_segment(sumstate[6], 0, 5);
                dseg = bit_segment(dsumstate[6], 0, 5);
                strseg = bit_segment(strdx0[6], 0, 5);
                dstrseg = bit_segment(dstrdx0[6], 0, 5);

                bool z1 =
                    get_bit(sumstate[6], 6) &&
                    get_bit(sumstate[6], 7) &&
                    get_bit(sumstate[6], 8);

                bool z2 =
                    get_bit(dsumstate[6], 6) &&
                    get_bit(dsumstate[6], 7) &&
                    get_bit(dsumstate[6], 8);

                if ((seg >= strseg) && (dseg >= dstrseg) && z1 && z2)
                {
                    break;
                }
            }
            else if (pnb_config.pnb_syncopation_flag)
            {
                condition = get_bit(sumstate[6], 9);
                dcondition = get_bit(dsumstate[6], 9);
                kcondition = ~get_bit(strdx0[6], 9) & 1;

                if ((condition == kcondition) && (dcondition == kcondition))
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
                calculate_word_bit(pnb_config.pnbs_in_pattern[i], WORD, BIT);
                unset_bit(strdx0[WORD], BIT);
                unset_bit(dstrdx0[WORD], BIT);
            }
            for (size_t i{0}; i < pnb_config.pnbs_in_border.size(); ++i)
            {
                calculate_word_bit(pnb_config.pnbs_in_border[i], WORD, BIT);
                set_bit(strdx0[WORD], BIT);
                set_bit(dstrdx0[WORD], BIT);
            }
            for (size_t i{0}; i < pnb_config.rest_pnbs.size(); ++i)
            {
                calculate_word_bit(pnb_config.rest_pnbs[i], WORD, BIT);
                if (GenerateRandomBoolean())
                {
                    toggle_bit(strdx0[WORD], BIT);
                    toggle_bit(dstrdx0[WORD], BIT);
                }
            }
        }
        else
        {
            for (size_t i{0}; i < pnb_config.pnbs.size(); ++i)
            {
                calculate_word_bit(pnb_config.pnbs[i], WORD, BIT);

                if (GenerateRandomBoolean())
                {
                    toggle_bit(strdx0[WORD], BIT);
                    toggle_bit(dstrdx0[WORD], BIT);
                }
            }
        }

        // modular subtraction of states
        subtract_state_oop(minusstate, sumstate, strdx0);
        subtract_state_oop(dminusstate, dsumstate, dstrdx0);

        // ---------------------------BW ROUND STARTS--------------------------------------------------------------------
        if (basic_config.total_halfround_flag)
        {
            if (total_fwd_rounds % 2)
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
        for (int i{total_fwd_rounds}; i > full_fwd_rounds; i--)
        {
            bckward.RoundFunction(minusstate, i);
            bckward.RoundFunction(dminusstate, i);
        }
        // ---------------------------BW ROUND ENDS----------------------------------------------------------------------

        xor_state_oop(DiffState, minusstate, dminusstate);

        bwdBit ^= get_bit(DiffState[2], 0);
        bwdBit ^= get_bit(DiffState[8], 0);
        bwdBit ^= get_bit(DiffState[7], 7);

        if (bwdBit == fwdBit)
            thread_match_count++;
        threadloop++;
    }
    return thread_match_count;
}
