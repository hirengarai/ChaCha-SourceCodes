/*
 * REFERENCE IMPLEMENTATION OF backward bias (epsilon_a) searching programme in multi-threaded manner in cpp
 *
 * Filename: bwbiasthreaded.cpp
 *
 * created: 24/9/23
 * updated: 29/6/25
 *
 * by Hiren
 * Research Fellow
 * NTU Singapore
 *
 * Synopsis:
 * This file contains the backward bias searching programme for the stream cipher ChaCha.
 * running command: g++ bwbiasthreaded.cpp && ./a.out or g++ -std=c++23 -flto -O3 bwbiasthreaded.cpp -o output && ./output
 * necessary files to run the prog: commonfiles2.h, chacha.h, one txt file containg the PNBs
 */

#include "chacha.h"                           // chacha round functions
#include <cmath>                              // pow function
#include <ctime>                              // time
#include <chrono>                             // execution time duration
#include <fstream>                            // storing output in a file
#include <future>                             // multithreading
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
    // time calculation
    auto progstart = std::chrono::high_resolution_clock::now();
    time_t t = time(nullptr);
    tm *lt = localtime(&t); // Declares a pointer lt to a structure of type tm. The tm structure holds information about date and time
    // time calculation

    bool filesave = false;
    ofstream file;

    // if (filesave)
    //     file.open("bias" + PNBdetails.PNBfile); // or any name like "bias.txt"

    stringstream startmsg;
    startmsg << "######## Execution started on: "
             << lt->tm_mday << '/' << lt->tm_mon + 1 << '/' << lt->tm_year + 1900 << " at "
             << lt->tm_hour << ':' << lt->tm_min << ':' << lt->tm_sec << " ########\n";
    write_out(&file, filesave, startmsg.str());

    basic_config.cipher = "ChaCha-256";
    basic_config.mode = "Backward Bias Determiantion";
    basic_config.total_round = 7;
    basic_config.total_halfround_flag = true;

    diff_config.fwdround = 4;

    const u16 max_num_threads = 11;
    samples_config.samples_per_thread = 1ULL << 22;

    samples_config.samples_per_loop = samples_config.samples_per_thread * max_num_threads;
    samples_config.total_loop = 1ULL << 15; // Number of times the inner loop will run

    diff_config.ID = {{0, 13, 6}};
    diff_config.mask = {{4, 2, 0}, {4, 7, 7}, {4, 8, 0}};

    diff_config.precision_digit = 4;


    // ===-------------------------------------------------------------------===
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

    stringstream initmsg;
    initmsg << "# of threads: " << max_num_threads << "\n";
    initmsg << "Bias Calculation Started . . . (Shh! It's a multi-threaded programme and will take some time !)\n";
    initmsg << "Have patience with a cup of tea . . .\n";
    write_out(&file, filesave, initmsg.str());

    print_header(cout);

    future<double> futureCounts[max_num_threads];

    const u16 continuitycount{1000};
    u16 apprxbiascounter{0}, apprxbiasindex{0};
    double apprxbiaslist[continuitycount], loop{0}, SUM{0}, prob, correlation, temp{0}, precisionlimit = pow(10, -diff_config.precision_digit);
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
        if (fabs(fabs(correlation) - temp) <= precisionlimit)
        {
            closeflag = true;
            apprxbiascounter++;
            apprxbiaslist[apprxbiasindex++] = correlation;
        }
        else
        {
            apprxbiascounter = 0;
            apprxbiasindex = 0;
        }
        auto loopend = chrono::high_resolution_clock::now();

        stringstream row;

        output_result(loop, prob, prob - 0.5, correlation, (chrono::duration<double, std::micro>(loopend - loopstart).count()) / 1000000.0, closeflag, loop - 1, row);

        write_out(&file, filesave, row.str());

        temp = fabs(correlation);

        if (apprxbiascounter >= continuitycount)
        {
            stringstream biasinfo;
            biasinfo << "Median Bias ~ " << fixed << setprecision(5)
                     << CalculateMedian(apprxbiaslist, sizeof(apprxbiaslist) / sizeof(apprxbiaslist[0])) << "\n";
            biasinfo << "The latest " << continuitycount << " biases are as follows:\n";
            for (const auto &i : apprxbiaslist)
                biasinfo << i << "\n";
            biasinfo << "Number of loops: " << loop << "\n";
            write_out(&file, filesave, biasinfo.str());
            break;
        }
    }

    if (loop == samples_config.total_loop)
        write_out(&file, filesave, "The bias does not converge\n");

    time(&t);           // Gets the current time since epoch (Jan 1, 1970)
    lt = localtime(&t); // Converts the time stored in t to a local time representation and stores it in the tm structure pointed to by lt.
    auto progend = std::chrono::high_resolution_clock::now();
    auto duration = chrono::duration<double, std::micro>(progend - progstart).count();

    stringstream finalmsg;
    finalmsg << "######## Execution ended on: "
             << lt->tm_mday << '/' << lt->tm_mon + 1 << '/' << lt->tm_year + 1900 << " at "
             << lt->tm_hour << ':' << lt->tm_min << ':' << lt->tm_sec << " ########\n";
    finalmsg << "Total execution time: " << duration << " seconds\n";
    write_out(&file, filesave, finalmsg.str());

    if (file.is_open())
        file.close();
    return 0;
}

double bwbias()
{
    double threadloop{0}, thread_match_count{0};
    u32 x0[WORD_COUNT], strdx0[WORD_COUNT], key[KEY_COUNT], dx0[WORD_COUNT], dstrdx0[WORD_COUNT], DiffState[WORD_COUNT], sumstate[WORD_COUNT], minusstate[WORD_COUNT], dsumstate[WORD_COUNT], dminusstate[WORD_COUNT], condition, dcondition, kcondition, temp;
    std::vector<u32 *> round_diffstates;
    u8 fwdBit, bwdBit;
    u16 WORD, WORD1, BIT, BIT1;

    const int full_fwd_rounds = diff_config.rounded_round();
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

            xor_state(DiffState, x0, dx0, WORD_COUNT);

            // difference_bit_1(DiffState, diff_config.mask, fwdBit);

            fwdBit ^= get_bit(DiffState[2], 0);
            fwdBit ^= get_bit(DiffState[8], 0);
            fwdBit ^= get_bit(DiffState[7], 7);

            for (int i{full_fwd_rounds + 1}; i <= static_cast<int>(basic_config.total_round); ++i)
            {
                frward.RoundFunction(x0, i);
                frward.RoundFunction(dx0, i);
            }
            frward.Half_1_EvenRF(x0);
            frward.Half_1_EvenRF(dx0);
            // ---------------------------FW ROUND ENDs-----------------------------------------------------------------------

            if (pnb_config.pnb_carrylock_flag)
            {
                xor_state(sumstate, x0, strdx0);
                xor_state(dsumstate, dx0, dstrdx0);
            }
            else
            {
                // modular addition of states
                add_state_oop(sumstate, x0, strdx0);
                add_state_oop(dsumstate, dx0, dstrdx0);
            }

            if (pnb_config.pnb_syncopation_flag)
            {
                condition = get_bit(sumstate[6], 9);
                dcondition = get_bit(dsumstate[6], 9);
                kcondition = ~get_bit(strdx0[6], 9) & 1;

                if ((condition == kcondition) && (dcondition == kcondition))
                    break;
            }
            else
            {
                break;
            }
        }

        // randomise the PNBs
        if (pnb_config.pnb_pattern_flag)
        {
            for (int i{0}; i < pnb_config.pnbs_in_pattern.size(); ++i)
            {
                calculate_word_bit(pnb_config.pnbs_in_pattern[i], WORD, BIT);
                clear_bit(strdx0[WORD], BIT);
                clear_bit(dstrdx0[WORD], BIT);
            }
            for (int i{0}; i < pnb_config.pnbs_in_border.size(); ++i)
            {
                calculate_word_bit(pnb_config.pnbs_in_border[i], WORD, BIT);
                set_bit(strdx0[WORD], BIT);
                set_bit(dstrdx0[WORD], BIT);
            }
            for (int i{0}; i < pnb_config.rest_pnbs.size(); ++i)
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
            for (int i{0}; i < pnb_config.pnbs.size(); ++i)
            {
                calculate_word_bit(pnb_config.pnbs[i], WORD, BIT);

                if (GenerateRandomBoolean())
                {
                    toggle_bit(strdx0[WORD], BIT);
                    toggle_bit(dstrdx0[WORD], BIT);
                }
            }
        }

        if (pnb_config.pnb_carrylock_flag)
        {
            xor_state(minusstate, sumstate, strdx0);
            xor_state(dminusstate, dsumstate, dstrdx0);
        }
        else
        {
            // modular subtraction of states
            subtract_state_oop(minusstate, sumstate, strdx0);
            subtract_state_oop(dminusstate, dsumstate, dstrdx0);
        }
       
        // ---------------------------BW ROUND STARTS--------------------------------------------------------------------
        bckward.Half_2_EvenRF(minusstate);
        bckward.Half_2_EvenRF(dminusstate);
        for (int i{static_cast<int>(basic_config.total_round)}; i > full_fwd_rounds; i--)
        {
            bckward.RoundFunction(minusstate, i);
            bckward.RoundFunction(dminusstate, i);
        }
        // ---------------------------BW ROUND ENDS----------------------------------------------------------------------

        xor_state(DiffState, minusstate, dminusstate, WORD_COUNT);

        bwdBit ^= get_bit(DiffState[2], 0);
        bwdBit ^= get_bit(DiffState[8], 0);
        bwdBit ^= get_bit(DiffState[7], 7);

        if (bwdBit == fwdBit)
            thread_match_count++;
        threadloop++;
    }
    return thread_match_count;
}
