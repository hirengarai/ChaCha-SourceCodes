/*
 *
 * Synopsis:
 * This file contains the PNB searching programe using carry-lock for the stream cipher ChaCha
 * 
 * CLI:
 *   g++ -std=c++2c -O3 filename.cpp -o output && ./output nm log
 *
 * Needs: commonfiles.hpp, chacha.hpp
 */

#include "../header/chacha.hpp" // chacha round functions
#include <cmath>             // pow function
#include <ctime>             // time
#include <fstream>           // storing output in a file
#include <future>            // multithreading
#include <sstream>
#include <thread> // multithreading

using namespace std;

config::CipherInfo basic_config;
config::DifferentialInfo diff_config;
config::SamplesInfo samples_config;
chacha::PNBInfo pnb_config;

using BiasEntry = pair<u16, double>;

bool passes_carrylock(const u32 *sumstate, const u32 *dsumstate,
                      const u32 *strdx0, const u32 *dstrdx0,
                      int key_word, int key_bit, bool check_mirror);
double matchcount(int key_bit, int key_word);

// ---------------- main function -----------------
int main(int argc, char *argv[])
{
    bool log_to_file = false;

    if (argc >= 2)
    {
        try
        {
            pnb_config.neutrality_measure = std::stod(argv[1]);
            if (pnb_config.neutrality_measure < 0.0 || pnb_config.neutrality_measure > 1.0)
            {
                std::cerr << "Neutrality must be in [0,1]. Using default 0.0.\n";
                pnb_config.neutrality_measure = 0.0;
            }
        }
        catch (...)
        {
            std::cerr << "Invalid neutrality input. Using default 0.0.\n";
            pnb_config.neutrality_measure = 0.0;
        }
    }

    if (argc >= 3)
    {
        std::string flag = argv[2];
        if (flag == "log" || flag == "LOG" || flag == "1")
            log_to_file = true;
        else
            log_to_file = false;
    }

    Timer timer;

    stringstream dmsg; //  log buffer

    dmsg << timer.start_message();

    // ---------------- config -----------------
    basic_config.name = "ChaCha";
    basic_config.key_bits = 128;
    basic_config.total_rounds = 7;

    diff_config.fwd_rounds = 4;
    diff_config.id = {{13, 6}};
    diff_config.mask = {{2, 0}, {8, 0}, {7, 7}};

    samples_config.samples_per_thread = 1ULL << 17;
    samples_config.samples_per_loop =
        samples_config.samples_per_thread * samples_config.max_num_threads;

    size_t key_count =
        (basic_config.key_bits == 128) ? KEY_COUNT - 4 : KEY_COUNT;

    pnb_config.pnb_search_flag = true;

    display::showBasicConfig(basic_config, dmsg);
    display::showDiffConfig(diff_config, dmsg);
    display::showSamplesConfig(samples_config, dmsg);
    chacha::showPNBconfig(pnb_config, dmsg);

    cout << dmsg.str();
    // ---------------- config end -----------------

    vector<BiasEntry> all_pnbs;
    vector<BiasEntry> all_nonpnbs;

    vector<BiasEntry> temp_pnb;
    vector<BiasEntry> temp_non_pnb;

    all_pnbs.reserve(256);
    all_nonpnbs.reserve(256);
    temp_pnb.reserve(256);
    temp_non_pnb.reserve(256);

    double sum, bias;

    vector<std::future<double>> future_results;
    future_results.reserve(samples_config.max_num_threads);

    // ---------------- key-word / key-bit loop -----------------
    for (size_t key_word{0}; key_word < key_count; ++key_word)
    {
        for (size_t key_bit{0}; key_bit < WORD_SIZE; key_bit++)
        {
            u16 global_idx = static_cast<u16>(key_word * WORD_SIZE + key_bit);

            sum = 0.0;
            future_results.clear();

            // ---------------- launch threads for this (key_word, key_bit) -----------------
            for (u16 thread_number{0}; thread_number < samples_config.max_num_threads; ++thread_number)
                future_results.emplace_back(async(launch::async, matchcount, static_cast<int>(key_bit), static_cast<int>(key_word)));

            try
            {
                for (auto &f : future_results)
                    sum += f.get();
            }
            catch (const exception &e)
            {
                cerr << "Thread error: " << e.what() << "\n";
            }

            // samples_per_loop = samples_per_thread * max_num_threads
            bias = (2.0 * sum / static_cast<double>(samples_config.samples_per_loop)) - 1.0;

            if (std::fabs(bias) >= pnb_config.neutrality_measure)
                temp_pnb.push_back({global_idx, bias});
            else
                temp_non_pnb.push_back({global_idx, bias});
        }

        for (auto &l : temp_pnb)
            all_pnbs.push_back(l);

        for (auto &l : temp_non_pnb)
            all_nonpnbs.push_back(l);

        temp_pnb.clear();
        temp_non_pnb.clear();
    }

    // ---------------- deduplicate + sort PNB and non-PNB lists -----------------
    auto sort_by_index = [](auto &v)
    {
        std::sort(v.begin(), v.end(),
                  [](const auto &a, const auto &b)
                  { return a.first < b.first; });
        v.erase(std::unique(v.begin(), v.end(),
                            [](const auto &x, const auto &y)
                            { return x.first == y.first; }),
                v.end());
    };

    sort_by_index(all_pnbs);
    sort_by_index(all_nonpnbs);

    std::vector<u16> pnbs_sorted_by_index;
    pnbs_sorted_by_index.reserve(all_pnbs.size());
    for (auto &e : all_pnbs)
        pnbs_sorted_by_index.push_back(e.first);

    cout << "\n";
    cout << pnbs_sorted_by_index.size() << " PNBs (sorted by index):\n{";
    for (std::size_t i{0}; i < pnbs_sorted_by_index.size(); ++i)
    {
        cout << pnbs_sorted_by_index[i];
        if (i + 1 != pnbs_sorted_by_index.size())
            cout << ", ";
    }
    cout << "}\n";
    cout << "\n";

    // ---------------- save log (if enabled) -----------------
    if (log_to_file)
    {
        // PNB sorted by |bias| (descending)
        std::vector<std::pair<u16, double>> pnbs_sorted_by_bias = all_pnbs;
        std::sort(pnbs_sorted_by_bias.begin(), pnbs_sorted_by_bias.end(),
                  [](const auto &a, const auto &b)
                  {
                      return std::fabs(a.second) > std::fabs(b.second);
                  });

        // non-PNB sorted by index
        std::vector<u16> nonpnbs_sorted_by_index;
        nonpnbs_sorted_by_index.reserve(all_nonpnbs.size());
        for (auto &e : all_nonpnbs)
            nonpnbs_sorted_by_index.push_back(e.first);

        // per-bit biases (size = 256 always)
        std::vector<double> bias_per_bit(256, 0.0);
        for (auto &e : all_pnbs)
            bias_per_bit[e.first] = e.second;
        for (auto &e : all_nonpnbs)
            bias_per_bit[e.first] = e.second;

        auto append_index_list = [&](const std::string &label, const std::vector<u16> &list)
        {
            dmsg << "\n"
                 << label << " (" << list.size() << "):\n{";
            for (std::size_t i{0}; i < list.size(); ++i)
            {
                dmsg << list[i];
                if (i + 1 != list.size())
                    dmsg << ", ";
            }
            dmsg << "}\n";
        };

        auto append_bias_list = [&](const std::string &label, const std::vector<std::pair<u16, double>> &list)
        {
            dmsg << "\n"
                 << label << " (" << list.size() << "):\n{";
            for (std::size_t i{0}; i < list.size(); ++i)
            {
                dmsg << list[i].first << ":" << list[i].second;
                if (i + 1 != list.size())
                    dmsg << ", ";
            }
            dmsg << "}\n";
        };

        append_index_list("PNBs sorted by index", pnbs_sorted_by_index);
        append_bias_list("PNBs sorted by |bias|", pnbs_sorted_by_bias);
        append_index_list("Non-PNBs sorted by index", nonpnbs_sorted_by_index);

        dmsg << "\nBias per bit (index: bias):\n{";
        for (std::size_t i{0}; i < bias_per_bit.size(); ++i)
        {
            dmsg << i << ":" << bias_per_bit[i];
            if (i + 1 != bias_per_bit.size())
                dmsg << ", ";
        }
        dmsg << "}\n";

        dmsg << timer.end_message();

        // ---------------- save file -----------------
        std::ostringstream filename;
        filename << "pnb_search_" << basic_config.name << "_" << basic_config.key_bits
                 << "_r" << basic_config.total_rounds << "_f" << diff_config.fwd_rounds
                 << ".log";
        std::ofstream fout(filename.str());
        if (fout.is_open())
        {
            fout << dmsg.str();
            fout.close();
            std::cout << "Log saved to: " << filename.str() << "\n";
        }
        else
        {
            std::cerr << "ERROR: Could not write log file: " << filename.str() << "\n";
        }
    }

    cout << timer.end_message();
    return 0;
}

bool passes_carrylock(const u32 *sumstate, const u32 *dsumstate,
                      const u32 *strdx0, const u32 *dstrdx0,
                      int key_word, int key_bit, bool check_mirror)
{
    u16 word = static_cast<u16>(key_word + 4);
    u16 mirror_word = static_cast<u16>(word + 4);

    auto check_word = [&](u16 word_idx)
    {
        bool bit1 = GET_BIT(sumstate[word_idx], key_bit);
        bool bit2 = GET_BIT(dsumstate[word_idx], key_bit);

        if (!key_bit)
            return bit1 && bit2;

        u32 seg = ops::bitSegment(sumstate[word_idx], 0, key_bit - 1);
        u32 dseg = ops::bitSegment(dsumstate[word_idx], 0, key_bit - 1);

        u32 strseg = ops::bitSegment(strdx0[word_idx], 0, key_bit - 1);
        u32 dstrseg = ops::bitSegment(dstrdx0[word_idx], 0, key_bit - 1);

        bool w1 = (seg >= strseg) && (dseg >= dstrseg);

        return w1 && bit1 && bit2;
    };

    if (!check_word(word))
        return false;
    if (check_mirror)
        return check_word(mirror_word);
    return true;
}

// ---------------- worker: match count for one (key_word, key_bit) -----------------
double matchcount(int key_bit, int key_word)
{
    chacha::InitKey init_key;
    u64 thread_match_count{0};

    u32 x0[WORD_COUNT], strdx0[WORD_COUNT], key[KEY_COUNT],
        dx0[WORD_COUNT], dstrdx0[WORD_COUNT],
        DiffState[WORD_COUNT], sumstate[WORD_COUNT],
        minusstate[WORD_COUNT], dsumstate[WORD_COUNT],
        dminusstate[WORD_COUNT];

    u8 fwd_parity, bwd_parity;

    const int rounded_total_rounds = basic_config.roundedTotalRounds();
    const int rounded_fwd_rounds = diff_config.roundedFwdRounds();
    const bool rounded_total_rounds_are_odd = (rounded_total_rounds % 2 != 0);
    const bool rounded_fwd_rounds_are_odd = (rounded_fwd_rounds % 2 != 0);
    const bool fwd_rounds_are_fractional = diff_config.fwdRoundsAreFractional();

    int fwd_post_round =
        fwd_rounds_are_fractional ? rounded_fwd_rounds + 2 : rounded_fwd_rounds + 1;
    int bwd_round =
        fwd_rounds_are_fractional ? rounded_fwd_rounds + 1 : rounded_fwd_rounds;

    size_t spt = samples_config.samples_per_thread;

    for (size_t loop{0}; loop < spt; ++loop)
    {
        bwd_parity = 0;

        while (true)
        {
            fwd_parity = 0;

            // ---------------- ChaCha setup -----------------
            chacha::init_iv_const(x0);
            if (basic_config.key_bits == 128)
                init_key.key_128bit(key);
            else
                init_key.key_256bit(key);

            chacha::insert_key(x0, key);

            ops::copyState(strdx0, x0);
            ops::copyState(dx0, x0);

            // ---------------- inject diff -----------------
            for (const auto &d : diff_config.id)
                TOGGLE_BIT(dx0[d.first], d.second);
            ops::copyState(dstrdx0, dx0);

            // ---------------- forward round -----------------
            for (int i{1}; i <= rounded_fwd_rounds; ++i)
            {
                frward.RoundFunction(x0, i);
                frward.RoundFunction(dx0, i);
            }
            if (fwd_rounds_are_fractional)
            {
                if (rounded_fwd_rounds_are_odd)
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

            // ---------------- XOR state -----------------
            ops::xorState(DiffState, x0, dx0);

            // ---------------- store forward parity -----------------
            for (const auto &d : diff_config.mask)
                fwd_parity ^= GET_BIT(DiffState[d.first], d.second);

            // ---------------- forward round -----------------
            if (fwd_rounds_are_fractional)
            {
                if (rounded_fwd_rounds_are_odd)
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
                if (rounded_total_rounds_are_odd)
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
            // ---------------- forward round end -----------------

            // ---------------- Z = X + X^R -----------------
            ops::addState(sumstate, x0, strdx0);
            ops::addState(dsumstate, dx0, dstrdx0);

            // ---------------- carry-lock gate -----------------
            if (passes_carrylock(
                    sumstate, dsumstate, strdx0, dstrdx0,
                    key_word, key_bit, basic_config.key_bits == 128))
                break;
        }
        // ---------------- flip key bit -----------------
        TOGGLE_BIT(key[key_word], key_bit);
        if (basic_config.key_bits == 128)
            TOGGLE_BIT(key[key_word + 4], key_bit);

        // ---------------- make new X and X' with altered key bits -----------------
        chacha::insert_key(strdx0, key);
        chacha::insert_key(dstrdx0, key);

        // ---------------- Z = X - X^R -----------------
        ops::minusState(minusstate, sumstate, strdx0);
        ops::minusState(dminusstate, dsumstate, dstrdx0);

        // ---------------- backward round -----------------
        if (basic_config.totalRoundsAreFractional())
        {
            if (rounded_total_rounds_are_odd)
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
        for (int i{rounded_total_rounds}; i > bwd_round; i--)
        {
            bckward.RoundFunction(minusstate, i);
            bckward.RoundFunction(dminusstate, i);
        }

        if (fwd_rounds_are_fractional)
        {
            if (rounded_fwd_rounds_are_odd)
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
        // ---------------- backward round end -----------------

        // ---------------- XOR state -----------------
        ops::xorState(DiffState, minusstate, dminusstate);

        // ---------------- store backward parity -----------------
        for (const auto &d : diff_config.mask)
            bwd_parity ^= GET_BIT(DiffState[d.first], d.second);

        // ---------------- parity check -----------------
        if (fwd_parity == bwd_parity)
            thread_match_count++;
    }

    return static_cast<double>(thread_match_count);
}
