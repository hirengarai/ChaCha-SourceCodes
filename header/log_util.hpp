/*
 * Filename: log_util.hpp
 *
 * Thread-safe tee streambuf: forwards writes to two underlying streambufs
 * at once (e.g. stdout + a log file).
 */

#pragma once

#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>

class TeeBuffer : public std::streambuf
{
    std::streambuf *sb1;
    std::streambuf *sb2;
    std::mutex mtx;

public:
    TeeBuffer(std::streambuf *s1, std::streambuf *s2) : sb1(s1), sb2(s2) {}

    int overflow(int c) override
    {
        std::lock_guard lock(mtx);
        if (c == EOF)
            return !EOF;
        sb1->sputc(c);
        sb2->sputc(c);
        return c;
    }

    std::streamsize xsputn(const char *s, std::streamsize n) override
    {
        std::lock_guard lock(mtx);
        sb1->sputn(s, n);
        sb2->sputn(s, n);
        sb2->pubsync();
        return n;
    }
};

class Logger
{
    std::ofstream logfile;
    std::optional<TeeBuffer> teebuf;
    std::streambuf *old_cout = nullptr;
    bool active = false;

public:
    void enable(const std::string &filename = "output.log")
    {
        if (active)
            return; // guard against double-enable
        setvbuf(stdout, nullptr, _IOLBF, 0);
        // logfile.open(filename, std::ios::app);
        logfile.open(filename);
        teebuf.emplace(std::cout.rdbuf(), logfile.rdbuf());
        old_cout = std::cout.rdbuf(&teebuf.value());
        active = true;
    }

    void disable()
    {
        if (!active)
            return;
        std::cout.rdbuf(old_cout);
        teebuf.reset();
        logfile.close();
        active = false;
    }

    ~Logger() { disable(); }
};

inline Logger gLogger;
