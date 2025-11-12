# Source Codes of ChaCha

This repository contains the source codes accompanying the article **Improved Key-Recovery Attack on ChaCha Using
Carry-Lock Method** on **backward bias detection in ChaCha** using the **carry-lock method**.

---

## Overview

We provide framework for evaluating backward statistical biases in:

- **ChaCha-7.5 / 256-bit key**
- **ChaCha-7 / 128-bit key**

Our proposed **carry-lock method** introduces a refined model for identifying and quantifying backward biases in ChaCha by exploiting carry dependencies between key and state bits.

This source code also includes comparative implementations of:
- The **classical approach** of *Aumasson et al.* [https://www.aumasson.jp/data/papers/AFKMR08.pdf]
- The **Wang et al.** method [https://eprint.iacr.org/2023/1087]
- The **pattern-based technique** proposed by *Dey, Garai, Sarkar, and Sharma* [https://ieeexplore.ieee.org/abstract/document/10107619]

---

## Repository Structure


- `biascheck.cpp` — Source codes for bias measurement. 
Change the flag inside for different approaches. Change the key size for different versions.   

---

## How to Use

1. Compile the C++ sources with:
   ```bash
   g++ -std=c++20 -O3 filename && ./a.out
