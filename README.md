# Source Codes of ChaCha

This repository contains the source codes accompanying our **upcoming research paper** on **backward bias detection in ChaCha** using the **carry-lock method**.

---

## Overview

We provide the full implementation and analysis framework for evaluating backward statistical biases in:

- **ChaCha-7.5 / 256-bit key**
- **ChaCha-7 / 128-bit key**

Our proposed **carry-lock method** introduces a refined model for identifying and quantifying backward biases in ARX ciphers by exploiting carry dependencies between key and state bits.

This repository also includes comparative implementations of:
- The **classical approach** of *Aumasson et al.*
- The **Wang et al.** method
- The **pattern-based technique** proposed by *Dey, Garai, Sarkar, and Sharma*

---

## Repository Structure

- `src/` — Source codes for bias measurement and differential analysis  
- `scripts/` — Python utilities for automation, data analysis, and plotting  
- `results/` — Example output logs and computed bias values  

---

## How to Use

1. Compile the C++ sources with:
   ```bash
   g++ -std=c++2c -O3 -flto main.cpp -o run
   ./run
