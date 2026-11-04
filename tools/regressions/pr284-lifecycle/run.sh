#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 generate.py
g++ -std=c++20 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer generated.cpp -o regression
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 ./regression | tee results.log
