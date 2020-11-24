# stack overflow: hands-on challenge source code

## Files

- challenges
    - chal1.c: hands-on (1) buffer overflow basic
    - chal2.c: hands-on (2) integer / string representation
    - chal3.c: hands-on (3) buffer overflow to integer variable
    - chal4.c: hands-on (4) buffer overflow to function pointer
    - chal5.c: hands-on (5) buffer overflow to return address
- utilities
    - CMakeLists.txt: build config for CMake
    - Makefile: build config for GNU Make
    - chal4.lds: linker script (so that `win` address is represented in ASCII)
    - chal5.lds: linker script (so that `win` address is represented in ASCII)
    - stkdbg.h: header file for stkdbg.c
    - stkdbg.c: utilities for dumping stack (as a hint)

## Make / CMake targets

- individual targets
    - chalN-{32,64}: with hint (stack dump) - using libstkdbg{32,64}.so
    - chalN-{32,64}s: with hint (stack dump) - stkdbg statically linked
    - chalN-{32,64}n: without hint (stack dump)
- aggregate targets
    - 32 | 64: build all chalN-32 | chalN-64
    - 32s | 64s: build all chalN-32s | chalN-64s
    - 32n | 64n: build all chalN-32n | chanN-64n

## License (MIT)

Copyright 2020 Phish'n'Chips Team

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
