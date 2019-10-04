# Breaking-Imphash
32-bit Implementation for Breaking Imphash as described in paper: https://arxiv.org/abs/1909.07630

# Authors
- breaking-imphash.py: Chris Balles (chrisbvt)
- breaking-imphash.cpp: Ateeq Sharfuddin 

# Usage
Precompiled executables (including great.exe referred in the paper) reside in
bin\Win32\Release

# Abstract
There are numerous schemes to generically signature artifacts. We specifically
consider how to circumvent signatures based on imphash. Imphash is used to
signature Portable Executable (PE) files and an imphash of a PE file is an MD5
digest over all the symbols that PE file imports. Imphash has been used in
numerous cases to accurately tie a PE file seen in one environment to PE files
in other environments, although each of these PE files' contents was different.
An argument made for imphash is that alteration of imphashes of derived PE
file artifacts is unlikely since it is an expensive process, such that you
will need to either modify the source code and recompile or relink in a
different order. Nevertheless, we present a novel algorithm that generates
derivative PE files such that its imphash is different from the original PE
file. This straightforward algorithm produces feasible solutions that defeat
approaches relying on the imphash algorithm to signature PE files.

# Copyright
MIT License

Copyright (c) 2019, Chris Balles, Ateeq Sharfuddin, SCYTHE, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
