The field carry, multiplication, selection and encoding routines in `ed25519.cu`
are adapted from the public-domain TweetNaCl implementation by Daniel J.
Bernstein, Bernard van Gastel, Wesley Janssen, Tanja Lange, Peter Schwabe and
Sjaak Smetsers. TweetNaCl is dedicated to the public domain:
https://tweetnacl.cr.yp.to/ and https://tweetnacl.cr.yp.to/tweetnacl-20140917.pdf

The fixed-base table contains public Ed25519 curve points and is reproducible
with `scripts/generate_ed25519_table.py`. The CUDA implementation uses signed
radix-16 fixed-base multiplication and an addition chain for field inversion.

`bip39_words.cuh` reproduces the English BIP39 word list distributed with
python-mnemonic. Its license follows:

The MIT License (MIT)

Copyright (c) 2013-2016 Pavol Rusnak

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
