### Symbol Vanity Address Generator

Vanity address generator for Symbol and NEM, supporting mainnet and testnets.

Multiple options are supported:

```
--blockchain {symbol,nem}   blockchain to target
--network {testnet,mainnet} network to target
--patterns PATTERNS         patterns to match (comma delimited)
--max-offset MAX_OFFSET     maximum offset of match start (default: 2)
--format {pretty,csv}       output format
--suppress-console          suppress printing matches to console
--out OUT                   output file
--backend {cpu,cuda,cuda-hybrid} address search backend (default: cpu)
--gpu-device GPU_DEVICE     CUDA device index (default: 0)
--batch-size BATCH_SIZE     wallets per batch (default: cuda 16384, cuda-hybrid 1024)
--workers WORKERS           CPU scanning processes for cuda-hybrid (default: CPU count)
--stats                     print CUDA batch timings to stderr
```

### Patterns and match positions

Patterns are case-sensitive literal strings, not regular expressions or wildcards.
Use uppercase letters and the digits `2` through `7`, as used in addresses.
Characters such as `^`, `$` and `*` are treated literally.

`--max-offset` sets the largest allowed starting position of a match, counting
from zero at the beginning of the address. The limit is inclusive and applies
to the start of the pattern, not its end.

| Options | Match condition |
| --- | --- |
| `--patterns NAXE --max-offset 0` | Address starts with `NAXE` (mainnet). |
| `--patterns TAXE --network testnet --max-offset 0` | Address starts with `TAXE` (testnet). |
| `--patterns AXE` | `AXE` starts at offset 0, 1 or 2 (the default maximum is 2). |
| `--patterns AXE --max-offset 100` | `AXE` appears anywhere in the address. |

For example, `NAXE...` contains `AXE` at offset 1, while `NCAXE...` contains it
at offset 2. Both match the default options. `NCAAXE...` has `AXE` at offset 3
and requires `--max-offset 3` or greater. An offset of 100 covers the entire
address for both Symbol and NEM. There is no option to require a suffix match.

Separate patterns with commas to search for one account per pattern. The search
finishes after all patterns have a match; the patterns do not have to occur in
the same address.

Run these examples from `tools/vanity`:

```sh
# Mainnet address beginning with NAXE:
python -m vanity --patterns NAXE --max-offset 0
# Find an account for AXE and another for CAT, anywhere in their addresses:
python -m vanity --patterns AXE,CAT --max-offset 100
# Testnet address beginning with TAXE:
python -m vanity --network testnet --patterns TAXE --max-offset 0
```

These matching rules apply to both the CPU and CUDA backends.

### NVIDIA GPU support

`--backend cuda` runs BIP39 checksum and English mnemonic encoding, seed generation
(PBKDF2-HMAC-SHA512, 2048 iterations),
hardened BIP32/SLIP10 derivation, Ed25519 public key generation, address hashing,
Base32 encoding and literal pattern matching on an NVIDIA GPU. Both Symbol and
NEM and their mainnet/testnet networks are supported. The first ten wallet
accounts and their mnemonic recovery paths are preserved.

The CPU supplies cryptographic entropy in bulk using the OS random source. The
GPU converts each independent 32-byte block into its 24-word BIP39 mnemonic and
HMAC key; the CPU encodes only the mnemonics of full matches. Seeds and derived
private keys stay on the device during the search; only the best
candidate account for each active pattern is copied back. Each full match is
independently derived again from its mnemonic on the CPU before export. GPU
buffers holding entropy, passwords, seeds and private keys are cleared before reuse.
Duplicate patterns remain separate search targets.

Startup compiles the kernels and verifies GPU derivation, public keys, addresses
and pattern matching against the SDK for both blockchains and networks. CUDA
initialization or self-test failures stop the search instead of falling back to
CPU execution. Actual throughput depends on the GPU and batch size.

Install the normal dependencies and the CuPy package matching your CUDA version:

```sh
cd tools/vanity
python -m pip install -r requirements.txt
# CUDA 12.x, including the CUDA components needed by CuPy:
python -m pip install "cupy-cuda12x[ctk]"
# For CUDA 13.x, use cupy-cuda13x instead.
python -m vanity --backend cuda --gpu-device 0 --patterns AXE,CAT
```

See the [CuPy installation guide](https://docs.cupy.dev/en/stable/install.html)
for driver/toolkit requirements and installation without a system CUDA Toolkit.
CuPy is optional and is not imported by the CPU backend. Selecting CUDA requires
a working CUDA environment; initialization failures are reported before opening
the output file. Omit `--backend cuda` to use the existing CPU implementation.
`--gpu-device` and `--batch-size` apply only to CUDA. Larger batches can improve
GPU utilization but increase latency and memory use.

### Throughput and diagnostics

```sh
python -m vanity --backend cuda --batch-size 16384 --stats --patterns AXEAXE
```

For `cuda`, `--stats` reports the following after each batch on stderr:

| Field | Meaning |
| --- | --- |
| `GPU prepare` | BIP39 checksum, word encoding and HMAC key preparation time in seconds. |
| `GPU seed` | BIP39 seed kernel execution time in seconds. |
| `GPU derive` | Hardened account derivation kernel execution time in seconds. |
| `GPU scan` | Public keys, address calculation and pattern matching time in seconds. |
| `total` | Complete batch time, including OS entropy generation, transfers and candidate verification. |
| `addresses/s` | Addresses processed by the GPU divided by complete batch time. |

GPU times are measured with CUDA events. They exclude host preparation,
transfers and buffer cleanup; `total` includes these costs. Each wallet contributes
ten addresses. All accounts in a GPU batch are evaluated before collecting
results, including in the final batch. Compare batches after startup compilation
and self-tests when tuning throughput. The CUDA default is 16384 wallets;
`cuda-hybrid` retains its 1024-wallet default. Increasing the batch further can
improve utilization, but also increases latency and memory use.

SHA-512 uses sixteen-round tiles so its message schedule stays in registers
rather than local memory. A warm RTX 2070 SUPER comparison with alternating
before/after runs measured approximately 1.2–1.3 million addresses/second for
8192–32768-wallet batches, including entropy generation and transfers. This is
a reference measurement; workloads and other GPU activity affect throughput.

The earlier implementation remains available as `--backend cuda-hybrid`. It uses
the GPU for seeds and CPU processes for account scanning. For that backend,
`--workers` controls the CPU process count (default: Python's CPU count), and
`--stats` retains the `seed wait` / `CPU scan` format. Its workers use `spawn` so
they never inherit a live CUDA context, and the next seed batch is prepared while
CPU scanning runs. Use it to compare throughput or investigate device behavior:

```sh
python -m vanity --backend cuda-hybrid --workers 8 --batch-size 8192 --stats --patterns AXEAXE
```

Remove `--workers` when switching to `--backend cuda`; GPU address scanning does
not use CPU worker processes. `--stats` requires either CUDA backend.

Run the tests from `tools/vanity`:

```sh
python -m unittest discover -v
# Also exercise the actual CUDA device and compare seeds with the CPU reference:
VANITY_TEST_CUDA=1 python -m unittest tests.test_CudaSeedGenerator tests.test_CudaSearchBackend -v
```

The normal tests compile the same CUDA arithmetic as C++ when a C++ compiler is
available and compare seed generation, hardened derivation, public keys, address
hashing and pattern winners with CPU references. They also check mnemonic
recovery and rejection of incorrect GPU candidates. This does not replace running
the device tests on a GPU. Set `VANITY_GPU_DEVICE` to select a different device
for the device tests. `VANITY_CUDA_SANITIZE=1` enables C++ undefined-behavior checks.

The public Ed25519 fixed-base table is reproducible with
`python scripts/generate_ed25519_table.py`; the English word table with
`python scripts/generate_bip39_words.py`. Attribution and licenses are in
[CUDA_NOTICES.md](vanity/CUDA_NOTICES.md).
