<!---

This file is used to generate your project datasheet. Please fill in the information below and delete any unused
sections.

You can also include images in this folder and reference them in the markdown. Each image must be less than
512 kb in size, and the combined size of all images must be less than 1 MB.
-->

## How it works

This project implements a **fully pipelined AES-128 encryption core** on silicon.

The design is structured as 10 fully unrolled AES rounds instantiated in hardware simultaneously,
connected in a chain through pipeline registers. Each round performs the standard AES operations:
SubBytes (non-linear S-box byte substitution), ShiftRows (cyclic row rotation),
MixColumns (GF(2⁸) column mixing — omitted in the final round), and AddRoundKey
(XOR with the round-derived key).

Key expansion is handled by a dedicated combinational `key_gen` module that derives
all 11 round keys (the original key plus 10 round keys) from the 128-bit input key
in a single clock cycle using the AES key schedule. All 11 round keys are available
as wires throughout the pipeline — no key scheduling latency.

A valid-bit shift register (`valid_pipe`) shadows the data pipeline. When `start` is
pulsed high for one cycle, a '1' propagates through all 10 stages in lock-step with
the data, and the `done` output goes high exactly 10 clock cycles later to signal
that a valid ciphertext is present at the output.

**Throughput:** After the 10-cycle initial fill, the pipeline produces one new
128-bit ciphertext every clock cycle, provided a new plaintext and key are presented
each cycle.

**Area:** The design uses approximately 10× the logic of an iterative single-round
core, as all 10 rounds are instantiated simultaneously in dedicated hardware.

Because Tiny Tapeout provides only 8 input and 8 output pins per project, a
byte-serial interface wraps the wide 128-bit internal buses. The 128-bit key
and plaintext are loaded one byte at a time, and the 128-bit ciphertext is
read back one byte at a time after encryption completes.

## How to test

### Pin mapping

| Signal       | Direction | Description                                              |
|--------------|-----------|----------------------------------------------------------|
| `ui_in[7:0]` | Input     | Data byte to write into key or plaintext register        |
| `uio_in[4:0]`| Input     | Byte index: 0–15 = key byte slot, 16–31 = plaintext slot |
| `uio_in[5]`  | Input     | Write enable — load `ui_in` into the selected slot       |
| `uio_in[6]`  | Input     | Start — pulse high for one cycle to begin encryption     |
| `uio_in[7]`  | Input     | Output select — set high to read ciphertext on `uo_out`  |
| `uo_out[7:0]`| Output    | Ciphertext byte selected by `uio_in[3:0]`                |
| `uio_out[0]` | Output    | Done — goes high 10 cycles after the start pulse         |

### Step-by-step operation

**1. Reset**
Hold `rst_n` low for at least 2 clock cycles to clear all pipeline registers and
input byte stores, then release it high.

**2. Load the 128-bit key (16 bytes)**
For each byte index `i` from 0 to 15:
- Set `ui_in` to `key[i]` (byte 0 = most significant byte)
- Set `uio_in = (i & 0x1F) | 0x20` (byte_index = i, we = 1)
- Hold for one rising clock edge

**3. Load the 128-bit plaintext (16 bytes)**
For each byte index `i` from 0 to 15:
- Set `ui_in` to `plaintext[i]`
- Set `uio_in = ((16 + i) & 0x1F) | 0x20` (byte_index = 16+i, we = 1)
- Hold for one rising clock edge

**4. Start encryption**
On the next cycle after the last plaintext byte:
- Set `ui_in = 0`, `uio_in = 0x40` (start = 1, we = 0)
- Hold for exactly one rising clock edge, then set `uio_in = 0`

**5. Wait for done**
Monitor `uio_out[0]`. It will go high exactly **10 clock cycles** after the
start pulse. Keep `uio_in = 0` while waiting.

**6. Read the ciphertext (16 bytes)**
For each byte index `i` from 0 to 15:
- Set `uio_in = (i & 0x0F) | 0x80` (byte_index = i, output_sel = 1)
- Wait one clock edge
- Sample `uo_out` — this is ciphertext byte `i`

After reading all 16 bytes, set `uio_in = 0`.

### Verification

Use the following NIST known-answer test vectors to verify correct operation:

| # | Key (hex) | Plaintext (hex) | Expected ciphertext (hex) |
|---|-----------|-----------------|---------------------------|
| 1 | `2b7e151628aed2a6abf7158809cf4f3c` | `3243f6a8885a308d313198a2e0370734` | `3925841d02dc09fbdc118597196a0b32` |
| 2 | `2b7e151628aed2a6abf7158809cf4f3c` | `6bc1bee22e409f96e93d7e117393172a` | `3ad77bb40d7a3660a89ecaf32466ef97` |
| 3 | `2b7e151628aed2a6abf7158809cf4f3c` | `ae2d8a571e03ac9c9eb76fac45af8e51` | `f5d3d58503b9699de785895a96fdbaaf` |
| 4 | `0000000000000000000000000000000000` | `00000000000000000000000000000000` | `66e94bd4ef8a2c3b884cfa59ca342b2e` |
| 5 | `000102030405060708090a0b0c0d0e0f` | `00112233445566778899aabbccddeeff` | `69c4e0d86a7b0430d8cdb78070b4c55a` |

### Continuous streaming mode

Once the pipeline is filled, a new plaintext+key pair can be presented every clock
cycle without reloading. Simply keep writing new bytes each cycle while reading
ciphertext from previous inputs — the pipeline runs continuously at one
encryption per clock.

## External hardware

List external hardware used in your project (e.g. PMOD, LED display, etc), if any
