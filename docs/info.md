<!---

This file is used to generate your project datasheet. Please fill in the information below and delete any unused
sections.

You can also include images in this folder and reference them in the markdown. Each image must be less than
512 kb in size, and the combined size of all images must be less than 1 MB.
-->

## How it works

This project implements an **iterative AES-128 encryption core** on silicon.

The design is structured as a single shared AES round datapath reused across all
10 rounds, controlled by a finite state machine (FSM). Each round performs the
standard AES operations: SubBytes (non-linear S-box byte substitution), ShiftRows
(cyclic row rotation), MixColumns (GF(2⁸) column mixing — omitted in the final
round), and AddRoundKey (XOR with the round-derived key). A `final_round` flag
suppresses MixColumns automatically in round 10.

Key expansion is handled by a dedicated `aes_key_schedule_step` submodule that
derives the next round key on-the-fly each clock cycle from the current key
register, using four S-box instances (RotWord → SubWord → XOR Rcon). No
pre-computation or wide key bus is required — the round key is available exactly
when each round needs it.

On the cycle that `start` is pulsed high, the initial AddRoundKey is performed
immediately by initialising the state register to `plaintext XOR key`, eliminating
a dedicated setup state. The FSM then steps through all 10 rounds, one per clock
cycle, and pulses `done` high when the ciphertext is ready.

**Latency:** 10 clock cycles from `start` to `done`.

**Area:** A single instantiation of the round datapath and on-the-fly key schedule
minimises gate count, avoiding the large combinational key expansion block used in
fully pre-computed designs.

Because Tiny Tapeout provides only 8 input and 8 output pins per project, a
byte-serial interface wraps the wide 128-bit internal buses. The 128-bit key and
plaintext are each loaded one byte at a time, and the 128-bit ciphertext is read
back one byte at a time after encryption completes.


## How to test

### Pin mapping

| Signal        | Direction | Description                                               |
|---------------|-----------|-----------------------------------------------------------|
| `ui_in[7:0]`  | Input     | Data byte to write into key or plaintext register         |
| `uio_in[4:0]` | Input     | Byte index: 0–15 = key byte slot, 16–31 = plaintext slot  |
| `uio_in[5]`   | Input     | Write enable — load `ui_in` into the selected slot        |
| `uio_in[6]`   | Input     | Start — pulse high for one cycle to begin encryption      |
| `uio_in[7]`   | Input     | Output select — set high to read ciphertext on `uo_out`   |
| `uo_out[7:0]` | Output    | Ciphertext byte selected by `uio_in[3:0]`                 |
| `uio_out[0]`  | Output    | Done — goes high 10 cycles after the start pulse          |

### Step-by-step operation

**1. Reset**

Hold `rst_n` low for at least 2 clock cycles to clear all internal registers and
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

Monitor `uio_out[0]`. It will go high exactly **10 clock cycles** after the start
pulse. Keep `uio_in = 0` while waiting.

**6. Read the ciphertext (16 bytes)**

For each byte index `i` from 0 to 15:
- Set `uio_in = (i & 0x0F) | 0x80` (byte_index = i, output_sel = 1)
- Wait one clock edge
- Sample `uo_out` — this is ciphertext byte `i`

After reading all 16 bytes, set `uio_in = 0`.

### Verification

Use the following NIST known-answer test vectors to verify correct operation:

| # | Key (hex)                          | Plaintext (hex)                    | Expected ciphertext (hex)          |
|---|------------------------------------|------------------------------------|------------------------------------|
| 1 | `2b7e151628aed2a6abf7158809cf4f3c` | `3243f6a8885a308d313198a2e0370734` | `3925841d02dc09fbdc118597196a0b32` |
| 2 | `2b7e151628aed2a6abf7158809cf4f3c` | `6bc1bee22e409f96e93d7e117393172a` | `3ad77bb40d7a3660a89ecaf32466ef97` |
| 3 | `2b7e151628aed2a6abf7158809cf4f3c` | `ae2d8a571e03ac9c9eb76fac45af8e51` | `f5d3d58503b9699de785895a96fdbaaf` |
| 4 | `00000000000000000000000000000000` | `00000000000000000000000000000000` | `66e94bd4ef8a2c3b884cfa59ca342b2e` |
| 5 | `000102030405060708090a0b0c0d0e0f` | `00112233445566778899aabbccddeeff` | `69c4e0d86a7b0430d8cdb78070b4c55a` |

### Note on throughput

This iterative core processes one plaintext block at a time. A new encryption can
only begin after `done` is asserted. Back-to-back encryptions are supported by
reloading key and plaintext bytes immediately after reading the previous ciphertext.

## External hardware

None.