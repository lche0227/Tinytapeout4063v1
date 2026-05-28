# # test/test.py
# import cocotb
# from cocotb.clock import Clock
# from cocotb.triggers import RisingEdge, ClockCycles

# # ============================================================================
# # Helper: pack a 128-bit integer into a list of 16 bytes (big-endian)
# # ============================================================================

# def to_bytes(val128):
#     return [(val128 >> (120 - i * 8)) & 0xFF for i in range(16)]

# # ============================================================================
# # Helper: build uio_in control byte
# # ============================================================================

# def make_uio(byte_index=0, we=0, start=0, output_sel=0):
#     return (byte_index & 0x1F) | (we << 5) | (start << 6) | (output_sel << 7)

# # ============================================================================
# # Core task: load key+plaintext, pulse start, wait for done, read ciphertext
# # ============================================================================

# async def run_vector(dut, pt_int, key_int, ct_expected_int, label=""):
#     pt_bytes       = to_bytes(pt_int)
#     key_bytes      = to_bytes(key_int)
#     ct_expected    = to_bytes(ct_expected_int)

#     dut._log.info(f"--- {label} ---")
#     dut._log.info(f"  Key:      {' '.join(f'{b:02x}' for b in key_bytes)}")
#     dut._log.info(f"  PT:       {' '.join(f'{b:02x}' for b in pt_bytes)}")
#     dut._log.info(f"  Expected: {' '.join(f'{b:02x}' for b in ct_expected)}")

#     # ------------------------------------------------------------------
#     # Load key bytes — byte_index 0-15, byte_index[4]=0
#     # ------------------------------------------------------------------
#     for idx, byte in enumerate(key_bytes):
#         dut.ui_in.value  = byte
#         dut.uio_in.value = make_uio(byte_index=idx, we=1)
#         await RisingEdge(dut.clk)

#     # ------------------------------------------------------------------
#     # Load plaintext bytes — byte_index 16-31, byte_index[4]=1
#     # ------------------------------------------------------------------
#     for idx, byte in enumerate(pt_bytes):
#         dut.ui_in.value  = byte
#         dut.uio_in.value = make_uio(byte_index=16 + idx, we=1)
#         await RisingEdge(dut.clk)

#     # ------------------------------------------------------------------
#     # Deassert WE, pulse start for exactly one cycle
#     # ------------------------------------------------------------------
#     dut.ui_in.value  = 0
#     dut.uio_in.value = make_uio(start=1)
#     await RisingEdge(dut.clk)
#     dut.uio_in.value = 0

#     # ------------------------------------------------------------------
#     # Wait for done (valid_pipe[10] — should arrive in exactly 10 cycles)
#     # Timeout after 30 cycles to catch hangs
#     # ------------------------------------------------------------------
#     done = False
#     for cycle in range(30):
#         await RisingEdge(dut.clk)
#         if int(dut.uio_out.value) & 0x01:
#             dut._log.info(f"  done asserted after {cycle + 1} cycle(s) post-start")
#             done = True
#             break

#     if not done:
#         raise AssertionError(f"[{label}] TIMEOUT: done never asserted within 30 cycles")

#     # ------------------------------------------------------------------
#     # Read back 16 ciphertext bytes using output_sel=1
#     # byte_index[3:0] selects which byte of cipher_out to read
#     # No pipeline latency here — cipher_byte_out is combinational
#     # ------------------------------------------------------------------
#     result = []
#     for idx in range(16):
#         dut.uio_in.value = make_uio(byte_index=idx, output_sel=1)
#         await RisingEdge(dut.clk)   # settle one cycle for mux
#         result.append(int(dut.uo_out.value))

#     dut.uio_in.value = 0
#     await RisingEdge(dut.clk)      # clean bus before next vector

#     # ------------------------------------------------------------------
#     # Compare
#     # ------------------------------------------------------------------
#     dut._log.info(f"  Got:      {' '.join(f'{b:02x}' for b in result)}")

#     if result == ct_expected:
#         dut._log.info(f"  PASSED ✅")
#     else:
#         mismatches = [
#             f"  byte[{i}]: got {result[i]:02x}, expected {ct_expected[i]:02x}"
#             for i in range(16) if result[i] != ct_expected[i]
#         ]
#         raise AssertionError(
#             f"[{label}] CIPHERTEXT MISMATCH\n" + "\n".join(mismatches)
#         )


# # ============================================================================
# # Test vectors
# # ============================================================================

# VECTORS = [
#     # (plaintext, key, expected_ciphertext, label)

#     # Test 1 — FIPS 197 Appendix B
#     (
#         0x3243F6A8885A308D313198A2E0370734,
#         0x2B7E151628AED2A6ABF7158809CF4F3C,
#         0x3925841D02DC09FBDC118597196A0B32,
#         "FIPS 197 Appendix B",
#     ),

#     # Test 2 — "That's my Kung Fu"
#     (
#         0x54776F204F6E65204E696E652054776F,
#         0x5468617473206D79204B756E67204675,
#         0x29C3505F571420F6402299B31A02D73A,
#         "That's my Kung Fu",
#     ),

#     # Test 3 — NIST SP800-38A vector (same as 9a below, kept for numbering)
#     (
#         0x6BC1BEE22E409F96E93D7E117393172A,
#         0x2B7E151628AED2A6ABF7158809CF4F3C,
#         0x3AD77BB40D7A3660A89ECAF32466EF97,
#         "NIST SP800-38A Block 1 (ECB-AES128.Encrypt PT#1)",
#     ),

#     # Test 4 — All zeros
#     (
#         0x00000000000000000000000000000000,
#         0x00000000000000000000000000000000,
#         0x66E94BD4EF8A2C3B884CFA59CA342B2E,
#         "All-zero key and plaintext",
#     ),

#     # Test 5 — NIST AES standard vector
#     (
#         0x00112233445566778899AABBCCDDEEFF,
#         0x000102030405060708090A0B0C0D0E0F,
#         0x69C4E0D86A7B0430D8CDB78070B4C55A,
#         "NIST AES standard (FIPS 197 Appendix C.1)",
#     ),

#     # Tests 9a–9d — NIST SP800-38A ECB-AES128.Encrypt
#     # https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
#     (
#         0x6BC1BEE22E409F96E93D7E117393172A,
#         0x2B7E151628AED2A6ABF7158809CF4F3C,
#         0x3AD77BB40D7A3660A89ECAF32466EF97,
#         "SP800-38A ECB PT#1 (9a)",
#     ),
#     (
#         0xAE2D8A571E03AC9C9EB76FAC45AF8E51,
#         0x2B7E151628AED2A6ABF7158809CF4F3C,
#         0xF5D3D58503B9699DE785895A96FDBAAF,
#         "SP800-38A ECB PT#2 (9b)",
#     ),
#     (
#         0x30C81C46A35CE411E5FBC1191A0A52EF,
#         0x2B7E151628AED2A6ABF7158809CF4F3C,
#         0x43B1CD7F598ECE23881B00E3ED030688,
#         "SP800-38A ECB PT#3 (9c)",
#     ),
#     (
#         0xF69F2445DF4F9B17AD2B417BE66C3710,
#         0x2B7E151628AED2A6ABF7158809CF4F3C,
#         0x7B0C785E27E8AD3F8223207104725DD4,
#         "SP800-38A ECB PT#4 (9d)",
#     ),
# ]


# # ============================================================================
# # Top-level cocotb test
# # ============================================================================

# @cocotb.test()
# async def test_aes128_all_vectors(dut):
#     """Run all AES-128 known-answer test vectors."""

#     # Start clock — 50 MHz (20 ns period)
#     cocotb.start_soon(Clock(dut.clk, 20, units="ns").start())

#     # Reset for 5 cycles
#     dut.rst_n.value  = 0
#     dut.ui_in.value  = 0
#     dut.uio_in.value = 0
#     await ClockCycles(dut.clk, 5)
#     dut.rst_n.value  = 1
#     await RisingEdge(dut.clk)

#     dut._log.info("=" * 60)
#     dut._log.info("AES-128 Optimized KAT — all vectors")
#     dut._log.info("=" * 60)

#     passed = 0
#     failed = 0

#     for pt, key, ct, label in VECTORS:
#         try:
#             await run_vector(dut, pt, key, ct, label=label)
#             passed += 1
#         except AssertionError as e:
#             dut._log.error(str(e))
#             failed += 1

#     dut._log.info("=" * 60)
#     dut._log.info(f"Results: {passed} passed, {failed} failed out of {len(VECTORS)} vectors")
#     dut._log.info("=" * 60)

#     if failed:
#         raise AssertionError(f"{failed} test vector(s) FAILED — see log above")



##VERSION 10
# # SPDX-FileCopyrightText: © 2024 Tiny Tapeout
# # SPDX-License-Identifier: Apache-2.0

# import cocotb
# from cocotb.clock import Clock
# from cocotb.triggers import ClockCycles


# @cocotb.test()
# async def test_project(dut):
#     dut._log.info("Start")

#     # Set the clock period to 10 us (100 KHz)
#     clock = Clock(dut.clk, 10, unit="us")
#     cocotb.start_soon(clock.start())

#     # Reset
#     dut._log.info("Reset")
#     dut.ena.value = 1
#     dut.ui_in.value = 0
#     dut.uio_in.value = 0
#     dut.rst_n.value = 0
#     await ClockCycles(dut.clk, 10)
#     dut.rst_n.value = 1

#     dut._log.info("Test project behavior")

#     # Set the input values you want to test
#     dut.ui_in.value = 20
#     dut.uio_in.value = 30

#     # Wait for one clock cycle to see the output values
#     await ClockCycles(dut.clk, 1)

#     # The following assersion is just an example of how to check the output values.
#     # Change it to match the actual expected output of your module:
#     assert dut.uo_out.value == 50

#     # Keep testing the module by changing the input values, waiting for
#     # one or more clock cycles, and asserting the expected output values.


# Cycle  Action
# ─────  ──────────────────────────────────────────────────
# 0      rst_n deasserted
# 1-16   Load key bytes 0-15 (we=1, byte_index=0..15)
# 17     Deassert we → load_key_r fires inside wrapper
# 18     key_gen samples key_in, computes all round keys,
#        asserts keys_ready (uio_out[1]) for one cycle
# 19     Testbench sees keys_ready, loads plaintext bytes
# 19-34  Load plaintext bytes 0-15
# 35     Pulse start=1
# 36-45  Processes 10 rounds
# 46     done asserted (uio_out[0])
# 46-61  Read ciphertext bytes 0-15


# test/test.py
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles

def to_bytes(val128):
    return [(val128 >> (120 - i * 8)) & 0xFF for i in range(16)]

def make_uio(byte_index=0, we=0, start=0, output_sel=0):
    return (byte_index & 0x1F) | (we << 5) | (start << 6) | (output_sel << 7)

async def run_vector(dut, pt_int, key_int, ct_expected_int, label=""):
    pt_bytes    = to_bytes(pt_int)
    key_bytes   = to_bytes(key_int)
    ct_expected = to_bytes(ct_expected_int)

    dut._log.info(f"--- {label} ---")
    dut._log.info(f"  Key:      {' '.join(f'{b:02x}' for b in key_bytes)}")
    dut._log.info(f"  PT:       {' '.join(f'{b:02x}' for b in pt_bytes)}")
    dut._log.info(f"  Expected: {' '.join(f'{b:02x}' for b in ct_expected)}")

    # ------------------------------------------------------------------
    # Load key bytes 0-15
    # After byte 15 is clocked in, the wrapper auto-pulses load_key_r
    # on the NEXT cycle, so key_gen samples stable key_in
    # ------------------------------------------------------------------
    for idx, byte in enumerate(key_bytes):
        dut.ui_in.value  = byte
        dut.uio_in.value = make_uio(byte_index=idx, we=1)
        await RisingEdge(dut.clk)

    # Deassert we — load_key_r fires this cycle inside the wrapper
    dut.uio_in.value = 0
    dut.ui_in.value  = 0

    # ------------------------------------------------------------------
    # Wait for keys_ready (uio_out[1]) — key_gen completes in 1 cycle
    # Timeout after 10 cycles
    # ------------------------------------------------------------------
    keys_ok = False
    for cycle in range(10):
        await RisingEdge(dut.clk)
        # Handle X/Z safely
        uio_val = dut.uio_out.value
        try:
            if (int(uio_val) >> 1) & 1:
                dut._log.info(f"  keys_ready after {cycle + 1} cycle(s)")
                keys_ok = True
                break
        except ValueError:
            pass  # X/Z on uio_out — keep waiting

    if not keys_ok:
        raise AssertionError(f"[{label}] TIMEOUT: keys_ready never asserted")

    # ------------------------------------------------------------------
    # Load plaintext bytes 16-31
    # ------------------------------------------------------------------
    for idx, byte in enumerate(pt_bytes):
        dut.ui_in.value  = byte
        dut.uio_in.value = make_uio(byte_index=16 + idx, we=1)
        await RisingEdge(dut.clk)

    # ------------------------------------------------------------------
    # Pulse start for one cycle
    # ------------------------------------------------------------------
    dut.ui_in.value  = 0
    dut.uio_in.value = make_uio(start=1)
    await RisingEdge(dut.clk)
    dut.uio_in.value = 0

    # ------------------------------------------------------------------
    # Wait for done (uio_out[0]), timeout 30 cycles
    # ------------------------------------------------------------------
    done = False
    for cycle in range(30):
        await RisingEdge(dut.clk)
        try:
            if int(dut.uio_out.value) & 0x01:
                dut._log.info(f"  done after {cycle + 1} cycle(s) post-start")
                done = True
                break
        except ValueError:
            pass  # X/Z — keep waiting

    if not done:
        raise AssertionError(f"[{label}] TIMEOUT: done never asserted")

    # ------------------------------------------------------------------
    # Read 16 ciphertext bytes
    # ------------------------------------------------------------------
    result = []
    for idx in range(16):
        dut.uio_in.value = make_uio(byte_index=idx, output_sel=1)
        await RisingEdge(dut.clk)
        try:
            result.append(int(dut.uo_out.value))
        except ValueError:
            raise AssertionError(
                f"[{label}] X/Z on uo_out reading byte {idx} — "
                f"cipher_out not stable (key expansion may be wrong)"
            )

    dut.uio_in.value = 0
    await RisingEdge(dut.clk)

    # ------------------------------------------------------------------
    # Compare
    # ------------------------------------------------------------------
    dut._log.info(f"  Got:      {' '.join(f'{b:02x}' for b in result)}")

    if result == ct_expected:
        dut._log.info("  PASSED ✅")
    else:
        mismatches = [
            f"    byte[{i}]: got {result[i]:02x}, expected {ct_expected[i]:02x}"
            for i in range(16) if result[i] != ct_expected[i]
        ]
        raise AssertionError(
            f"[{label}] CIPHERTEXT MISMATCH\n" + "\n".join(mismatches)
        )


# ============================================================================
# Test vectors
# ============================================================================

VECTORS = [
    (
        0x3243F6A8885A308D313198A2E0370734,
        0x2B7E151628AED2A6ABF7158809CF4F3C,
        0x3925841D02DC09FBDC118597196A0B32,
        "FIPS 197 Appendix B",
    ),
    (
        0x54776F204F6E65204E696E652054776F,
        0x5468617473206D79204B756E67204675,
        0x29C3505F571420F6402299B31A02D73A,
        "That's my Kung Fu",
    ),
    (
        0x6BC1BEE22E409F96E93D7E117393172A,
        0x2B7E151628AED2A6ABF7158809CF4F3C,
        0x3AD77BB40D7A3660A89ECAF32466EF97,
        "SP800-38A ECB PT#1 (9a)",
    ),
    (
        0x00000000000000000000000000000000,
        0x00000000000000000000000000000000,
        0x66E94BD4EF8A2C3B884CFA59CA342B2E,
        "All-zero key and plaintext",
    ),
    (
        0x00112233445566778899AABBCCDDEEFF,
        0x000102030405060708090A0B0C0D0E0F,
        0x69C4E0D86A7B0430D8CDB78070B4C55A,
        "FIPS 197 Appendix C.1",
    ),
    (
        0xAE2D8A571E03AC9C9EB76FAC45AF8E51,
        0x2B7E151628AED2A6ABF7158809CF4F3C,
        0xF5D3D58503B9699DE785895A96FDBAAF,
        "SP800-38A ECB PT#2 (9b)",
    ),
    (
        0x30C81C46A35CE411E5FBC1191A0A52EF,
        0x2B7E151628AED2A6ABF7158809CF4F3C,
        0x43B1CD7F598ECE23881B00E3ED030688,
        "SP800-38A ECB PT#3 (9c)",
    ),
    (
        0xF69F2445DF4F9B17AD2B417BE66C3710,
        0x2B7E151628AED2A6ABF7158809CF4F3C,
        0x7B0C785E27E8AD3F8223207104725DD4,
        "SP800-38A ECB PT#4 (9d)",
    ),
]


# ============================================================================
# Top-level test
# ============================================================================

@cocotb.test()
async def test_aes128_all_vectors(dut):
    """AES-128 optimized KAT — all vectors, clocked key_gen."""

    cocotb.start_soon(Clock(dut.clk, 20, units="ns").start())

    dut.rst_n.value  = 0
    dut.ui_in.value  = 0
    dut.uio_in.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value  = 1
    await RisingEdge(dut.clk)

    dut._log.info("=" * 60)
    dut._log.info("AES-128 Optimized KAT — clocked key_gen")
    dut._log.info("=" * 60)

    passed = 0
    failed = 0

    for pt, key, ct, label in VECTORS:
        try:
            await run_vector(dut, pt, key, ct, label=label)
            passed += 1
        except AssertionError as e:
            dut._log.error(str(e))
            failed += 1

    dut._log.info("=" * 60)
    dut._log.info(f"Results: {passed} passed, {failed} failed / {len(VECTORS)} total")
    dut._log.info("=" * 60)

    if failed:
        raise AssertionError(f"{failed} vector(s) FAILED")
    