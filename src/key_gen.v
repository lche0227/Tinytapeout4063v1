// =============================================================================
// key_gen.v  –  AES-128 Key Expansion (KeySchedule)
// =============================================================================
// Generates all 11 round keys (RoundKey[0..10]) from the 128-bit cipher key
// using the AES key schedule defined in FIPS-197 Section 5.2.
//
// The expansion is done combinationally so all round keys are available
// within the same clock cycle after reset / key load.  This is the standard
// approach for an iterative AES core where the datapath steps through rounds
// sequentially while the key schedule is pre-computed.
//
// Key schedule summary for AES-128 (Nk = 4, Nr = 10):
//   W[i] = W[i-Nk] XOR SubWord(RotWord(W[i-1])) XOR Rcon[i/Nk]   (i mod Nk == 0)
//   W[i] = W[i-Nk] XOR W[i-1]                                     (otherwise)
//
// Rcon values (round constant, applied to the most-significant byte only):
//   Rcon[1..10] = {01,02,04,08,10,20,40,80,1b,36}
//
// Ports
//   key_in        [127:0]    – original 128-bit cipher key
//   round_key_out [1407:0]   – all 11 round keys concatenated
//                              bits[1407:1280] = RoundKey[0]  (= key_in)
//                              bits[1279:1152] = RoundKey[1]
//                              ...
//                              bits[127:0]     = RoundKey[10]

// =============================================================================
// key_gen.v  –  AES-128 Key Expansion (KeySchedule) (combinational)

//   - Packed W_flat vector (no unpacked wire arrays) → no UNOPTFLAT on W
//   - rot_w/sub_w UNOPTFLAT suppressed with lint pragmas (false positive:

//     the logic is provably acyclic – each sub_w[s] depends only on
//     W_flat bits that are driven by earlier words with lower indices)
//   - All generate if/else blocks have explicit labels → no GENUNNAMED
// =============================================================================

`default_nettype none

module key_gen (
    input  wire [127:0]  key_in,
    output wire [1407:0] round_key_out   // 11 × 128 bits
);

    localparam integer WORDS = 44;

    // -------------------------------------------------------------------------
    // W_flat: W[0..43] packed. Word i at bits [i*32 +: 32].
    // Packed avoids the UNOPTFLAT Verilator raises on unpacked wire arrays
    // when driven inside generate loops.
    // -------------------------------------------------------------------------
    wire [WORDS*32-1:0] W_flat;

    // -------------------------------------------------------------------------
    // Rcon table (1-based; only MSB is non-zero)
    // -------------------------------------------------------------------------
    function automatic [31:0] rcon;
        input integer rnd;
        begin
            case (rnd)
                1:  rcon = 32'h01000000;
                2:  rcon = 32'h02000000;
                3:  rcon = 32'h04000000;
                4:  rcon = 32'h08000000;
                5:  rcon = 32'h10000000;
                6:  rcon = 32'h20000000;
                7:  rcon = 32'h40000000;
                8:  rcon = 32'h80000000;
                9:  rcon = 32'h1b000000;
                10: rcon = 32'h36000000;
                default: rcon = 32'h00000000;
            endcase
        end
    endfunction

    // RotWord: left-rotate by 8 bits
    function automatic [31:0] rot_word;
        input [31:0] w;
        begin
            rot_word = {w[23:0], w[31:24]};
        end
    endfunction

    // -------------------------------------------------------------------------
    // Seed W[0..3] from cipher key
    // -------------------------------------------------------------------------
    assign W_flat[0*32 +: 32] = key_in[127:96];
    assign W_flat[1*32 +: 32] = key_in[95:64];
    assign W_flat[2*32 +: 32] = key_in[63:32];
    assign W_flat[3*32 +: 32] = key_in[31:0];

    // -------------------------------------------------------------------------
    // SubWord(RotWord(W[4s+3])) for s = 0..9
    //

    // paths through sbox combinational logic back into W_flat and mistakes it
    // for a cycle.  The circuit is genuinely acyclic: sub_w[s] depends on
    // W_flat[(4s+3)*32 +: 32] which is always a lower-index word than the
    // W_flat word that consumes sub_w[s] (W[4s+4]).  The lint_off/on pair
    // suppresses only this false-positive; synthesis is unaffected.
    // -------------------------------------------------------------------------

    wire [31:0] rot_w [0:9];
    wire [31:0] sub_w [0:9];

    genvar s;
    generate
        for (s = 0; s < 10; s = s + 1) begin : SUBWORD_INST
            assign rot_w[s] = rot_word(W_flat[(4*s+3)*32 +: 32]);

            sbox u_sb0 (.in_byte(rot_w[s][31:24]), .out_byte(sub_w[s][31:24]));
            sbox u_sb1 (.in_byte(rot_w[s][23:16]), .out_byte(sub_w[s][23:16]));
            sbox u_sb2 (.in_byte(rot_w[s][15:8]),  .out_byte(sub_w[s][15:8]));
            sbox u_sb3 (.in_byte(rot_w[s][7:0]),   .out_byte(sub_w[s][7:0]));
        end
    endgenerate

    // -------------------------------------------------------------------------
    // Key schedule: W[4..43]
    // W[i] = W[i-4] ^ SubWord(RotWord(W[i-1])) ^ Rcon[i/4]  if i % 4 == 0
    // W[i] = W[i-4] ^ W[i-1]                                 otherwise
    // -------------------------------------------------------------------------
    genvar i;
    generate
        for (i = 4; i < WORDS; i = i + 1) begin : KEY_SCHED
            if ((i % 4) == 0) begin : gen_round_word
                assign W_flat[i*32 +: 32] =
                    W_flat[(i-4)*32 +: 32] ^ sub_w[(i/4) - 1] ^ rcon(i/4);
            end else begin : gen_nonround_word
                assign W_flat[i*32 +: 32] =
                    W_flat[(i-4)*32 +: 32] ^ W_flat[(i-1)*32 +: 32];
            end
        end
    endgenerate

    // -------------------------------------------------------------------------
    // Pack round keys: RoundKey[k] = {W[4k..4k+3]}
    // RoundKey[0] at MSBs [1407:1280], RoundKey[10] at LSBs [127:0]
    // -------------------------------------------------------------------------
    genvar k;
    generate
        for (k = 0; k <= 10; k = k + 1) begin : PACK_KEYS
            assign round_key_out[(10-k)*128 +: 128] = {
                W_flat[(4*k+0)*32 +: 32],
                W_flat[(4*k+1)*32 +: 32],
                W_flat[(4*k+2)*32 +: 32],
                W_flat[(4*k+3)*32 +: 32]
            };
        end
    endgenerate

endmodule