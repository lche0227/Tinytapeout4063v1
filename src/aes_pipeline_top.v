// =============================================================================
// aes_pipeline_top.v
// 3-stage pipelined AES-128 encryption core
//
// Architecture:
//   - 10 AES rounds folded into 3 pipeline stages
//   - Stage A: Initial AddRoundKey + Rounds 1-3   (4 round-key ops)
//   - Stage B: Rounds 4-7                          (4 round-key ops)
//   - Stage C: Rounds 8-9 + Final Round 10         (3 round-key ops)
//
//   - Total latency : 3 cycles after pipeline fill
//   - Throughput    : 1 ciphertext per clock (once filled)
//   - Area          : ~3x vs iterative, vs ~10x for fully unrolled
//
// Interface unchanged from 10-stage version.
// =============================================================================

`default_nettype none

module aes_pipeline_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,

    input  wire [127:0] key_in,
    input  wire [127:0] plain_in,

    output wire         done,
    output wire [127:0] cipher_out
);

    // =========================================================================
    // Key Expansion  (combinational, all 11 round keys at once)
    // =========================================================================

    wire [1407:0] all_round_keys;
    wire [127:0]  round_key [0:10];

    key_gen u_key_gen (
        .key_in        (key_in),
        .round_key_out (all_round_keys)
    );

    genvar rk;
    generate
        for (rk = 0; rk <= 10; rk = rk + 1) begin : RK_UNPACK
            assign round_key[rk] = all_round_keys[(10-rk)*128 +: 128];
        end
    endgenerate

    // =========================================================================
    // Stage A combinational path
    //   AddRoundKey(RK0) → Round1 → Round2 → Round3
    // =========================================================================

    wire [127:0] ark0_out;          // after initial AddRoundKey
    wire [127:0] rA1_out;           // after Round 1
    wire [127:0] rA2_out;           // after Round 2
    wire [127:0] rA3_out;           // after Round 3

    assign ark0_out = plain_in ^ round_key[0];

    aes_round uA1 (.state_in(ark0_out), .round_key(round_key[1]),  .state_out(rA1_out));
    aes_round uA2 (.state_in(rA1_out),  .round_key(round_key[2]),  .state_out(rA2_out));
    aes_round uA3 (.state_in(rA2_out),  .round_key(round_key[3]),  .state_out(rA3_out));

    // --- Pipeline register A → B ---
    reg [127:0] stageA;

    always @(posedge clk) begin
        if (!rst_n) stageA <= 128'b0;
        else        stageA <= rA3_out;
    end

    // =========================================================================
    // Stage B combinational path
    //   Round4 → Round5 → Round6 → Round7
    // =========================================================================

    wire [127:0] rB4_out;
    wire [127:0] rB5_out;
    wire [127:0] rB6_out;
    wire [127:0] rB7_out;

    aes_round uB4 (.state_in(stageA),   .round_key(round_key[4]),  .state_out(rB4_out));
    aes_round uB5 (.state_in(rB4_out),  .round_key(round_key[5]),  .state_out(rB5_out));
    aes_round uB6 (.state_in(rB5_out),  .round_key(round_key[6]),  .state_out(rB6_out));
    aes_round uB7 (.state_in(rB6_out),  .round_key(round_key[7]),  .state_out(rB7_out));

    // --- Pipeline register B → C ---
    reg [127:0] stageB;

    always @(posedge clk) begin
        if (!rst_n) stageB <= 128'b0;
        else        stageB <= rB7_out;
    end

    // =========================================================================
    // Stage C combinational path
    //   Round8 → Round9 → FinalRound10
    // =========================================================================

    wire [127:0] rC8_out;
    wire [127:0] rC9_out;
    wire [127:0] rC10_out;

    aes_round       uC8  (.state_in(stageB),   .round_key(round_key[8]),  .state_out(rC8_out));
    aes_round       uC9  (.state_in(rC8_out),  .round_key(round_key[9]),  .state_out(rC9_out));
    aes_final_round uC10 (.state_in(rC9_out),  .round_key(round_key[10]), .state_out(rC10_out));

    // --- Output register ---
    reg [127:0] stageC;

    always @(posedge clk) begin
        if (!rst_n) stageC <= 128'b0;
        else        stageC <= rC10_out;
    end

    // =========================================================================
    // Valid / Done pipeline  (3 flops, one per stage)
    // =========================================================================

    reg [2:0] valid_pipe;

    always @(posedge clk) begin
        if (!rst_n) begin
            valid_pipe <= 3'b0;
        end else begin
            valid_pipe[0] <= start;
            valid_pipe[1] <= valid_pipe[0];
            valid_pipe[2] <= valid_pipe[1];
        end
    end

    // =========================================================================
    // Outputs
    // =========================================================================

    assign done       = valid_pipe[2];
    assign cipher_out = stageC;

endmodule


// =============================================================================
// AES MAIN ROUND  (SubBytes → ShiftRows → MixColumns → AddRoundKey)
// =============================================================================

module aes_round (
    input  wire [127:0] state_in,
    input  wire [127:0] round_key,
    output wire [127:0] state_out
);

    wire [127:0] sb_out;
    wire [127:0] sr_out;
    wire [127:0] mc_out;

    sub_byte u_sb (.data_in(state_in), .data_out(sb_out));
    shift_row u_sr (.data_in(sb_out),  .data_out(sr_out));
    mix_col   u_mc (.data_in(sr_out),  .data_out(mc_out));

    assign state_out = mc_out ^ round_key;

endmodule


// =============================================================================
// AES FINAL ROUND  (SubBytes → ShiftRows → AddRoundKey, no MixColumns)
// =============================================================================

module aes_final_round (
    input  wire [127:0] state_in,
    input  wire [127:0] round_key,
    output wire [127:0] state_out
);

    wire [127:0] sb_out;
    wire [127:0] sr_out;

    sub_byte  u_sb (.data_in(state_in), .data_out(sb_out));
    shift_row u_sr (.data_in(sb_out),   .data_out(sr_out));

    assign state_out = sr_out ^ round_key;

endmodule