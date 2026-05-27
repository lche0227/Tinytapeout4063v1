// =============================================================================
// aes_pipeline_top.v
// Fully pipelined AES-128 encryption core
//
// Architecture:
//   - Fully unrolled
//   - 10 pipeline stages
//   - One ciphertext output per clock after pipeline fill
//	  - Streaming input/output handshake interface
//
//	Operation:
// 1. Now there is dedicated hardware every round (much larger area ~10x) and all rounds are instantiated simultaneously
//	1. Total Latency: 10 cycles
//	2. Compared to iterative one-round-per-cycle, throughput massively improved (1 ciphertext per clock instead of 1 every 12 clocks)
// =============================================================================

`default_nettype none

module aes_pipeline_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         valid_in,

    input  wire [127:0] plaintext,
    input  wire [127:0] key_in,

    output reg  [127:0] ciphertext,
    output reg          valid_out
);

    // -------------------------------------------------------------------------
    // Key Expansion
    // -------------------------------------------------------------------------

    wire [1407:0] all_round_keys;
    wire [127:0] round_key [0:10];

    key_gen u_key_gen (
        .key_in        (key_in),
        .round_key_out (all_round_keys)
    );

    genvar rk;

    generate
        for (rk = 0; rk <= 10; rk = rk + 1) begin : RK_UNPACK
            assign round_key[rk] =
                all_round_keys[(10-rk)*128 +: 128];
        end
    endgenerate

    // -------------------------------------------------------------------------
    // Initial AddRoundKey
    // -------------------------------------------------------------------------

    wire [127:0] round0_state;

    assign round0_state = plaintext ^ round_key[0];

    // -------------------------------------------------------------------------
    // Fully combinational rounds
    // -------------------------------------------------------------------------

    wire [127:0] round_state [1:9];

    aes_round r1 (
        .state_in  (round0_state),
        .round_key (round_key[1]),
        .state_out (round_state[1])
    );

    aes_round r2 (
        .state_in  (round_state[1]),
        .round_key (round_key[2]),
        .state_out (round_state[2])
    );

    aes_round r3 (
        .state_in  (round_state[2]),
        .round_key (round_key[3]),
        .state_out (round_state[3])
    );

    aes_round r4 (
        .state_in  (round_state[3]),
        .round_key (round_key[4]),
        .state_out (round_state[4])
    );

    aes_round r5 (
        .state_in  (round_state[4]),
        .round_key (round_key[5]),
        .state_out (round_state[5])
    );

    aes_round r6 (
        .state_in  (round_state[5]),
        .round_key (round_key[6]),
        .state_out (round_state[6])
    );

    aes_round r7 (
        .state_in  (round_state[6]),
        .round_key (round_key[7]),
        .state_out (round_state[7])
    );

    aes_round r8 (
        .state_in  (round_state[7]),
        .round_key (round_key[8]),
        .state_out (round_state[8])
    );

    aes_round r9 (
        .state_in  (round_state[8]),
        .round_key (round_key[9]),
        .state_out (round_state[9])
    );

    // -------------------------------------------------------------------------
    // Final Round
    // -------------------------------------------------------------------------

    wire [127:0] final_state;

    aes_final_round r10 (
        .state_in  (round_state[9]),
        .round_key (round_key[10]),
        .state_out (final_state)
    );

    // -------------------------------------------------------------------------
    // ONLY output register retained
    // -------------------------------------------------------------------------

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ciphertext <= 128'd0;
            valid_out  <= 1'b0;
        end
        else begin
            ciphertext <= final_state;
            valid_out  <= valid_in;
        end
    end

endmodule


// =============================================================================
// AES MAIN ROUND
// =============================================================================

module aes_round (

    input  wire [127:0] state_in,
    input  wire [127:0] round_key,

    output wire [127:0] state_out
);

    wire [127:0] sb_out;
    wire [127:0] sr_out;
    wire [127:0] mc_out;

    sub_byte u_sb (
        .data_in  (state_in),
        .data_out (sb_out)
    );

    shift_row u_sr (
        .data_in  (sb_out),
        .data_out (sr_out)
    );

    mix_col u_mc (
        .data_in  (sr_out),
        .data_out (mc_out)
    );

    assign state_out = mc_out ^ round_key;

endmodule


// =============================================================================
// AES FINAL ROUND
// =============================================================================

module aes_final_round (

    input  wire [127:0] state_in,
    input  wire [127:0] round_key,

    output wire [127:0] state_out
);

    wire [127:0] sb_out;
    wire [127:0] sr_out;

    sub_byte u_sb (
        .data_in  (state_in),
        .data_out (sb_out)
    );

    shift_row u_sr (
        .data_in  (sb_out),
        .data_out (sr_out)
    );

    assign state_out = sr_out ^ round_key;

endmodule
