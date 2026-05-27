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

// `timescale 1ns / 1ps
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
    // Key Expansion
    // =========================================================================

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

    // =========================================================================
    // Initial AddRoundKey
    // =========================================================================

    wire [127:0] init_state;

    assign init_state = plain_in ^ round_key[0];

    // =========================================================================
    // Pipeline Registers
    // =========================================================================

    reg [127:0] stage0;
    reg [127:0] stage1;
    reg [127:0] stage2;
    reg [127:0] stage3;
    reg [127:0] stage4;
    reg [127:0] stage5;
    reg [127:0] stage6;
    reg [127:0] stage7;
    reg [127:0] stage8;
    reg [127:0] stage9;
    reg [127:0] stage10;

    // =========================================================================
    // Round Outputs
    // =========================================================================

    wire [127:0] round1_out;
    wire [127:0] round2_out;
    wire [127:0] round3_out;
    wire [127:0] round4_out;
    wire [127:0] round5_out;
    wire [127:0] round6_out;
    wire [127:0] round7_out;
    wire [127:0] round8_out;
    wire [127:0] round9_out;
    wire [127:0] round10_out;

    // =========================================================================
    // AES Rounds 1-9
    // =========================================================================

    aes_round r1 (
        .state_in  (stage0),
        .round_key (round_key[1]),
        .state_out (round1_out)
    );

    aes_round r2 (
        .state_in  (stage1),
        .round_key (round_key[2]),
        .state_out (round2_out)
    );

    aes_round r3 (
        .state_in  (stage2),
        .round_key (round_key[3]),
        .state_out (round3_out)
    );

    aes_round r4 (
        .state_in  (stage3),
        .round_key (round_key[4]),
        .state_out (round4_out)
    );

    aes_round r5 (
        .state_in  (stage4),
        .round_key (round_key[5]),
        .state_out (round5_out)
    );

    aes_round r6 (
        .state_in  (stage5),
        .round_key (round_key[6]),
        .state_out (round6_out)
    );

    aes_round r7 (
        .state_in  (stage6),
        .round_key (round_key[7]),
        .state_out (round7_out)
    );

    aes_round r8 (
        .state_in  (stage7),
        .round_key (round_key[8]),
        .state_out (round8_out)
    );

    aes_round r9 (
        .state_in  (stage8),
        .round_key (round_key[9]),
        .state_out (round9_out)
    );

    // =========================================================================
    // Final Round (No MixColumns)
    // =========================================================================

    aes_final_round r10 (
        .state_in  (stage9),
        .round_key (round_key[10]),
        .state_out (round10_out)
    );

    // =========================================================================
    // Pipeline Registers
    // =========================================================================

    always @(posedge clk) begin

        if (!rst_n) begin

            stage0  <= 128'b0;
            stage1  <= 128'b0;
            stage2  <= 128'b0;
            stage3  <= 128'b0;
            stage4  <= 128'b0;
            stage5  <= 128'b0;
            stage6  <= 128'b0;
            stage7  <= 128'b0;
            stage8  <= 128'b0;
            stage9  <= 128'b0;
            stage10 <= 128'b0;

        end
        else begin

            // Load new plaintext every cycle
            stage0 <= init_state;

            // Shift pipeline forward
            stage1  <= round1_out;
            stage2  <= round2_out;
            stage3  <= round3_out;
            stage4  <= round4_out;
            stage5  <= round5_out;
            stage6  <= round6_out;
            stage7  <= round7_out;
            stage8  <= round8_out;
            stage9  <= round9_out;
            stage10 <= round10_out;

        end
    end

    // =========================================================================
    // Valid / Done Pipeline
    // =========================================================================

    reg [10:0] valid_pipe;

    always @(posedge clk) begin

        if (!rst_n) begin
            valid_pipe <= 11'b0;
        end
        else begin

            valid_pipe[0]  <= start;

            valid_pipe[1]  <= valid_pipe[0];
            valid_pipe[2]  <= valid_pipe[1];
            valid_pipe[3]  <= valid_pipe[2];
            valid_pipe[4]  <= valid_pipe[3];
            valid_pipe[5]  <= valid_pipe[4];
            valid_pipe[6]  <= valid_pipe[5];
            valid_pipe[7]  <= valid_pipe[6];
            valid_pipe[8]  <= valid_pipe[7];
            valid_pipe[9]  <= valid_pipe[8];
            valid_pipe[10] <= valid_pipe[9];

        end
    end

    // =========================================================================
    // Outputs
    // =========================================================================

    assign done       = valid_pipe[10];
    assign cipher_out = stage10;

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