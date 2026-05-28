// =============================================================================
// aes_pipeline_top.v
// Fully pipelined AES-128 encryption core // not anymore
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

    // ---------------------------------------------------------------------
    // Round keys
    // ---------------------------------------------------------------------

    wire [127:0] current_round_key;
    wire [3:0]   current_round;
    wire         key_valid;
    
    key_gen u_key_gen (
        .clk       (clk),
        .rst_n     (rst_n),
        .start     (valid_in),
    
        .key_in    (key_in),
    
        .round_key (current_round_key),
        .round     (current_round),
        .valid     (key_valid)
    );

    // ---------------------------------------------------------------------
    // Internal state
    // ---------------------------------------------------------------------

    reg [127:0] state_reg;
    reg [2:0]   phase;
    reg         busy;
    reg [127:0] round9_reg;

    // ---------------------------------------------------------------------
    // Round outputs
    // ---------------------------------------------------------------------

    wire [127:0] round1_out;
    wire [127:0] round2_out;
    wire [127:0] final_out;

    // ---------------------------------------------------------------------
    // Two reused AES rounds
    // ---------------------------------------------------------------------
    wire [3:0] rk1_idx;
    wire [3:0] rk2_idx;
    
    assign rk1_idx = (phase == 3'd4) ? 4'd9 :
                     ({1'b0, phase} << 1) + 4'd1;
    
    assign rk2_idx = (phase >= 3'd4) ? 4'd9 :
                     ({1'b0, phase} << 1) + 4'd2;
    
    aes_round r1 (
        .state_in  (state_reg),
        .round_key (current_round_key),
        .state_out (round1_out)
    );

    aes_round r2 (
        .state_in  (round1_out),
        .round_key (current_round_key),
        .state_out (round2_out)
    );

    // ---------------------------------------------------------------------
    // Final round
    // ---------------------------------------------------------------------

    aes_final_round rf (
        .state_in  (round9_reg),
        .round_key (current_round_key),
        .state_out (final_out)
    );

    // ---------------------------------------------------------------------
    // Main controller
    // ---------------------------------------------------------------------

    always @(posedge clk) begin

        if (!rst_n) begin

            state_reg  <= 128'd0;
            ciphertext <= 128'd0;
            valid_out  <= 1'b0;
            phase      <= 3'd0;
            busy       <= 1'b0;

        end
        else begin

            valid_out <= 1'b0;

            // -------------------------------------------------------------
            // Start encryption
            // -------------------------------------------------------------

            if (valid_in && !busy) begin

                state_reg <= plaintext ^ current_round_key;
                phase     <= 3'd0;
                busy      <= 1'b1;

            end

            // -------------------------------------------------------------
            // Perform 2 rounds per cycle
            // -------------------------------------------------------------

            else if (busy) begin
                // ---------------------------------------------------------
                // Phases 0..3
                // Perform TWO normal AES rounds
                // ---------------------------------------------------------
                if (phase < 4) begin

                    state_reg <= round2_out;
                    phase     <= phase + 1'b1;

                end

                // ---------------------------------------------------------
                // Phase 4
                // Perform ONLY round 9
                // ---------------------------------------------------------
            
                else if (phase == 4) begin
            
                    round9_reg <= round1_out;
                    phase     <= phase + 1'b1;
            
                end
    
                // ---------------------------------------------------------
                // Phase 5
                // Final AES round (round 10)
                // ---------------------------------------------------------

                else begin

                    // Final round after rounds 1..9 complete
                    ciphertext <= final_out;
                    valid_out  <= 1'b1;
                    busy       <= 1'b0;
                    phase <= 3'd0;

                end
            end
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
