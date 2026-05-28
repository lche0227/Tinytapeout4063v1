// =============================================================================
// aes_pipeline_top.v  —  Partially-unrolled AES-128, 2 rounds per cycle
//
// Architecture
// ─────────────────────────────────────────────────────────────────────
//  • Two reused aes_round instances (r1, r2) + one aes_final_round (rf)
//  • One aes_final_round for round 10
//
// Operation (latency = 17 cycles after valid_in pulse)
// ─────────────────────────────────────────────────────────────────────
//  KEYWAIT  : 10 cycles — key_gen expands RK0..RK10
//  Initial  :  1 cycle  — pt XOR RK0
//  Phase 0  :  1 cycle  — rounds 1, 2   (r1→RK1,  r2→RK2)
//  Phase 1  :  1 cycle  — rounds 3, 4   (r1→RK3,  r2→RK4)
//  Phase 2  :  1 cycle  — rounds 5, 6   (r1→RK5,  r2→RK6)
//  Phase 3  :  1 cycle  — rounds 7, 8   (r1→RK7,  r2→RK8)
//  Phase 4  :  1 cycle  — round  9      (r1→RK9)
//  Phase 5  :  1 cycle  — round  10     (rf→RK10)  valid_out asserted
// ─────────────────────────────────────────────────────────────────────
// =============================================================================

`default_nettype none

module aes_pipeline_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         valid_in,   // one-cycle start pulse

    input  wire [127:0] plaintext,
    input  wire [127:0] key_in,

    output reg  [127:0] ciphertext,
    output reg          valid_out
);

    // =========================================================================
    // FSM states
    // =========================================================================
    localparam [1:0] IDLE    = 2'd0;
    localparam [1:0] KEYWAIT = 2'd1;
    localparam [1:0] BUSY    = 2'd2;

    reg [1:0]   state;
    reg [2:0]   phase;
    reg [127:0] pt_latch;    // holds plaintext while key expansion runs
    reg [127:0] state_reg;   // running AES state
    reg [127:0] round9_reg;  // latches state after round 9

    // =========================================================================
    // Key-gen read-port index logic
    //
    //  • When not BUSY (IDLE / KEYWAIT): idx_a = 0  →  key_a = RK0
    //    This ensures RK0 is combinationally available the instant
    //    the KEYWAIT→BUSY transition fires.
    //
    //  • When BUSY, phase 0-4:  idx_a = 2*phase+1  (odd  keys for r1)
    //    When BUSY, phase 5:    idx_a = 10          (RK10 for final round)
    //
    //  • idx_b = 2*phase+2  (even keys for r2; ignored in phases 4-5)
    //
    //  Key assignments per phase:
    //    phase 0 → r1:RK1,  r2:RK2   (rounds 1,2)
    //    phase 1 → r1:RK3,  r2:RK4   (rounds 3,4)
    //    phase 2 → r1:RK5,  r2:RK6   (rounds 5,6)
    //    phase 3 → r1:RK7,  r2:RK8   (rounds 7,8)
    //    phase 4 → r1:RK9            (round  9)
    //    phase 5 → rf:RK10           (round  10, final)
    // =========================================================================

    wire [3:0] idx_a = (state != BUSY) ? 4'd0 :
                       (phase == 3'd5) ? 4'd10 :
                                         ({1'b0, phase} << 1) + 4'd1;

    wire [3:0] idx_b = ({1'b0, phase} << 1) + 4'd2;   // valid for phases 0-3

    // =========================================================================
    // Key generator instantiation
    // =========================================================================
    wire [127:0] key_a, key_b;
    wire         kg_ready;

    // Trigger expansion only from IDLE so we never accidentally restart
    wire kg_start = (state == IDLE) && valid_in;

    key_gen u_key_gen (
        .clk    (clk),
        .rst_n  (rst_n),
        .start  (kg_start),
        .key_in (key_in),
        .idx_a  (idx_a),
        .idx_b  (idx_b),
        .key_a  (key_a),
        .key_b  (key_b),
        .ready  (kg_ready)
    );

    // =========================================================================
    // Round function instantiations
    //
    //  r1  — main round:  state_reg  keyed by key_a
    //  r2  — main round:  round1_out keyed by key_b
    //  rf  — final round: round9_reg keyed by key_a  (= RK10 when phase==5)
    // =========================================================================
    wire [127:0] round1_out;
    wire [127:0] round2_out;
    wire [127:0] final_out;

    aes_round r1 (
        .state_in  (state_reg),
        .round_key (key_a),
        .state_out (round1_out)
    );

    aes_round r2 (
        .state_in  (round1_out),
        .round_key (key_b),
        .state_out (round2_out)
    );

    aes_final_round rf (
        .state_in  (round9_reg),
        .round_key (key_a),      // key_a = RK10 when phase == 5
        .state_out (final_out)
    );

    // =========================================================================
    // Main FSM
    // =========================================================================
    always @(posedge clk) begin
        if (!rst_n) begin
            state      <= IDLE;
            phase      <= 3'd0;
            valid_out  <= 1'b0;
            ciphertext <= 128'd0;
            state_reg  <= 128'd0;
            round9_reg <= 128'd0;
            pt_latch   <= 128'd0;
        end
        else begin
            valid_out <= 1'b0;   // default: deassert every cycle

            case (state)

                // -------------------------------------------------------------
                // IDLE — wait for an encryption request.
                // Latch plaintext; kg_start combinationally triggers key_gen.
                // -------------------------------------------------------------
                IDLE: begin
                    if (valid_in) begin
                        pt_latch <= plaintext;
                        state    <= KEYWAIT;
                    end
                end

                // -------------------------------------------------------------
                // KEYWAIT — stall while key_gen expands all 11 round keys.
                //
                // idx_a = 0 throughout this state, so key_a = RK0
                // is combinationally available when kg_ready fires.
                // The initial AddRoundKey (pt XOR RK0) is done here.
                // -------------------------------------------------------------
                KEYWAIT: begin
                    if (kg_ready) begin
                        state_reg <= pt_latch ^ key_a;   // key_a = RK0 here
                        phase     <= 3'd0;
                        state     <= BUSY;
                    end
                end

                // -------------------------------------------------------------
                // BUSY — execute the 2-round-per-cycle pipeline.
                // -------------------------------------------------------------
                BUSY: begin
                    if (phase < 3'd4) begin
                        // Two normal rounds using key_a (r1) and key_b (r2)
                        state_reg <= round2_out;
                        phase     <= phase + 1'b1;
                    end
                    else if (phase == 3'd4) begin
                        // Round 9 only — key_a = RK9
                        round9_reg <= round1_out;
                        phase      <= phase + 1'b1;
                    end
                    else begin
                        // Round 10 (final) — key_a = RK10
                        ciphertext <= final_out;
                        valid_out  <= 1'b1;
                        phase      <= 3'd0;
                        state      <= IDLE;
                    end
                end

                default: state <= IDLE;

            endcase
        end
    end

endmodule


// =============================================================================
// AES MAIN ROUND  (SubBytes + ShiftRows + MixColumns + AddRoundKey)
// =============================================================================

module aes_round (
    input  wire [127:0] state_in,
    input  wire [127:0] round_key,
    output wire [127:0] state_out
);
    wire [127:0] sb_out, sr_out, mc_out;

    sub_byte  u_sb (.data_in(state_in), .data_out(sb_out));
    shift_row u_sr (.data_in(sb_out),   .data_out(sr_out));
    mix_col   u_mc (.data_in(sr_out),   .data_out(mc_out));

    assign state_out = mc_out ^ round_key;
endmodule


// =============================================================================
// AES FINAL ROUND  (SubBytes + ShiftRows + AddRoundKey — no MixColumns)
// =============================================================================

module aes_final_round (
    input  wire [127:0] state_in,
    input  wire [127:0] round_key,
    output wire [127:0] state_out
);
    wire [127:0] sb_out, sr_out;

    sub_byte  u_sb (.data_in(state_in), .data_out(sb_out));
    shift_row u_sr (.data_in(sb_out),   .data_out(sr_out));

    assign state_out = sr_out ^ round_key;
endmodule
