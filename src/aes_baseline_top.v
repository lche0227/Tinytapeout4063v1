// =============================================================================
// aes_baseline_top.v  –  AES-128 Encryption Core (top level)
// =============================================================================
// Iterative one-round-per-cycle architecture.
//
// Interface (start/busy/done style – design choice B in the project spec):
//   clk        – clock
//   rst_n      – active-low synchronous reset
//   start      – assert for one cycle to begin encryption
//   key_in     – 128-bit cipher key
//   plain_in   – 128-bit plaintext
//   busy       – high while encryption is in progress
//   done       – pulses high for one cycle when ciphertext is ready
//   cipher_out – 128-bit ciphertext output (valid when done is high and
//                remains stable until the next start)
//
// Operation
//   1. Assert start=1 with valid key_in and plain_in.
//   2. The core loads the key, pre-computes all round keys, performs the
//      initial AddRoundKey, then steps through 9 main rounds (each one clock
//      cycle) and the final round 10 (no MixColumns).
//   3. busy is high throughout; done pulses when cipher_out is valid.
//   4. Total latency: 12 clock cycles after start (1 load + 1 initial ARK +
//      9 main rounds + 1 final round).
//
// Hierarchy
//   main          (this file)
//   ├── key_gen   (key_gen.v)
//   ├── sub_byte  (sub_byte.v)  x2 instances (main + final round)
//   ├── shift_row (shift_row.v) x2 instances
//   └── mix_col   (mix_col.v)
// =============================================================================

`default_nettype none

module aes_baseline_top (
    input  wire         clk,
    input  wire         rst_n,      // active-low synchronous reset
    input  wire         start,
    input  wire [127:0] key_in,
    input  wire [127:0] plain_in,
    output reg          done,
    output reg  [127:0] cipher_out
);

    // -------------------------------------------------------------------------
    // FSM states
    // -------------------------------------------------------------------------
    localparam [3:0]
        S_IDLE       = 4'd0,
        S_INIT_ARK   = 4'd1,   // initial AddRoundKey (round key 0)
        S_ROUND_MAIN = 4'd2,   // rounds 1-9 (SubBytes→ShiftRows→MixColumns→ARK)
        S_ROUND_FINAL= 4'd3,   // round 10 (SubBytes→ShiftRows→ARK)
        S_DONE       = 4'd4;

    reg [3:0]  state;
    reg [3:0]  round_cnt;       // tracks current round (1-10)

    // -------------------------------------------------------------------------
    // Registered copies of inputs – declared here so key_gen can use key_reg
    // -------------------------------------------------------------------------
    reg [127:0] state_reg;      // current AES state (128-bit)

    // -------------------------------------------------------------------------
    // Key expansion – change to sequential
    // -------------------------------------------------------------------------
    wire [127:0] current_round_key;

    key_gen u_key_gen (

        .clk       (clk),
        .rst_n     (rst_n),
        .start     (start),
        .key_in    (key_in),
        .round_key (current_round_key)
    );

    // -------------------------------------------------------------------------
    // Datapath wires
    // -------------------------------------------------------------------------
    wire [127:0] sb_out;        // SubBytes output
    wire [127:0] sr_out;        // ShiftRows output
    wire [127:0] mc_out;        // MixColumns output

    sub_byte  u_subbytes  (.data_in(state_reg), .data_out(sb_out));
    shift_row u_shiftrows (.data_in(sb_out),    .data_out(sr_out));
    mix_col   u_mixcols   (.data_in(sr_out),    .data_out(mc_out));

    // -------------------------------------------------------------------------
    // FSM – sequential part
    // -------------------------------------------------------------------------
    always @(posedge clk) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            round_cnt <= 4'd0;
            done      <= 1'b0;
            cipher_out<= 128'b0;
            state_reg <= 128'b0;
        end else begin
            done <= 1'b0;   // default: not done

            case (state)
                // -------------------------------------------------------------
                S_IDLE: begin
                    if (start) begin
                        state_reg <= plain_in;
                        state     <= S_INIT_ARK;
                        round_cnt <= 4'd1;
                    end
                end

                // -------------------------------------------------------------
                // Initial AddRoundKey: state = plaintext XOR RoundKey[0]
                // -------------------------------------------------------------
                S_INIT_ARK: begin
                    state_reg <= state_reg ^ current_round_key;
                    state     <= S_ROUND_MAIN;
                end

                // -------------------------------------------------------------
                // Main rounds 1-9: SubBytes → ShiftRows → MixColumns → ARK
                // Datapath modules are already driven by state_reg (registered).
                // On this clock edge we write the ARK result back to state_reg
                // and advance the round counter.
                // -------------------------------------------------------------
                S_ROUND_MAIN: begin
                    state_reg <= mc_out ^ current_round_key;

                    if (round_cnt == 4'd9) begin
                        // Next iteration is the final round
                        round_cnt <= round_cnt + 4'd1;
                        state     <= S_ROUND_FINAL;
                    end else begin
                        round_cnt <= round_cnt + 4'd1;
                        state     <= S_ROUND_MAIN;
                    end
                end

                // -------------------------------------------------------------
                // Final round 10: SubBytes → ShiftRows → ARK (no MixColumns)
                // sr_out = ShiftRows(SubBytes(state_reg))
                // -------------------------------------------------------------
                S_ROUND_FINAL: begin
                    state_reg  <= sr_out ^ current_round_key;
                    cipher_out <= sr_out ^ current_round_key;
                    state      <= S_DONE;
                end

                // -------------------------------------------------------------
                S_DONE: begin
                    done  <= 1'b1;
                    state <= S_IDLE;
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
