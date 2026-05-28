// -----------------------------------------------------------------------------
// key_gen.v  – Sequential AES-128 key schedule (top-level for key expansion)
// -----------------------------------------------------------------------------
// Behavior
//  - Implements AES-128 key expansion sequentially: on `start` the provided
//    128-bit `key_in` is loaded as RoundKey[0], and subsequent round keys are
//    generated one-per-cycle on each rising clock until all 10 round keys are
//    produced. This module does not compute all round keys combinationally in
//    a single cycle — it advances the key register each cycle.
//  - `round_key` presents the current round key. After `start`, the first
//    cycle presents RoundKey[0] (the original key), and successive cycles
//    present RoundKey[1], RoundKey[2], ..., RoundKey[10].
//
// Interface
//   clk       - clock
//   rst_n     - active-low synchronous reset
//   start     - assert for one cycle to begin expansion and load `key_in`
//   key_in    - 128-bit cipher key (used as RoundKey[0])
//   round_key - 128-bit output presenting the current round key
//
// Notes
//  - The module uses a small number of S-box instances (`sbox`) to implement
//    `SubWord` (4 bytes) used in the key schedule; these are instantiated as
//    separate `sbox` instances (one per byte of the `rot_word`).
//  - A `valid` register is used internally to drive sequential generation of
//    next keys until 10 rounds are produced.
// -----------------------------------------------------------------------------

`default_nettype none

module key_gen (

    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [127:0] key_in,
    output reg  [127:0] round_key
);

    // ---------------------------------------------------------------------
    // Current key register and round counter and valid
    // ---------------------------------------------------------------------

    reg [127:0] current_key;
    reg  [3:0]   round;
    reg valid;

    // ---------------------------------------------------------------------
    // Split current key into words
    // ---------------------------------------------------------------------

    wire [31:0] w0, w1, w2, w3;

    assign w0 = current_key[127:96];
    assign w1 = current_key[95:64];
    assign w2 = current_key[63:32];
    assign w3 = current_key[31:0];

    // ---------------------------------------------------------------------
    // RotWord
    // ---------------------------------------------------------------------

    wire [31:0] rot_word;

    assign rot_word = {
        w3[23:0],
        w3[31:24]
    };

    // ---------------------------------------------------------------------
    // SubWord
    // ONLY 4 S-boxes total
    // ---------------------------------------------------------------------

    wire [31:0] sub_word;

    sbox sb0 (
        .in_byte(rot_word[31:24]),
        .out_byte(sub_word[31:24])
    );

    sbox sb1 (
        .in_byte(rot_word[23:16]),
        .out_byte(sub_word[23:16])
    );

    sbox sb2 (
        .in_byte(rot_word[15:8]),
        .out_byte(sub_word[15:8])
    );

    sbox sb3 (
        .in_byte(rot_word[7:0]),
        .out_byte(sub_word[7:0])
    );

    // ---------------------------------------------------------------------
    // Rcon
    // ---------------------------------------------------------------------

    function [31:0] rcon;

        input [3:0] r;

        begin

            case (r)

                4'd1:  rcon = 32'h01000000;
                4'd2:  rcon = 32'h02000000;
                4'd3:  rcon = 32'h04000000;
                4'd4:  rcon = 32'h08000000;
                4'd5:  rcon = 32'h10000000;
                4'd6:  rcon = 32'h20000000;
                4'd7:  rcon = 32'h40000000;
                4'd8:  rcon = 32'h80000000;
                4'd9:  rcon = 32'h1b000000;
                4'd10: rcon = 32'h36000000;

                default:
                    rcon = 32'h00000000;

            endcase

        end

    endfunction

    // ---------------------------------------------------------------------
    // Generate next key
    // ---------------------------------------------------------------------

    wire [31:0] next_w0;
    wire [31:0] next_w1;
    wire [31:0] next_w2;
    wire [31:0] next_w3;

    assign next_w0 = w0 ^ sub_word ^ rcon(round + 1'b1);
    assign next_w1 = w1 ^ next_w0;
    assign next_w2 = w2 ^ next_w1;
    assign next_w3 = w3 ^ next_w2;

    wire [127:0] next_key;

    assign next_key = {
        next_w0,
        next_w1,
        next_w2,
        next_w3
    };

    // ---------------------------------------------------------------------
    // Sequential key schedule
    // ---------------------------------------------------------------------

    always @(posedge clk) begin

        if (!rst_n) begin

            current_key <= 128'd0;
            round       <= 4'd0;
            round_key   <= 128'd0;
            valid       <= 1'b0;

        end
        else begin

            // -------------------------------------------------------------
            // Start new key expansion
            // -------------------------------------------------------------

            if (start) begin

                current_key <= key_in;

                round_key <= key_in;
                round     <= 4'd0;
                valid <= 1'b1;

            end

            // -------------------------------------------------------------
            // Generate next round key
            // -------------------------------------------------------------

            else if (valid && (round < 10)) begin

                current_key <= next_key;

                round_key <= next_key;
                round     <= round + 1'b1;
                valid <= 1'b1;

            end

            // -------------------------------------------------------------
            // Done
            // -------------------------------------------------------------

            else begin

                valid <= 1'b0;

            end
        end
    end

endmodule
