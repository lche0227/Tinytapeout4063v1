`default_nettype none

module key_gen (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,

    input  wire [127:0] key_in,

    output reg  [127:0] round_key,
    output reg  [3:0]   round,
    output reg          valid
);

    // ---------------------------------------------------------------------
    // Internal current key storage
    // ---------------------------------------------------------------------

    reg [127:0] current_key;

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
    // SubWord (ONLY 4 S-boxes total)
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
                default: rcon = 32'h00000000;
            endcase
        end
    endfunction

    // ---------------------------------------------------------------------
    // Next key generation
    // ---------------------------------------------------------------------

    wire [31:0] next_w0, next_w1, next_w2, next_w3;

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

            if (start) begin

                current_key <= key_in;
                round_key   <= key_in;
                round       <= 4'd0;
                valid       <= 1'b1;

            end
            else if (valid && (round < 10)) begin

                current_key <= next_key;
                round_key   <= next_key;
                round       <= round + 1'b1;
                valid       <= 1'b1;

            end
            else begin

                valid <= 1'b0;

            end
        end
    end

endmodule
```
