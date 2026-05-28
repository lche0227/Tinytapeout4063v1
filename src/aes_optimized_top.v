// =============================================================================
// aes_optimized_top.v
// Iterative AES-128 encryption core
//
// Architecture:
//   - One shared AES round datapath reused for all 10 rounds
//   - One shared 4-S-box key step reused for the round-key schedule
//   - Latency: 10 cycles from start to done
//   - Area: minimal for Tiny Tapeout absolute sizing
//
// Interface unchanged from the byte-serial wrapper.
// =============================================================================

`default_nettype none

module aes_optimized_top (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,

    input  wire [127:0] key_in,
    input  wire [127:0] plain_in,

    output wire         done,
    output wire [127:0] cipher_out
);

    // -------------------------------------------------------------------------
    // Iterative AES core state
    // -------------------------------------------------------------------------

    reg [127:0] state_reg;
    reg [127:0] key_reg;
    reg [3:0]   round_ctr;
    reg         busy;
    reg         done_reg;
    reg [127:0] cipher_reg;

    wire [127:0] next_key;
    wire [127:0] next_state;
    wire         final_round = (round_ctr == 4'd10);

    aes_key_schedule_step u_key_step (
        .key_in    (key_reg),
        .round_num (round_ctr),
        .key_out   (next_key)
    );

    aes_iter_round u_round (
        .state_in    (state_reg),
        .round_key   (next_key),
        .final_round (final_round),
        .state_out   (next_state)
    );

    always @(posedge clk) begin
        if (!rst_n) begin
            state_reg  <= 128'b0;
            key_reg    <= 128'b0;
            round_ctr  <= 4'b0;
            busy       <= 1'b0;
            done_reg   <= 1'b0;
            cipher_reg <= 128'b0;
        end else begin
            done_reg <= 1'b0;

            if (start) begin
                state_reg  <= plain_in ^ key_in;
                key_reg    <= key_in;
                round_ctr  <= 4'd1;
                busy       <= 1'b1;
                cipher_reg <= plain_in ^ key_in;
            end else if (busy) begin
                state_reg  <= next_state;
                key_reg    <= next_key;
                cipher_reg <= next_state;

                if (round_ctr == 4'd10) begin
                    busy     <= 1'b0;
                    done_reg <= 1'b1;
                end else begin
                    round_ctr <= round_ctr + 4'd1;
                end
            end
        end
    end

    assign done       = done_reg;
    assign cipher_out = cipher_reg;

endmodule


// =============================================================================
// AES KEY SCHEDULE STEP  (W[0..3] -> W[4..7])
// =============================================================================

module aes_key_schedule_step (
    input  wire [127:0] key_in,
    input  wire [3:0]   round_num,
    output wire [127:0] key_out
);

    function automatic [31:0] rcon;
        input [3:0] rnd;
        begin
            case (rnd)
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

    wire [31:0] w0 = key_in[127:96];
    wire [31:0] w1 = key_in[95:64];
    wire [31:0] w2 = key_in[63:32];
    wire [31:0] w3 = key_in[31:0];

    wire [31:0] rot_w = {w3[23:0], w3[31:24]};
    wire [31:0] sub_w;
    wire [31:0] temp_w;
    wire [31:0] w4;
    wire [31:0] w5;
    wire [31:0] w6;
    wire [31:0] w7;

    sbox u_sb0 (.in_byte(rot_w[31:24]), .out_byte(sub_w[31:24]));
    sbox u_sb1 (.in_byte(rot_w[23:16]), .out_byte(sub_w[23:16]));
    sbox u_sb2 (.in_byte(rot_w[15:8]),  .out_byte(sub_w[15:8]));
    sbox u_sb3 (.in_byte(rot_w[7:0]),   .out_byte(sub_w[7:0]));

    assign temp_w = sub_w ^ rcon(round_num);
    assign w4 = w0 ^ temp_w;
    assign w5 = w1 ^ w4;
    assign w6 = w2 ^ w5;
    assign w7 = w3 ^ w6;

    assign key_out = {w4, w5, w6, w7};

endmodule


// =============================================================================
// AES ITERATIVE ROUND  (SubBytes -> ShiftRows -> MixColumns -> AddRoundKey)
// =============================================================================

module aes_iter_round (
    input  wire [127:0] state_in,
    input  wire [127:0] round_key,
    input  wire         final_round,
    output wire [127:0] state_out
);

    wire [127:0] sb_out;
    wire [127:0] sr_out;
    wire [127:0] mc_out;

    sub_byte u_sb (.data_in(state_in), .data_out(sb_out));
    shift_row u_sr (.data_in(sb_out), .data_out(sr_out));
    mix_col   u_mc (.data_in(sr_out), .data_out(mc_out));

    assign state_out = final_round ? (sr_out ^ round_key) : (mc_out ^ round_key);

endmodule
