/*
 * Copyright (c) 2024 lche0227
 * SPDX-License-Identifier: Apache-2.0
 */

// `timescale 1ns / 1ps

`default_nettype none
module tt_um_lche0227_aes_pipeline_top (
    input  wire [7:0] ui_in,
    output wire [7:0] uo_out,
    input  wire [7:0] uio_in,
    output wire [7:0] uio_out,
    output wire [7:0] uio_oe,
    input  wire       ena,
    input  wire       clk,
    input  wire       rst_n
);

    // =========================================================================
    // Control signal decoding
    //
    //   uio_in[4:0]  byte_index  0-15  = key byte slot
    //                            16-31 = plaintext byte slot
    //   uio_in[5]    we          write ui_in into selected slot
    //   uio_in[6]    start       pulse high for 1 cycle to begin encryption
    //   uio_in[7]    output_sel  1 = uo_out shows cipher byte; 0 = uo_out = 0
    //
    //   uio_out[0]   done        goes high 10 cycles after start pulse
    //   uo_out[7:0]  cipher byte selected by byte_index[3:0] when output_sel=1
    // =========================================================================

    wire [4:0] byte_index = uio_in[4:0];
    wire       we         = uio_in[5];
    wire       start_in   = uio_in[6];
    wire       output_sel = uio_in[7];

    // =========================================================================
    // Serial input registers: 128-bit key and 128-bit plaintext
    // Stored as byte arrays, written one byte at a time via ui_in
    // =========================================================================

    reg [7:0] key_bytes   [0:15];
    reg [7:0] plain_bytes [0:15];

    // Unroll the reset and write explicitly — avoids integer loop issues in Yosys
    genvar gi;
    generate
        for (gi = 0; gi < 16; gi = gi + 1) begin : BYTE_REGS

            always @(posedge clk) begin
                if (!rst_n) begin
                    key_bytes[gi]   <= 8'h00;
                    plain_bytes[gi] <= 8'h00;
                end
                else if (we) begin
                    // byte_index 0-15  → key slot gi
                    if (!byte_index[4] && (byte_index[3:0] == gi[3:0]))
                        key_bytes[gi] <= ui_in;

                    // byte_index 16-31 → plaintext slot gi
                    // byte_index[4] distinguishes the two halves
                    if (byte_index[4] && (byte_index[3:0] == gi[3:0]))
                        plain_bytes[gi] <= ui_in;
                end
            end

        end
    endgenerate

    // =========================================================================
    // Pack byte arrays into 128-bit vectors (big-endian: byte 0 = MSB)
    // =========================================================================

    wire [127:0] key_in;
    wire [127:0] plain_in;

    genvar b;
    generate
        for (b = 0; b < 16; b = b + 1) begin : PACK
            assign key_in  [127 - b*8 -: 8] = key_bytes[b];
            assign plain_in[127 - b*8 -: 8] = plain_bytes[b];
        end
    endgenerate
    // =========================================================================
    // Auto load_key: pulse one cycle after last key byte (index 15) written
    // =========================================================================

    reg load_key_r;

    always @(posedge clk) begin
        if (!rst_n)
            load_key_r <= 1'b0;
        else
            // fires the cycle AFTER byte_index=15 we=1 — key_bytes[15] is
            // already registered, so key_in is stable for key_gen to sample
            load_key_r <= (we && !byte_index[4] && (byte_index[3:0] == 4'd15));
    end

    // =========================================================================
    // Key generation (clocked)
    // =========================================================================

    wire [1407:0] all_round_keys;
    wire           keys_ready;

    key_gen u_key_gen (
        .clk           (clk),
        .rst_n         (rst_n),
        .load_key      (load_key_r),
        .key_in        (key_in),
        .round_key_out (all_round_keys),
        .keys_ready    (keys_ready)       // one-cycle pulse when expansion done
    );

    wire [127:0] round_key [0:10];
    genvar rk;
    generate
        for (rk = 0; rk <= 10; rk = rk + 1) begin : RK_UNPACK
            assign round_key[rk] = all_round_keys[(10-rk)*128 +: 128];
        end
    endgenerate

    // =========================================================================
    // AES pipeline core
    // =========================================================================
    
    wire        done;
    wire [127:0] cipher_out;

    aes_pipeline_top u_aes (
        .clk        (clk),
        .rst_n      (rst_n),
        .start      (start_in),
        .key_in     (key_in),
        .plain_in   (plain_in),
        .done       (done),
        .cipher_out (cipher_out)
    );

    // =========================================================================
    // Output byte mux — explicit 16:1 mux on cipher_out bytes
    // Avoids variable part-select in always @(*) which some tools warn about
    // =========================================================================

    wire [3:0] out_sel = byte_index[3:0];

    wire [7:0] cipher_mux_out;

    assign cipher_mux_out =
        (out_sel == 4'd0)  ? cipher_out[127:120] :
        (out_sel == 4'd1)  ? cipher_out[119:112] :
        (out_sel == 4'd2)  ? cipher_out[111:104] :
        (out_sel == 4'd3)  ? cipher_out[103: 96] :
        (out_sel == 4'd4)  ? cipher_out[ 95: 88] :
        (out_sel == 4'd5)  ? cipher_out[ 87: 80] :
        (out_sel == 4'd6)  ? cipher_out[ 79: 72] :
        (out_sel == 4'd7)  ? cipher_out[ 71: 64] :
        (out_sel == 4'd8)  ? cipher_out[ 63: 56] :
        (out_sel == 4'd9)  ? cipher_out[ 55: 48] :
        (out_sel == 4'd10) ? cipher_out[ 47: 40] :
        (out_sel == 4'd11) ? cipher_out[ 39: 32] :
        (out_sel == 4'd12) ? cipher_out[ 31: 24] :
        (out_sel == 4'd13) ? cipher_out[ 23: 16] :
        (out_sel == 4'd14) ? cipher_out[ 15:  8] :
                             cipher_out[  7:  0] ;

    // =========================================================================
    // Output assignments
    // =========================================================================

    assign uo_out  = output_sel ? cipher_mux_out : 8'h00;
    assign uio_out = {6'b0, keys_ready, done};  // [1]=keys_ready, [0]=done
    assign uio_oe  = 8'b0000_0001;   // only uio[0] is driven (done)

    // Suppress unused input warning
    wire _unused = &{ena, 1'b0};

endmodule