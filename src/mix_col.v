// =============================================================================
// mix_col.v  –  AES-128 MixColumns transformation
// =============================================================================
// Applies the MixColumns operation to all four columns of the 128-bit state.
// Each column is processed independently by the mixcolumns_one_column
// sub-module (provided in the project spec) using GF(2^8) arithmetic.
//
// State layout (column-major, as used throughout this project):
//   bits[127:96]  = column 0
//   bits[95:64]   = column 1
//   bits[63:32]   = column 2
//   bits[31:0]    = column 3
//
// Ports
//   data_in  [127:0]  – 128-bit input state (after ShiftRows)
//   data_out [127:0]  – 128-bit output state after MixColumns
// =============================================================================

module mix_col (
    input  wire [127:0] data_in,
    output wire [127:0] data_out
);

    mixcolumns_one_column u_col0 (
        .col_in  (data_in[127:96]),
        .col_out (data_out[127:96])
    );

    mixcolumns_one_column u_col1 (
        .col_in  (data_in[95:64]),
        .col_out (data_out[95:64])
    );

    mixcolumns_one_column u_col2 (
        .col_in  (data_in[63:32]),
        .col_out (data_out[63:32])
    );

    mixcolumns_one_column u_col3 (
        .col_in  (data_in[31:0]),
        .col_out (data_out[31:0])
    );

endmodule


// =============================================================================
// mixcolumns_one_column  –  GF(2^8) column mix (provided by project spec)
// =============================================================================
// Operates on a single 32-bit column [s0 s1 s2 s3] where s0 is the most-
// significant byte (row 0).  Implements the MDS matrix multiply defined in
// FIPS-197 Section 4.2.1.
// =============================================================================
module mixcolumns_one_column (
    input  wire [31:0] col_in,
    output wire [31:0] col_out
);
    wire [7:0] s0, s1, s2, s3;
    wire [7:0] m0, m1, m2, m3;

    assign s0 = col_in[31:24];
    assign s1 = col_in[23:16];
    assign s2 = col_in[15:8];
    assign s3 = col_in[7:0];

    assign m0 = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2          ^ s3;
    assign m1 = s0         ^ xtime(s1)         ^ (xtime(s2) ^ s2) ^ s3;
    assign m2 = s0         ^ s1                ^ xtime(s2)  ^ (xtime(s3) ^ s3);
    assign m3 = (xtime(s0) ^ s0) ^ s1          ^ s2         ^ xtime(s3);

    assign col_out = {m0, m1, m2, m3};

    // xtime: multiply by 2 in GF(2^8) with reduction polynomial x^8+x^4+x^3+x+1
    function [7:0] xtime;
        input [7:0] b;
        begin
            if (b[7] == 1'b1)
                xtime = (b << 1) ^ 8'h1b;
            else
                xtime = (b << 1);
        end
    endfunction

endmodule