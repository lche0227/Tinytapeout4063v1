// =============================================================================
// shift_row.v  –  AES-128 ShiftRows transformation
// =============================================================================
// The 128-bit state is treated as a 4×4 byte matrix stored column-major,
// matching the AES FIPS-197 convention used throughout the project:
//
//   state[127:120]  state[95:88]   state[63:56]   state[31:24]   <- row 0
//   state[119:112]  state[87:80]   state[55:48]   state[23:16]   <- row 1
//   state[111:104]  state[79:72]   state[47:40]   state[15:8]    <- row 2
//   state[103:96]   state[71:64]   state[39:32]   state[7:0]     <- row 3
//
// ShiftRows cyclically left-shifts each row:
//   Row 0: no shift
//   Row 1: shift left by 1 byte
//   Row 2: shift left by 2 bytes
//   Row 3: shift left by 3 bytes
//
// Ports
//   data_in  [127:0]  – 128-bit input state
//   data_out [127:0]  – 128-bit output state after row shifting
// =============================================================================
// `timescale 1ns / 1ps
`default_nettype none
module shift_row (
    input  wire [127:0] data_in,
    output wire [127:0] data_out
);

    // -------------------------------------------------------------------------
    // Extract individual bytes (named by row, column: bRC)
    // Column-major layout: col0 = bits[127:96], col1 = bits[95:64],
    //                      col2 = bits[63:32],  col3 = bits[31:0]
    // -------------------------------------------------------------------------
    wire [7:0] b00, b01, b02, b03;  // row 0
    wire [7:0] b10, b11, b12, b13;  // row 1
    wire [7:0] b20, b21, b22, b23;  // row 2
    wire [7:0] b30, b31, b32, b33;  // row 3

    // Column 0 (bits 127:96)
    assign b00 = data_in[127:120];
    assign b10 = data_in[119:112];
    assign b20 = data_in[111:104];
    assign b30 = data_in[103:96];

    // Column 1 (bits 95:64)
    assign b01 = data_in[95:88];
    assign b11 = data_in[87:80];
    assign b21 = data_in[79:72];
    assign b31 = data_in[71:64];

    // Column 2 (bits 63:32)
    assign b02 = data_in[63:56];
    assign b12 = data_in[55:48];
    assign b22 = data_in[47:40];
    assign b32 = data_in[39:32];

    // Column 3 (bits 31:0)
    assign b03 = data_in[31:24];
    assign b13 = data_in[23:16];
    assign b23 = data_in[15:8];
    assign b33 = data_in[7:0];

    // -------------------------------------------------------------------------
    // Apply cyclic left-shifts per row, then reassemble column-major
    //   Row 0: [b00, b01, b02, b03]  -> no shift  -> [b00, b01, b02, b03]
    //   Row 1: [b10, b11, b12, b13]  -> <<1 byte  -> [b11, b12, b13, b10]
    //   Row 2: [b20, b21, b22, b23]  -> <<2 bytes -> [b22, b23, b20, b21]
    //   Row 3: [b30, b31, b32, b33]  -> <<3 bytes -> [b33, b30, b31, b32]
    // -------------------------------------------------------------------------
    assign data_out = {
        // Column 0 (after shift)
        b00,   // row 0, col 0 (no shift)
        b11,   // row 1, col 1 (shifted from col 0)
        b22,   // row 2, col 2 (shifted from col 0)
        b33,   // row 3, col 3 (shifted from col 0)
        // Column 1 (after shift)
        b01,   // row 0, col 1
        b12,   // row 1, col 2
        b23,   // row 2, col 3
        b30,   // row 3, col 0
        // Column 2 (after shift)
        b02,   // row 0, col 2
        b13,   // row 1, col 3
        b20,   // row 2, col 0
        b31,   // row 3, col 1
        // Column 3 (after shift)
        b03,   // row 0, col 3
        b10,   // row 1, col 0
        b21,   // row 2, col 1
        b32    // row 3, col 2
    };

endmodule