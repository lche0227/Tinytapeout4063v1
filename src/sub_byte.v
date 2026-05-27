// =============================================================================
// sub_byte.v  –  AES-128 SubBytes transformation
// =============================================================================
// Applies the AES S-box substitution to every byte of the 128-bit state.
// The S-box values are taken directly from FIPS-197 (and match the table in
// the project spec: row = upper nibble (X), column = lower nibble (Y)).
//
// Ports
//   data_in  [127:0]  – 128-bit input state
//   data_out [127:0]  – 128-bit output state after byte substitution
// =============================================================================

module sub_byte (
    input  wire [127:0] data_in,
    output wire [127:0] data_out
);

    // Apply sbox to every one of the 16 bytes
    genvar i;
    generate
        for (i = 0; i < 16; i = i + 1) begin : SBOX_INST
            sbox u_sbox (
                .in_byte  (data_in [127 - i*8 -: 8]),
                .out_byte (data_out[127 - i*8 -: 8])
            );
        end
    endgenerate

endmodule


