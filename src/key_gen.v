// =============================================================================
// key_gen.v  –  AES-128 Key Expansion (KeySchedule)
// =============================================================================
// Generates all 11 round keys (RoundKey[0..10]) from the 128-bit cipher key
// using the AES key schedule defined in FIPS-197 Section 5.2.
//
// The expansion is done combinationally so all round keys are available
// within the same clock cycle after reset / key load.  This is the standard
// approach for an iterative AES core where the datapath steps through rounds
// sequentially while the key schedule is pre-computed.
//
// Key schedule summary for AES-128 (Nk = 4, Nr = 10):
//   W[i] = W[i-Nk] XOR SubWord(RotWord(W[i-1])) XOR Rcon[i/Nk]   (i mod Nk == 0)
//   W[i] = W[i-Nk] XOR W[i-1]                                     (otherwise)
//
// Rcon values (round constant, applied to the most-significant byte only):
//   Rcon[1..10] = {01,02,04,08,10,20,40,80,1b,36}
//
// Ports
//   key_in        [127:0]    – original 128-bit cipher key
//   round_key_out [1407:0]   – all 11 round keys concatenated
//                              bits[1407:1280] = RoundKey[0]  (= key_in)
//                              bits[1279:1152] = RoundKey[1]
//                              ...
//                              bits[127:0]     = RoundKey[10]
// =============================================================================

`default_nettype none

module key_gen (
    input  wire [127:0]  key_in,
    output wire [1407:0] round_key_out   // 11 × 128 bits
);

    // -------------------------------------------------------------------------
    // Internal word array  W[0..43]  (44 words × 32 bits)
    // -------------------------------------------------------------------------
    wire [31:0] W [0:43];

    // Seed from the cipher key
    assign W[0]  = key_in[127:96];
    assign W[1]  = key_in[95:64];
    assign W[2]  = key_in[63:32];
    assign W[3]  = key_in[31:0];

    // Rcon table (index 1-based; only the most-significant byte is non-zero)
    function [31:0] rcon;
        input integer rnd;  // round index 1..10
        begin
            case (rnd)
                1:  rcon = 32'h01000000;
                2:  rcon = 32'h02000000;
                3:  rcon = 32'h04000000;
                4:  rcon = 32'h08000000;
                5:  rcon = 32'h10000000;
                6:  rcon = 32'h20000000;
                7:  rcon = 32'h40000000;
                8:  rcon = 32'h80000000;
                9:  rcon = 32'h1b000000;
                10: rcon = 32'h36000000;
                default: rcon = 32'h00000000;
            endcase
        end
    endfunction

    // RotWord: left-rotate a 32-bit word by 8 bits (one byte)
    function [31:0] rot_word;
        input [31:0] w;
        begin
            rot_word = {w[23:0], w[31:24]};
        end
    endfunction


	 wire [31:0] rot_w [0:9];   // RotWord results for the 10 schedule positions
    wire [31:0] sub_w [0:9];   // SubWord results for the same 10 positions
 
	 
	genvar s;
		 generate
			  for (s = 0; s < 10; s = s + 1) begin : SUBWORD_INST
					// rot_w[s] = RotWord( W[4s+3] )  which is W[i-1] for i = 4*(s+1)
					assign rot_w[s] = rot_word(W[4*s + 3]);
	 
					// One sbox instance per byte of the rotated word
					sbox u_sb0 (.in_byte(rot_w[s][31:24]), .out_byte(sub_w[s][31:24]));
					sbox u_sb1 (.in_byte(rot_w[s][23:16]), .out_byte(sub_w[s][23:16]));
					sbox u_sb2 (.in_byte(rot_w[s][15:8]),  .out_byte(sub_w[s][15:8]));
					sbox u_sb3 (.in_byte(rot_w[s][7:0]),   .out_byte(sub_w[s][7:0]));
			  end
		 endgenerate
	 
		 // -------------------------------------------------------------------------
		 // Key schedule: generate W[4] through W[43]
		 // -------------------------------------------------------------------------
		 genvar i;
		 generate
			  for (i = 4; i < 44; i = i + 1) begin : KEY_SCHED
					if (i % 4 == 0) begin
						 // sub_w array index = (i/4) - 1  maps i=4->0, i=8->1, ... i=40->9
						 assign W[i] = W[i-4] ^ sub_w[(i/4) - 1] ^ rcon(i/4);
					end else begin
						 assign W[i] = W[i-4] ^ W[i-1];
					end
			  end
		 endgenerate
	 

    // -------------------------------------------------------------------------
    // Pack round keys into the output bus
    // RoundKey[n] = {W[4n], W[4n+1], W[4n+2], W[4n+3]}
    // Output order: RoundKey[0] at MSBs (bits 1407:1280) down to
    //               RoundKey[10] at LSBs (bits 127:0)
    // -------------------------------------------------------------------------
    genvar k;
    generate
        for (k = 0; k <= 10; k = k + 1) begin : PACK_KEYS
            assign round_key_out[(10-k)*128 +: 128] =
                { W[4*k], W[4*k+1], W[4*k+2], W[4*k+3] };
        end
    endgenerate

endmodule