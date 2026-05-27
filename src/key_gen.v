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

// `timescale 1ns / 1ps

// =============================================================================
// key_gen.v  –  AES-128 Key Expansion (KeySchedule, sequential/clocked version)
// =============================================================================

// =============================================================================
// key_gen.v  –  AES-128 Key Expansion (KeySchedule) – Sequential/Clocked Version
// =============================================================================

`default_nettype none
module key_gen (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        load_key,           // pulse high to (re)load key_in
    input  wire [127:0] key_in,
    output reg  [1407:0] round_key_out,     // 11 × 128 bits
    output reg           keys_ready        // high for one cycle when done
);

    // -------------------------------------------------------------------------
    // Internal word array  W[0..43]  (44 words × 32 bits)
    // -------------------------------------------------------------------------
    reg [31:0] W [0:43];
    integer i;

    // Rcon function
    function [31:0] rcon;
        input integer rnd;
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

    // RotWord
    function [31:0] rot_word;
        input [31:0] w;
        begin
            rot_word = {w[23:0], w[31:24]};
        end
    endfunction

    // Combinational SubWord (S-box) expansion for a 32-bit word
    function [31:0] sub_word;
        input [31:0] w;
        begin
            sub_word[31:24] = sbox(w[31:24]);
            sub_word[23:16] = sbox(w[23:16]);
            sub_word[15:8]  = sbox(w[15:8]);
            sub_word[7:0]   = sbox(w[7:0]);
        end
    endfunction

    // Sbox lookup table interface (replace this stub as needed)
    function [7:0] sbox;
        input [7:0] b;
        begin
            // You should connect this to your S-box implementation
            sbox = b; // <- Replace with your actual S-box logic
        end
    endfunction

    // Sequential logic for key expansion
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (i = 0; i < 44; i = i + 1) W[i] <= 32'd0;
            round_key_out <= 1408'd0;
            keys_ready    <= 1'b0;
        end else if (load_key) begin
            // Seed first four words from key_in
            W[0] <= key_in[127:96];
            W[1] <= key_in[95:64];
            W[2] <= key_in[63:32];
            W[3] <= key_in[31:0];

            // Key expansion loop
            for (i = 4; i < 44; i = i + 1) begin
                if (i % 4 == 0) begin
                    W[i] <= W[i-4] ^ sub_word(rot_word(W[i-1])) ^ rcon(i/4);
                end else begin
                    W[i] <= W[i-4] ^ W[i-1];
                end
            end

            // Pack round keys into output
            for (i = 0; i <= 10; i = i + 1) begin
                round_key_out[(10-i)*128 +: 128] <= { W[4*i], W[4*i+1], W[4*i+2], W[4*i+3] };    
            end
            
            keys_ready <= 1'b1; // signal that round keys are ready
        end else begin
            keys_ready <= 1'b0; // clear ready signal until next load
        end
    end

endmodule