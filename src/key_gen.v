// =============================================================================
// key_gen.v  —  AES-128 key schedule with full round-key storage
//
// After a one-cycle `start` pulse the module expands key_in into
// RK0..RK10 over 10 clock cycles, then asserts `ready`.
//
// Two combinational read ports (idx_a / idx_b → key_a / key_b) let the
// pipeline fetch any two round keys simultaneously in the same cycle.
// =============================================================================

`default_nettype none

module key_gen (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,       // one-cycle pulse; latches key_in as RK0

    input  wire [127:0] key_in,

    // Dual read ports — combinational, valid as soon as ready=1
    input  wire [3:0]   idx_a,       // index 0-10
    input  wire [3:0]   idx_b,       // index 0-10
    output wire [127:0] key_a,       // rk[idx_a]
    output wire [127:0] key_b,       // rk[idx_b]

    output reg          ready        // high when all 11 keys are valid
);

    // -------------------------------------------------------------------------
    // Round-key register bank: RK0 .. RK10
    // -------------------------------------------------------------------------
    reg [127:0] rk [0:10];

    // Dual combinational read
    assign key_a = rk[idx_a];
    assign key_b = rk[idx_b];

    // -------------------------------------------------------------------------
    // Expansion sequencer state
    // -------------------------------------------------------------------------
    reg [3:0] exp_cnt;    // 0..9 — index of the key we are expanding FROM
    reg       expanding;

    // -------------------------------------------------------------------------
    // Combinational next-key derivation from rk[exp_cnt]
    // (stable before the clock edge because exp_cnt and rk[] are registered)
    // -------------------------------------------------------------------------
    wire [31:0] ew0 = rk[exp_cnt][127:96];
    wire [31:0] ew1 = rk[exp_cnt][95:64];
    wire [31:0] ew2 = rk[exp_cnt][63:32];
    wire [31:0] ew3 = rk[exp_cnt][31:0];

    // RotWord(w3)
    wire [31:0] erot_w = {ew3[23:0], ew3[31:24]};

    // SubWord(RotWord(w3))
    wire [31:0] esub_w;
    sbox esb0 (.in_byte(erot_w[31:24]), .out_byte(esub_w[31:24]));
    sbox esb1 (.in_byte(erot_w[23:16]), .out_byte(esub_w[23:16]));
    sbox esb2 (.in_byte(erot_w[15: 8]), .out_byte(esub_w[15: 8]));
    sbox esb3 (.in_byte(erot_w[ 7: 0]), .out_byte(esub_w[ 7: 0]));

    // Rcon — indexed by round number 1..10
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

    // Next-key words:  RK[n+1] = f(RK[n])
    // rcon round number = exp_cnt + 1  (expanding RK[exp_cnt] → RK[exp_cnt+1])
    wire [31:0] enw0 = ew0 ^ esub_w ^ rcon(exp_cnt + 1'b1);
    wire [31:0] enw1 = ew1 ^ enw0;
    wire [31:0] enw2 = ew2 ^ enw1;
    wire [31:0] enw3 = ew3 ^ enw2;

    wire [127:0] next_rk = {enw0, enw1, enw2, enw3};

    // -------------------------------------------------------------------------
    // Sequential logic
    // -------------------------------------------------------------------------
    integer i;

    always @(posedge clk) begin
        if (!rst_n) begin
            expanding <= 1'b0;
            ready     <= 1'b0;
            exp_cnt   <= 4'd0;
            for (i = 0; i <= 10; i = i + 1)
                rk[i] <= 128'd0;
        end

        // Latch RK0 and kick off expansion
        else if (start) begin
            rk[0]     <= key_in;
            expanding <= 1'b1;
            ready     <= 1'b0;
            exp_cnt   <= 4'd0;
        end

        // Expand one key per cycle: rk[exp_cnt] → rk[exp_cnt+1]
        else if (expanding) begin
            rk[exp_cnt + 4'd1] <= next_rk;
            if (exp_cnt == 4'd9) begin
                expanding <= 1'b0;
                ready     <= 1'b1;   // RK0..RK10 all valid
            end
            exp_cnt <= exp_cnt + 1'b1;
        end
    end

endmodule
