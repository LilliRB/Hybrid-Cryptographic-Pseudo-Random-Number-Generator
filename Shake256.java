public class Shake256 {

    // 5x5 Keccak state array (1600-bit internal state total)
    private static long[][] state = new long[5][5];

    // Rate portion of sponge function (r = 1088 bits = 136 bytes)
    private static final int RATE = 136;

    // Capacity portion (c = 512 bits = 64 bytes)
    @SuppressWarnings("unused")
    private static final int CAPACITY = 64;

    // Tracks whether the sponge is still in absorbing phase
    private static boolean absorbing = true;

    // Tracks how many bytes have been squeezed from current block
    private static int squeezeIndex = 0;

    // SHAKE256 domain separation constant (per NIST FIPS 202)
    private static final byte SHAKE_DOMAIN = 0x1F;

    // Keccak-f[1600] round constants (24 rounds total)
    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L,
        0x800000000000808AL, 0x8000000080008000L,
        0x000000000000808BL, 0x0000000080000001L,
        0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008AL, 0x0000000000000088L,
        0x0000000080008009L, 0x000000008000000AL,
        0x000000008000808BL, 0x800000000000008BL,
        0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L,
        0x000000000000800AL, 0x800000008000000AL,
        0x8000000080008081L, 0x8000000000008080L,
        0x0000000080000001L, 0x8000000080008008L
    };

    /**
     * Initializes the SHAKE256 sponge with a seed.
     * Performs absorption, padding, and first permutation.
     */
    public static void init(byte[] seed) {
        clearState();
        absorbing = true;

        // Absorb input seed into state
        absorb(seed);

        // Apply SHAKE padding (domain separation + pad10*1 rule)
        applySHAKEPadding();

        // First Keccak permutation
        keccakF(state);

        // Switch to squeezing phase
        absorbing = false;
        squeezeIndex = 0;
    }

    //Reinitializes sponge with new entropy.
    public static void reseed(byte[] entropy) {
        init(entropy);
    }

    /**
     * Generates pseudorandom output bytes.
     * Expands state using Keccak-f when rate is exhausted.
     */
    public static byte[] nextBytes(int len) {

        if (absorbing) {
            throw new IllegalStateException("SHAKE256 not initialized. Call init() first.");
        }

        byte[] out = new byte[len];
        int pos = 0;

        while (pos < len) {

            byte[] block = squeezeBlock();

            int take = Math.min(block.length, len - pos);
            System.arraycopy(block, 0, out, pos, take);

            pos += take;
            squeezeIndex += take;

            // If current rate block is fully consumed, permute state again
            if (squeezeIndex >= RATE) {
                keccakF(state);
                squeezeIndex = 0;
            }
        }

        return out;
    }

    // =========================
    // Sponge construction
    // =========================

    /**
     * Absorbs input bytes into the Keccak state.
     * Each 8-byte chunk maps into one 64-bit lane.
     */
    private static void absorb(byte[] input) {

        int laneIndex = 0;

        for (int i = 0; i < input.length; i += 8) {

            if (laneIndex >= RATE / 8) break;

            int x = laneIndex % 5;
            int y = laneIndex / 5;

            long lane = 0;

            for (int j = 0; j < 8 && i + j < input.length; j++) {
                lane |= ((long)(input[i + j] & 0xFF)) << (8 * j);
            }

            // XOR absorbed data into state
            state[x][y] ^= lane;
            laneIndex++;
        }
    }

    /**
     * Applies SHAKE padding:
     * - domain separation (0x1F)
     * - pad10*1 rule (final bit set)
     */
    private static void applySHAKEPadding() {

        int x = (RATE / 8) % 5;
        int y = (RATE / 8) / 5;

        // Domain separation marker (SHAKE256)
        state[x][y] ^= (long) SHAKE_DOMAIN;

        // Final padding bit (pad10*1 rule)
        int lastIndex = (RATE / 8) - 1;
        int lx = lastIndex % 5;
        int ly = lastIndex / 5;

        state[lx][ly] ^= 0x8000000000000000L;
    }

    // Extracts a full rate-sized block from the state.
    private static byte[] squeezeBlock() {

        byte[] out = new byte[RATE];
        int idx = 0;

        for (int y = 0; y < 5 && idx < RATE; y++) {
            for (int x = 0; x < 5 && idx < RATE; x++) {

                long lane = state[x][y];

                for (int i = 0; i < 8 && idx < RATE; i++) {
                    out[idx++] = (byte)(lane >>> (8 * i));
                }
            }
        }

        return out;
    }

    // =========================
    // Keccak-f permutation (F1600)
    // =========================

    private static void keccakF(long[][] A) {
        for (int i = 0; i < 24; i++) {
            theta(A);
            rho(A);
            pi(A);
            chi(A);
            iota(A, i);
        }
    }

    //Theta step: mixes columns to achieve diffusion.
    
    private static void theta(long[][] A) {

        long[] C = new long[5];
        long[] D = new long[5];

        for (int x = 0; x < 5; x++) {
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4];
        }

        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ Long.rotateLeft(C[(x + 1) % 5], 1);
        }

        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                A[x][y] ^= D[x];
            }
        }
    }

    // Rho step: rotates each lane by fixed offsets.
    private static void rho(long[][] A) {

        int[][] R = {
            {0, 36, 3, 41, 18},
            {1, 44, 10, 45, 2},
            {62, 6, 43, 15, 61},
            {28, 55, 25, 21, 56},
            {27, 20, 39, 8, 14}
        };

        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                A[x][y] = Long.rotateLeft(A[x][y], R[x][y]);
            }
        }
    }

    
     // Pi step: permutes lane positions across the state.
    private static void pi(long[][] A) {

        long[][] B = new long[5][5];

        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                B[y][(2 * x + 3 * y) % 5] = A[x][y];
            }
        }

        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                A[x][y] = B[x][y];
            }
        }
    }

    // Chi step: introduces non-linearity per row.
    private static void chi(long[][] A) {

        long[][] B = new long[5][5];

        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                B[x][y] = A[x][y] ^ ((~A[(x + 1) % 5][y]) & A[(x + 2) % 5][y]);
            }
        }

        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                A[x][y] = B[x][y];
            }
        }
    }

    // Iota step: injects round constant into state.
    private static void iota(long[][] A, int round) {
        A[0][0] ^= RC[round];
    }

    // Clears Keccak state to all zeros.
    private static void clearState() {
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                state[x][y] = 0;
            }
        }
    }
}
