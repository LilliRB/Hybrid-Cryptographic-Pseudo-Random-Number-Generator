import java.security.SecureRandom;

public class CPRNG {

    // 256-bit AES key derived from SHAKE256 output
    private final byte[] key = new byte[32];

    // 128-bit IV used as the AES-CTR initial counter value
    private final byte[] iv = new byte[16];

    // Internal counter used to ensure unique input blocks per call
    private long counter = 0;

    // =========================
    // INITIALIZATION
    // =========================

    /**
     * Creates a CPRNG instance and immediately seeds it.
     */
    public CPRNG(byte[] seed) {
        reseed(seed);
    }

    // =========================
    // RESEED USING SHAKE256
    // =========================

    /**
     * Reseeds the generator using SHAKE256 as a KDF.
     *
     * The input seed is expanded into:
     * - 32-byte AES key
     * - 16-byte IV (initial counter value)
     */
    public final void reseed(byte[] seed) {

        // Initialize SHAKE256 sponge with provided entropy
        Shake256.init(seed);

        // Extract 48 bytes of derived key material
        byte[] material = Shake256.nextBytes(48);

        // Split into AES key and IV
        System.arraycopy(material, 0, key, 0, 32);
        System.arraycopy(material, 32, iv, 0, 16);

        // Reset internal counter state
        counter = 0;
    }

    // =========================
    // RANDOM OUTPUT GENERATION
    // =========================

    /**
     * Generates pseudorandom bytes using AES-CTR mode.
     *
     * A monotonically increasing counter is used to ensure
     * each encryption block input is unique.
     */
    public byte[] nextBytes(int len) {

        byte[] input = new byte[len];

        // Fill input with counter-derived values to guarantee uniqueness
        for (int i = 0; i < len; i++) {
            input[i] = (byte) (counter++);
        }

        // Encrypt using custom AES-CTR implementation
        return AES.processCTR(input, key, iv);
    }

    // =========================
    // FACTORY METHOD
    // =========================

    /**
     * Creates a CPRNG instance seeded from system entropy.
     */
    public static CPRNG create() {
        SecureRandom sr = new SecureRandom();

        byte[] seed = new byte[32];
        sr.nextBytes(seed);

        return new CPRNG(seed);
    }
}