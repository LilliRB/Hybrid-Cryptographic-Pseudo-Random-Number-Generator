import java.util.Scanner;
import java.math.BigInteger;

public class Main {

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        byte[] seed = new byte[32];
        new java.security.SecureRandom().nextBytes(seed);

        CSPRNG rng = new CSPRNG(seed);

        while (true) {

            System.out.print("\nHow many bytes (0 to exit)? ");
            int len = sc.nextInt();

            if (len <= 0) {
                System.out.println("Exit.");
                break;
            }

            // =========================
            // generate data
            // =========================
            byte[] data = new byte[len];
            rng.nextBytes(data);

            // =========================
            // 1. RAW BYTES
            // =========================
            System.out.println("\n--- RAW BYTES ---");
            printBytes(data);

            // =========================
            // 2. HEX OUTPUT
            // =========================
            System.out.println("\n--- HEX ---");
            System.out.println(toHex(data));

            // =========================
            // 3. DECIMAL (BigInteger)
            // =========================
            System.out.println("\n--- DECIMAL ---");
            BigInteger value = new BigInteger(1, data);
            System.out.println(value.toString());
        }

        sc.close();
    }

    // helpers

    private static void printBytes(byte[] data) {
        for (byte b : data) {
            System.out.print((b & 0xFF) + " ");
        }
        System.out.println();
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}