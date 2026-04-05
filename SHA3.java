
public class SHA3 {
	 private static long[][] A;

	    public static long[][]SHA3State() {
	        A = new long[5][5]; // state with just zeros 
	        return A;
	    }
	 public static byte[] pad(byte[] message, int rateBytes) {
	        int messageLen = message.length;

	        // Compute padding length
	        int padLen = rateBytes - (messageLen % rateBytes);
	        if (padLen == 0) {
	            padLen = rateBytes;
	        }

	        byte[] padded = new byte[messageLen + padLen];

	        // Copy original message
	        System.arraycopy(message, 0, padded, 0, messageLen);

	        // SHA-3 domain separation + padding
	        padded[messageLen] = 0x06;  // 0b00000110

	        // Last byte: set MSB to 1 (final '1' bit of pad10*1)
	        padded[padded.length - 1] |= 0x80;

	        return padded;
	    }
}
