public class AES {

	// AES-256 S-Box lookup table (used in SubBytes transformation)
	private static final int[] SBOX = {
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	};

	// Round constants used in the AES key schedule (Rcon)
	private static final int[] RCON = {
		0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
	};

	// -----------------------------
	// Key schedule helper functions
	// -----------------------------

	// Rotates a 32-bit word left by 8 bits (one byte)
	private static int rotWord(int word) {
		return (word << 8) | (word >>> 24);
	}

	// Applies S-Box substitution to each byte of a 32-bit word
	private static int subWord(int word) {
		return (SBOX[(word >>> 24) & 0xFF] << 24) |
			   (SBOX[(word >>> 16) & 0xFF] << 16) |
			   (SBOX[(word >>> 8) & 0xFF] << 8) |
			   (SBOX[word & 0xFF]);
	}

	// Expands a 32-byte AES-256 key into 240 bytes (60 words)
	public static byte[] expandKey(byte[] key) {

		int[] words = new int[60];

		// Load initial 256-bit key into first 8 words
		for (int i = 0; i < 8; i++) {
			words[i] =
				((key[i * 4] & 0xFF) << 24) |
				((key[i * 4 + 1] & 0xFF) << 16) |
				((key[i * 4 + 2] & 0xFF) << 8) |
				(key[i * 4 + 3] & 0xFF);
		}

		// Expand remaining words
		for (int i = 8; i < 60; i++) {
			int temp = words[i - 1];

			// Every 8th word: apply key schedule core
			if (i % 8 == 0) {
				temp = subWord(rotWord(temp)) ^ (RCON[i / 8] << 24);

			// Every 4th word: apply S-Box only
			} else if (i % 8 == 4) {
				temp = subWord(temp);
			}

			words[i] = words[i - 8] ^ temp;
		}

		// Convert words back into byte array
		byte[] expanded = new byte[240];

		for (int i = 0; i < 60; i++) {
			expanded[i * 4]     = (byte) (words[i] >>> 24);
			expanded[i * 4 + 1] = (byte) (words[i] >>> 16);
			expanded[i * 4 + 2] = (byte) (words[i] >>> 8);
			expanded[i * 4 + 3] = (byte) (words[i]);
		}

		return expanded;
	}

	// -----------------------------
	// AES block encryption
	// -----------------------------

	// Encrypts a single 16-byte block using AES-256
	public static byte[] encryptBlock(byte[] block, byte[] expanded) {

		byte[] state = new byte[16];

		// Copy input block into state array
		System.arraycopy(block, 0, state, 0, 16);

		// Initial round key addition
		addRoundKey(state, expanded, 0);

		// Main rounds (13 rounds for AES-256)
		for (int round = 1; round < 14; round++) {
			subBytes(state);
			shiftRows(state);
			mixColumns(state);
			addRoundKey(state, expanded, round);
		}

		// Final round (no MixColumns)
		subBytes(state);
		shiftRows(state);
		addRoundKey(state, expanded, 14);

		return state;
	}

	// SubBytes step: substitutes each byte using S-Box
	private static void subBytes(byte[] state) {
		for (int i = 0; i < 16; i++) {
			state[i] = (byte) SBOX[state[i] & 0xFF];
		}
	}

	// ShiftRows step: cyclically shifts rows of the AES state
	private static void shiftRows(byte[] state) {

		byte temp;

		// Row 1 shift
		temp = state[1];
		state[1] = state[5];
		state[5] = state[9];
		state[9] = state[13];
		state[13] = temp;

		// Row 2 shift (2-step rotation)
		temp = state[2];
		state[2] = state[10];
		state[10] = temp;

		temp = state[6];
		state[6] = state[14];
		state[14] = temp;

		// Row 3 shift (3-step rotation)
		temp = state[3];
		state[3] = state[7];
		state[7] = state[11];
		state[11] = state[15];
		state[15] = temp;
	}

	// Galois Field multiplication by 2
	private static byte mul2(int b) {
		int x = b & 0xFF;
		x = (x << 1) ^ ((x & 0x80) != 0 ? 0x1B : 0);
		return (byte) x;
	}

	// Galois Field multiplication by 3 (2x + x)
	private static byte mul3(int b) {
		int x = b & 0xFF;
		return (byte) (mul2(x) ^ x);
	}

	// MixColumns transformation (matrix multiplication in GF(2^8))
	private static void mixColumns(byte[] state) {

		for (int c = 0; c < 4; c++) {

			int i = c * 4;

			int s0 = state[i] & 0xFF;
			int s1 = state[i + 1] & 0xFF;
			int s2 = state[i + 2] & 0xFF;
			int s3 = state[i + 3] & 0xFF;

			state[i]     = (byte) (mul2(s0) ^ mul3(s1) ^ s2 ^ s3);
			state[i + 1] = (byte) (s0 ^ mul2(s1) ^ mul3(s2) ^ s3);
			state[i + 2] = (byte) (s0 ^ s1 ^ mul2(s2) ^ mul3(s3));
			state[i + 3] = (byte) (mul3(s0) ^ s1 ^ s2 ^ mul2(s3));
		}
	}

	// XORs state with round key
	private static void addRoundKey(byte[] state, byte[] key, int round) {
		int offset = round * 16;

		for (int i = 0; i < 16; i++) {
			state[i] ^= key[offset + i];
		}
	}

	// -----------------------------
	// CTR mode stream encryption
	// -----------------------------

	// Encrypt/decrypt using AES in CTR mode
	public static byte[] processCTR(byte[] input, byte[] key, byte[] counter) {

		if (counter.length != 16) {
			throw new IllegalArgumentException("Counter must be 16 bytes");
		}

		byte[] expandedKey = expandKey(key);
		byte[] output = new byte[input.length];

		byte[] keystream = new byte[16];
		byte[] ctr = new byte[16];

		System.arraycopy(counter, 0, ctr, 0, 16);

		for (int i = 0; i < input.length; i++) {

			if (i % 16 == 0) {
				keystream = encryptBlock(ctr, expandedKey);
				incrementCounter(ctr);
			}

			output[i] = (byte) (input[i] ^ keystream[i % 16]);
		}

		return output;
	}

	// Increments 128-bit counter (big-endian)
	public static void incrementCounter(byte[] counter) {
		for (int i = 15; i >= 0; i--) {
			counter[i]++;
			if (counter[i] != 0) break;
		}
	}
}
