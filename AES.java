public class AES {

	// Standard AES S-Box array, all values are in order 0x00-0xFF (decimal index 0
	// through 255)
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

	// The hardcoded Round Constant array. Index 0 = 0x00 (padding for natural i/8
	// operation)
	private static final int[] RCON = {
			0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
	};

	// Left circular shift for rotation. Shifts 4 bytes of a word to the left,
	// kicking out the first byte
	// Separately, the first byte is then moved to the last byte position. The
	// results are combined using bitwise OR.
	// [0x12345678] -> [0x34567812]
	private static int rotWord(int word) {
		return (word << 8) | (word >>> 24);
	}

	// Parses each of the 4 bytes of a word through the S-Box, then combines the
	// results into a single 32-bit word.
	// By using a shift and bitmask, we can isolate each byte and pass it through
	// the S-Box.
	// The results are then shifted back to their original bit positions and
	// combined using bitwise OR.
	private static int subWord(int word) {
		int b0 = SBOX[(word >>> 24) & 0xFF];
		int b1 = SBOX[(word >>> 16) & 0xFF];
		int b2 = SBOX[(word >>> 8) & 0xFF];
		int b3 = SBOX[word & 0xFF];

		return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
	}

	// The core export function, expanding 32 bytes to 240 bytes.
	public static byte[] expandKey(byte[] masterKey) {

		// Input validation for master key
		if (masterKey == null || masterKey.length != 32) {
			throw new IllegalArgumentException("Master key must be exactly 32 bytes for AES-256.");
		}

		// Initialize the expanded key array with 60 words (240 bytes) needed for all
		// rounds
		int[] words = new int[60];

		// Copy the master key into the first 8 words (index 0-7) of the expanded key
		// array "words"
		// Since the master key comes in as bytes, we need to convert it to words (4
		// bytes each)
		// For each group of 4 bytes in the master key (0-3, 4-7, ... 28-31), apply left
		// shifts to ensure proper word alignment
		// Once aligned, the bytes are combined into a single 32-bit word using bitwise
		// OR
		for (int i = 0; i < 8; i++) {
			int word = ((masterKey[i * 4] & 0xFF) << 24) |
					((masterKey[i * 4 + 1] & 0xFF) << 16) |
					((masterKey[i * 4 + 2] & 0xFF) << 8) |
					((masterKey[i * 4 + 3] & 0xFF));
			words[i] = word;
		}

		// Generate the remaining 52 words (index 8-59) of the expanded key
		// Introduce 'twists' to key schedule to ensure diffusion and non-linear
		// properties
		// For every 8 words (every time the key length Nk is iterated through), apply
		// the primary twist
		// For every 4th word of each Nk iteration, apply the secondary twist (Special
		// for AES-256)
		// For all other words, only apply the standard XOR operation
		// All twists are standard operations defined in FIPS 197
		for (int i = 8; i < 60; i++) {
			int temp = words[i - 1];

			if (i % 8 == 0) {
				temp = subWord(rotWord(temp)) ^ (RCON[i / 8] << 24);
			} else if (i % 8 == 4) {
				temp = subWord(temp);
			}

			words[i] = words[i - 8] ^ temp;
		}

		// Convert int array 'words' back to byte array, making sure the return type of
		// the function matches the input type of the master key
		// This is done by taking each word and splitting them into 4 bytes via bitwise
		// right shifts and masking, ending with a type cast to byte
		// Bytes from words are stored in big-endian format for the whole expanded key
		byte[] expandedKey = new byte[240];
		for (int i = 0; i < 60; i++) {
			expandedKey[i * 4] = (byte) ((words[i] >>> 24) & 0xFF);
			expandedKey[i * 4 + 1] = (byte) ((words[i] >>> 16) & 0xFF);
			expandedKey[i * 4 + 2] = (byte) ((words[i] >>> 8) & 0xFF);
			expandedKey[i * 4 + 3] = (byte) ((words[i]) & 0xFF);
		}

		return expandedKey;
	}

	// -------------------------------------------------------------------------
	// AES-256 Block Encryption Primitives
	// -------------------------------------------------------------------------

	// Applies the S-Box substitution to each of the 16 bytes in the state array.
	private static void subBytes(byte[] state) {
		for (int i = 0; i < 16; i++) {
			state[i] = (byte) SBOX[state[i] & 0xFF];
		}
	}

	// Performs the ShiftRows operation by cyclically shifting the bytes in the last
	// three rows
	// of the 4x4 state matrix. The state array operates in column-major order.
	// Columns are logically followed by stepping through the array 4 bytes at a
	// time
	// - Row 0 (indices 0, 4, 8, 12) is not shifted.
	// - Row 1 (indices 1, 5, 9, 13) is shifted left by 1 position.
	// - Row 2 (indices 2, 6, 10, 14) is shifted left by 2 positions.
	// - Row 3 (indices 3, 7, 11, 15) is shifted left by 3 positions.
	private static void shiftRows(byte[] state) {
		byte temp;

		// Row 1: Shift left by 1
		temp = state[1];
		state[1] = state[5];
		state[5] = state[9];
		state[9] = state[13];
		state[13] = temp;

		// Row 2: Shift left by 2
		temp = state[2];
		state[2] = state[10];
		state[10] = temp;
		temp = state[6];
		state[6] = state[14];
		state[14] = temp;

		// Row 3: Shift left by 3 (or right by 1)
		temp = state[15];
		state[15] = state[11];
		state[11] = state[7];
		state[7] = state[3];
		state[3] = temp;
	}

	// Helper for Galois Field multiplication by 2
	// Through the binary representaion of the value, we can perform multiplication
	// by 2
	// This is done by left shifting the value by 1
	// If the most significant bit is 1, a left shift by 1 would result in a value
	// greater than 255
	// In this case, we need to XOR the result with 0x11B (the irreducible
	// polynomial for GF(2^8))
	// to bring it back into the field
	private static byte mul2(int b) {
		int bInt = b & 0xFF;
		return (byte) ((bInt << 1) ^ ((bInt & 0x80) != 0 ? 0x11B : 0));
	}

	// Helper for Galois Field multiplication by 3
	// Since 3 = 2 + 1, we can perform multiplication by 3 by multiplying by 2 and
	// XORing the result with the original value
	private static byte mul3(int b) {
		int bInt = b & 0xFF;
		return (byte) (mul2(bInt) ^ bInt);
	}

	// Mixes the columns of the state matrix. Each column is operated on
	// independently using Galois Field mathematics.
	// Despite being a 1d array, the state array is treated as a 4x4 matrix
	// Operations are performed on each column independently by splitting the loop
	// into 4 separate stages
	// The matrix multiplication is as follows:
	// [02 03 01 01]
	// [01 02 03 01]
	// [01 01 02 03]
	// [03 01 01 02]
	// This operation is performed on each column independently by iterating through
	// the columns
	// and applying the matrix multiplication to each column
	private static void mixColumns(byte[] state) {
		for (int c = 0; c < 4; c++) {
			int i = c * 4;
			int s0 = state[i] & 0xFF;
			int s1 = state[i + 1] & 0xFF;
			int s2 = state[i + 2] & 0xFF;
			int s3 = state[i + 3] & 0xFF;

			state[i] = (byte) (mul2(s0) ^ mul3(s1) ^ s2 ^ s3);
			state[i + 1] = (byte) (s0 ^ mul2(s1) ^ mul3(s2) ^ s3);
			state[i + 2] = (byte) (s0 ^ s1 ^ mul2(s2) ^ mul3(s3));
			state[i + 3] = (byte) (mul3(s0) ^ s1 ^ s2 ^ mul2(s3));
		}
	}

	// XORs the 16-byte state with the 16-byte round key extracted from the
	// expanded key array.
	// The round key is extracted from the expanded key array by taking the
	// bytes from the expanded key array starting from the offset
	// The offset is calculated by multiplying the round number by 16
	private static void addRoundKey(byte[] state, byte[] expandedKey, int round) {
		int offset = round * 16;
		for (int i = 0; i < 16; i++) {
			state[i] = (byte) (state[i] ^ expandedKey[offset + i]);
		}
	}

	// The primary AES block encryption function.
	// Takes a 16-byte plaintext chunk and the 240-byte expanded key.
	public static byte[] encryptBlock(byte[] block, byte[] expandedKey) {
		if (block.length != 16) {
			throw new IllegalArgumentException("AES block size must be exactly 16 bytes.");
		}

		// Create a copy of the block to work with
		// Throughout the AES implementation, this is where the state array is loaded
		// from the block
		// and then modified throughout the rounds
		byte[] state = new byte[16];
		System.arraycopy(block, 0, state, 0, 16);

		// Initial Round
		addRoundKey(state, expandedKey, 0);

		// 13 Main Rounds for AES-256
		for (int round = 1; round < 14; round++) {
			subBytes(state);
			shiftRows(state);
			mixColumns(state);
			addRoundKey(state, expandedKey, round);
		}

		// Final 14th Round (Omits MixColumns)
		subBytes(state);
		shiftRows(state);
		addRoundKey(state, expandedKey, 14);

		return state;
	}
	// -------------------------------------------------------------------------
	// CTR Mode Implementation
	// -------------------------------------------------------------------------

	// Treats the entire 16-byte array as a single 128-bit big-endian integer.
	// Increments the count by 1. Carries over to the next byte if the current byte
	// overflows (reaches 0).
	private static void incrementCounter(byte[] counter) {
		for (int i = 15; i >= 0; i--) {
			counter[i]++;
			// If it did not roll over to 0, no carry is required, we can break.
			if (counter[i] != 0) {
				break;
			}
		}
	}

	// The primary export function for stream encryption/decryption in CTR mode.
	// CTR mode XORs the generated keystream with the input, thus encryption and
	// decryption are technically the same operation.
	public static byte[] processCTR(byte[] input, byte[] masterKey, byte[] initialCounter) {
		if (masterKey == null || masterKey.length != 32) {
			throw new IllegalArgumentException("Master key must be exactly 32 bytes for AES-256.");
		}
		if (initialCounter == null || initialCounter.length != 16) {
			throw new IllegalArgumentException("Initial counter must be exactly 16 bytes.");
		}
		if (input == null) {
			return new byte[0];
		}

		byte[] expandedKey = expandKey(masterKey);
		byte[] counter = new byte[16];
		System.arraycopy(initialCounter, 0, counter, 0, 16);

		byte[] output = new byte[input.length];
		byte[] keystreamBlock = new byte[16];

		for (int i = 0; i < input.length; i++) {
			if (i % 16 == 0) {
				keystreamBlock = encryptBlock(counter, expandedKey);
				incrementCounter(counter);
			}
			output[i] = (byte) (input[i] ^ keystreamBlock[i % 16]);
		}

		return output;
	}
}
