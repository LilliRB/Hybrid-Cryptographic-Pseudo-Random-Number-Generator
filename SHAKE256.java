
public class SHAKE256 {
	private long state[][] = new long [5][5];
    private byte[] squeezeBuffer;//capacity
    private int squeezeIndex = 0;
	//rate = 200-capacity
	//capacity = 64
	private int rate = 136;
	private byte Domain = 0X1F;
	//State slate at all 0 
	private void cleanState(long[][]state) {
		for(int i=0;i<5;i++) {
			for(int j=0;j<5;j++) {
				state[i][j]=0;
			}
		}
	}
	//Padding to make the input divisible by rate
	private byte[] padding(byte[] input) {
	    int padLen = rate - (input.length % rate);
	    if (padLen == 0) padLen = rate;

	    byte[] out = new byte[input.length + padLen];

	    // write input once
	    System.arraycopy(input, 0, out, 0, input.length);

	    // write padding directly
	    out[input.length] = Domain;
	    out[out.length - 1] |= (byte) 0x80;

	    return out;
	}

		   public void absorb(byte[] input) {
		        cleanState(state);
		        byte[] padded = padding(input);

		        for (int offset = 0; offset < padded.length; offset += rate) {

		            for (int i = 0; i < rate; i += 8) {
		                long lane = 0;

		                for (int b = 0; b < 8; b++) {
		                    lane |= ((long) padded[offset + i + b] & 0xFF) << (8 * b);
		                }

		                int laneIndex = i / 8;
		                int x = laneIndex % 5;
		                int y = laneIndex / 5;

		                state[x][y] ^= lane;
		            }

		            keccakF(state);
		        }


	}
	private void keccakF(long [][]state){
		for(int i=0;i<24;i++) {
		theta(state);
		rho(state);
		pi(state);
		chi(state);
		iota(state,i);
		}
	}
	private static long rotl(long x, int n) {
	    return (x << n) | (x >>> (64 - n));
	}
	//Mix each column with parity information from all other columns
	private void theta(long [][] state) {
	    long[] C = new long[5];
	    long[] D = new long[5];

	    // Step 1: column parity
	    for (int x = 0; x < 5; x++) {
	        C[x] = 0;
	        for (int y = 0; y < 5; y++) {
	            C[x] ^= state[x][y];
	        }
	    }

	    // Step 2: compute D
	    for (int x = 0; x < 5; x++) {
	        D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
	    }

	    // Step 3: apply to state
	    for (int x = 0; x < 5; x++) {
	        for (int y = 0; y < 5; y++) {
	            state[x][y] ^= D[x];
	        }
	    }
	}
    //rotates each lane by a fixed offset
	private void rho(long [][] state) {
		//Triangle numbers so the bits move diagonally through the state
		final int[][] RHO = {
			    {0,  36, 3,  41, 18},
			    {1,  44, 10, 45, 2},
			    {62, 6,  43, 15, 61},
			    {28, 55, 25, 21, 56},
			    {27, 20, 39, 8,  14}
			};
		  for (int x = 0; x < 5; x++) {
		        for (int y = 0; y < 5; y++) {
		            state[x][y] = rotl(state[x][y], RHO[x][y]);
		        }
		    }
		
	}
	//changes around the lane positions 
	private void pi(long [][] state) {
		  long[][] A = new long[5][5];
		  //Changing position 
		    for (int x = 0; x < 5; x++) {
		        for (int y = 0; y < 5; y++) {
		            A[y][(2 * x + 3 * y) % 5] = state[x][y];
		        }
		    }

		    // copying back
		    for (int x = 0; x < 5; x++) {
		        for (int y = 0; y < 5; y++) {
		            state[x][y] = A[x][y];
		        }
		    }
		
	}
	//It mixes bits inside each row using logic operations (AND + XOR)
	private void chi(long [][] state) {
	    long[][] A = new long[5][5];
	    //Mixing bits 
	    for (int y = 0; y < 5; y++) {
	        for (int x = 0; x < 5; x++) {
	            long current = state[x][y];
	            long next = state[(x + 1) % 5][y];
	            long next2 = state[(x + 2) % 5][y];

	            A[x][y] = current ^ ((~next) & next2);
	        }
	    }

	    // copy back
	    for (int x = 0; x < 5; x++) {
	        for (int y = 0; y < 5; y++) {
	            state[x][y] = A[x][y];
	        }
	    }
	}
	//XOR a round constant into one lane
	private void iota(long [][]state, int round) {
		final long[] RC = {
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
		 state[0][0] ^= RC[round];
	}
	public byte[] squeeze(int length) {
	    byte[] out = new byte[length];
	    int produced = 0;

	    while (produced < length) {

	        if (squeezeBuffer == null) {
	            // FIRST block: state is already finalized after absorb
	            squeezeBuffer = stateToBytes();
	            squeezeIndex = 0;
	        } else if (squeezeIndex >= rate) {
	            // Subsequent blocks
	            keccakF(state);
	            squeezeBuffer = stateToBytes();
	            squeezeIndex = 0;
	        }

	        out[produced++] = squeezeBuffer[squeezeIndex++];
	    }

	    return out;
	}

    private byte[] stateToBytes() {
        byte[] out = new byte[rate];
        int index = 0;

        for (int y = 0; y < 5 && index < rate; y++) {
            for (int x = 0; x < 5 && index < rate; x++) {
                long lane = state[x][y];

                for (int i = 0; i < 8 && index < rate; i++) {
                    out[index++] = (byte) (lane >>> (8 * i));
                }
            }
        }

        return out;
    }
}
