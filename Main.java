
public class Main {

	public static void main(String[] args) {
		byte[] message = "abc".getBytes();

        int rateBytes = 136; 
        int capacity = 512;
		SHA3 hash = new SHA3();

        byte[] padded = hash.pad(message, rateBytes);
	}


	}
