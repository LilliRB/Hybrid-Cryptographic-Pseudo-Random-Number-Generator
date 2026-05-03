public class CSPRNG {

    private final byte[] key;
    private final byte[] counter;

    private byte[] buffer = new byte[16];
    private int index = 16;
    private byte[] expandedKey;

    public CSPRNG(byte[] seed) {

        SHAKE256 shake = new SHAKE256();
        shake.absorb(seed);
        byte[] expanded = shake.squeeze(48);

        key = new byte[32];
        counter = new byte[16];

        System.arraycopy(expanded, 0, key, 0, 32);
        System.arraycopy(expanded, 32, counter, 0, 16);

        expandedKey = AES.expandKey(key);
    }

    private void refill() {
        buffer = AES.encryptBlock(counter.clone(), expandedKey);
        AES.incrementCounter(counter);
        index = 0;
    }

    public byte nextByte() {
        if (index >= 16) {
            refill();
        }
        return buffer[index++];
    }

    public void nextBytes(byte[] out) {

        int offset = 0;

        while (offset < out.length) {

            if (index >= 16) {
                refill();
            }

            int available = 16 - index;
            int remaining = out.length - offset;
            int toCopy = Math.min(available, remaining);

            System.arraycopy(buffer, index, out, offset, toCopy);

            index += toCopy;
            offset += toCopy;
        }
    }
}