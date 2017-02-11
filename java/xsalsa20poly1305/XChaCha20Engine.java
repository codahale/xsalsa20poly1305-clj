package xsalsa20poly1305;

import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.util.Pack;

/**
 * Implementation of Daniel J. Bernstein's XChaCha20 stream cipher - ChaCha20 with
 * an extended nonce. <p> XChaCha20 requires a 256 bit key, and a 192 bit nonce.
 */
public class XChaCha20Engine extends ChaCha7539Engine {
    public String getAlgorithmName() {
        return "XChaCha20";
    }

    protected int getNonceSize() {
        return 24;
    }

    /**
     * XChaCha20 key generation: process 256 bit input key and 128 bits of the
     * input nonce using a core ChaCha20 function without input addition to
     * produce 256 bit working key and use that with the remaining 64 bits of
     * nonce to initialize a standard ChaCha20 engine state.
     */
    protected void setKey(byte[] keyBytes, byte[] ivBytes) {
        if (keyBytes == null) {
            throw new IllegalArgumentException(getAlgorithmName() +
                                               " doesn't support re-init with null key");
        }

        if (keyBytes.length != 32) {
            throw new IllegalArgumentException(getAlgorithmName() +
                                               " requires a 256 bit key");
        }

        // Set key for HChaCha20
        super.setKey(keyBytes, ivBytes);

        // Pack next 64 bits of IV into engine state instead of counter
        Pack.littleEndianToInt(ivBytes, 8, engineState, 8, 2);

        // Process engine state to generate ChaCha20 key
        int[] hchacha20Out = new int[engineState.length];
        ChaChaEngine.chachaCore(20, engineState, hchacha20Out);

        // Set new key, removing addition in last round of chachaCore
        engineState[1] = hchacha20Out[0] - engineState[0];
        engineState[2] = hchacha20Out[5] - engineState[5];
        engineState[3] = hchacha20Out[10] - engineState[10];
        engineState[4] = hchacha20Out[15] - engineState[15];

        engineState[11] = hchacha20Out[6] - engineState[6];
        engineState[12] = hchacha20Out[7] - engineState[7];
        engineState[13] = hchacha20Out[8] - engineState[8];
        engineState[14] = hchacha20Out[9] - engineState[9];

        // Last 64 bits of input IV
        Pack.littleEndianToInt(ivBytes, 16, engineState, 6, 2);
    }
}
