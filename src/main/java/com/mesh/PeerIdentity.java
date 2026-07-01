package com.mesh;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * L0 identity keypair — P-256 EC, persisted as raw DER files.
 * No AndroidKeyStore dependency: works on any JVM (PC, router, Android).
 *
 * Private key is stored on disk; accept that trade-off for a transport-layer
 * identity (not a wallet custody key). The wallet keeps its own separate
 * keys in hardware-backed storage.
 *
 * storageDir: directory to persist mesh-identity.pub / mesh-identity.key.
 *             Pass null to generate a transient (in-memory only) keypair.
 */
public class PeerIdentity {

    private static final String PUB_FILE  = "mesh-identity.pub";
    private static final String PRIV_FILE = "mesh-identity.key";
    private static final String EC_ALG    = "EC";
    private static final String CURVE     = "secp256r1";
    private static final String SIG_ALG   = "SHA256withECDSA";

    private final KeyPair mKeyPair;
    private final PeerId  mPeerId;
    private MeshLogger    mLog = MeshLogger.DEFAULT;

    public PeerIdentity(File storageDir) {
        mKeyPair = mLoadOrCreate(storageDir);
        mPeerId  = new PeerId(mKeyPair.getPublic().getEncoded());
    }

    /**
     * Constructor for subclasses that manage their own key storage (e.g. AndroidKeyStore).
     * The subclass generates the keypair and passes it in; this class only calls
     * {@link #sign(byte[])} which subclasses can also override.
     */
    protected PeerIdentity(KeyPair keyPair) {
        mKeyPair = keyPair;
        mPeerId  = new PeerId(keyPair.getPublic().getEncoded());
    }

    public void setLogger(MeshLogger log) { mLog = log; }

    public PeerId getPeerId() { return mPeerId; }

    /** Signs payload with this device's private key. Returns null on failure. */
    public byte[] sign(byte[] payload) {
        for (int attempt = 1; attempt <= 2; attempt++) {
            try {
                Signature sig = Signature.getInstance(SIG_ALG);
                sig.initSign(mKeyPair.getPrivate());
                sig.update(payload);
                return sig.sign();
            } catch (Exception e) {
                mLog.e("MESH", "sign() attempt " + attempt + " failed: " + e.getMessage());
                if (attempt < 2) {
                    try { Thread.sleep(50); } catch (InterruptedException ignored) {}
                }
            }
        }
        return null;
    }

    /** Verifies a signature against a claimed PeerId's public key. */
    public static boolean verify(PeerId claimedPeer, byte[] payload, byte[] signature) {
        try {
            KeyFactory kf = KeyFactory.getInstance(EC_ALG);
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(claimedPeer.toBytes()));
            Signature sig = Signature.getInstance(SIG_ALG);
            sig.initVerify(pub);
            sig.update(payload);
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    private KeyPair mLoadOrCreate(File dir) {
        if (dir != null) {
            File pubFile  = new File(dir, PUB_FILE);
            File privFile = new File(dir, PRIV_FILE);
            if (pubFile.exists() && privFile.exists()) {
                try {
                    byte[] pubBytes  = mReadFile(pubFile);
                    byte[] privBytes = mReadFile(privFile);
                    KeyFactory kf = KeyFactory.getInstance(EC_ALG);
                    PublicKey  pub  = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
                    PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
                    return new KeyPair(pub, priv);
                } catch (Exception e) {
                    mLog.w("MESH", "Identity load failed, regenerating: " + e.getMessage());
                }
            }
        }

        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance(EC_ALG);
            gen.initialize(new ECGenParameterSpec(CURVE));
            KeyPair kp = gen.generateKeyPair();
            if (dir != null) {
                dir.mkdirs();
                mWriteFile(new File(dir, PUB_FILE),  kp.getPublic().getEncoded());
                mWriteFile(new File(dir, PRIV_FILE), kp.getPrivate().getEncoded());
            }
            return kp;
        } catch (Exception e) {
            throw new RuntimeException("Identity keypair generation failed", e);
        }
    }

    private static byte[] mReadFile(File f) throws Exception {
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] buf = new byte[(int) f.length()];
            int off = 0, n;
            while (off < buf.length && (n = fis.read(buf, off, buf.length - off)) != -1) off += n;
            return buf;
        }
    }

    private static void mWriteFile(File f, byte[] data) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(data);
        }
    }
}
