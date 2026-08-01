import com.mesh.MeshBase64;
import com.mesh.MeshFrame;
import com.mesh.PeerId;
import com.mesh.PeerIdentity;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Cross-implementation fixture generator: real Java com.mesh code produces
 * real wire bytes, which core/tests/test_interop.c then decodes with the C
 * core and checks byte-for-byte / cross-verifies.
 *
 * This is the check that "both sides look the same when you read them" does
 * not prove: it runs the actual Java encoder and hands its actual output to
 * the actual C decoder, and vice versa (see the "our signature" section,
 * verified by test_interop.c calling mesh_identity_verify).
 *
 * Not a JUnit test and not wired into build.gradle.kts — this is a one-shot
 * fixture producer for the C-side interop test, run manually:
 *   javac -cp <org.json jar> -d <outdir> FixtureGen.java
 *   java  -cp <outdir>;<org.json jar> FixtureGen <out.json>
 */
public class FixtureGen {

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: FixtureGen <output-fixture.json>");
            System.exit(2);
        }

        JSONObject root = new JSONObject();

        // ---- Base64: deterministic, must be byte-identical -----------------
        JSONObject b64 = new JSONObject();
        byte[][] b64Inputs = {
            {}, {0}, {1,2}, {1,2,3}, {(byte)0xFF,(byte)0xFE,(byte)0xFD},
            "hello mesh".getBytes(StandardCharsets.UTF_8),
            randomBytes(16), randomBytes(32), randomBytes(63), randomBytes(64), randomBytes(65)
        };
        org.json.JSONArray b64Cases = new org.json.JSONArray();
        for (byte[] in : b64Inputs) {
            JSONObject c = new JSONObject();
            c.put("input_hex", toHex(in));
            c.put("encoded", MeshBase64.encode(in));
            b64Cases.put(c);
        }
        b64.put("cases", b64Cases);
        root.put("base64", b64);

        // ---- Hex: deterministic, must be byte-identical (lowercase) -------
        JSONObject hex = new JSONObject();
        org.json.JSONArray hexCases = new org.json.JSONArray();
        for (byte[] in : b64Inputs) {
            JSONObject c = new JSONObject();
            c.put("input_hex", toHex(in));
            c.put("encoded_lower", toHex(in)); // PeerId.toHex() is already lowercase
            hexCases.put(c);
        }
        hex.put("cases", hexCases);
        root.put("hex", hex);

        // ---- Frame: 4-byte BE length prefix + JSON, must decode identically ----
        JSONObject framing = new JSONObject();
        org.json.JSONArray frameCases = new org.json.JSONArray();
        String[] payloads = {
            "{\"type\":\"heartbeat\"}",
            "{\"a\":1,\"b\":\"two\",\"c\":[1,2,3]}",
            "{\"unicode\":\"caf\\u00e9 \\u2603\"}",
            "{\"escapes\":\"line1\\nline2\\ttab\\\"quote\\\\backslash\"}"
        };
        for (String p : payloads) {
            JSONObject c = new JSONObject();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(bos);
            MeshFrame.write(dos, new JSONObject(p));
            byte[] framed = bos.toByteArray();
            c.put("payload_json", p);
            c.put("framed_hex", toHex(framed));
            frameCases.put(c);
        }
        framing.put("cases", frameCases);
        root.put("framing", framing);

        // ---- Identity + live cross-signature ------------------------------
        // A fresh P-256 identity (transient, no disk persistence). SHA256withECDSA
        // signatures are randomized per RFC 6979 is NOT used by the JDK's default
        // provider (it uses a random k), so signatures are NOT byte-reproducible
        // across runs -- the interop proof here is Java signs, C verifies, using
        // the real PeerIdentity.sign()/PeerId encoding, not a canned byte string.
        PeerIdentity id = new PeerIdentity(null);
        PeerId peerId = id.getPeerId();
        byte[] peerIdDer = peerId.toBytes();

        JSONObject identity = new JSONObject();
        identity.put("peer_id_hex", peerId.toHex());
        identity.put("peer_id_der_b64", MeshBase64.encode(peerIdDer));

        // The exact nonce-signing quirk from the L2 handshake: sign the RAW
        // base64 STRING bytes of a nonce, never the decoded bytes.
        byte[] nonceBytes = randomBytes(16);
        String nonceB64 = MeshBase64.encode(nonceBytes);
        byte[] sigOverNonceString = id.sign(nonceB64.getBytes(StandardCharsets.UTF_8));
        identity.put("sample_nonce_b64", nonceB64);
        identity.put("java_signature_over_nonce_string_b64", MeshBase64.encode(sigOverNonceString));

        // A second, plain message signature (not the nonce-string quirk) so the
        // C side also exercises a straightforward sign/verify path.
        byte[] plainMsg = "cross-implementation interop check".getBytes(StandardCharsets.UTF_8);
        byte[] sigOverPlain = id.sign(plainMsg);
        identity.put("plain_message_utf8", new String(plainMsg, StandardCharsets.UTF_8));
        identity.put("java_signature_over_plain_message_b64", MeshBase64.encode(sigOverPlain));

        root.put("identity", identity);

        // ---- L2 handshake hello frame shape, real Java output --------------
        JSONObject hello = new JSONObject();
        hello.put("type", "hello");
        hello.put("peerId", peerId.toHex());
        hello.put("nonce", nonceB64);
        hello.put("appId", "popcoin");
        JSONObject handshake = new JSONObject();
        ByteArrayOutputStream hbos = new ByteArrayOutputStream();
        MeshFrame.write(new DataOutputStream(hbos), hello);
        handshake.put("hello_framed_hex", toHex(hbos.toByteArray()));
        handshake.put("hello_json", hello.toString());
        root.put("handshake", handshake);

        // ---- L3 topology / route frame shapes, real Java output ------------
        JSONObject l3 = new JSONObject();
        JSONObject topoFrame = new JSONObject();
        topoFrame.put("type", "topology");
        topoFrame.put("peer", peerId.toHex());
        org.json.JSONArray neighbors = new org.json.JSONArray();
        neighbors.put("aa11");
        neighbors.put("bb22");
        topoFrame.put("neighbors", neighbors);
        l3.put("topology_json", topoFrame.toString());

        JSONObject routeFrame = new JSONObject();
        routeFrame.put("type", "route");
        routeFrame.put("from", peerId.toHex());
        routeFrame.put("to", "cc33");
        JSONObject innerPayload = new JSONObject();
        innerPayload.put("msg", "hi");
        routeFrame.put("payload", innerPayload);
        l3.put("route_json", routeFrame.toString());
        root.put("l3", l3);

        try (FileWriter fw = new FileWriter(args[0])) {
            fw.write(root.toString(2));
        }
        System.out.println("Fixture written to " + args[0]);
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new java.security.SecureRandom().nextBytes(b);
        return b;
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte x : data) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }
}
