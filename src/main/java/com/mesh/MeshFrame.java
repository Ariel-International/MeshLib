package com.mesh;

import org.json.JSONObject;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Wire framing for MeshLib sockets.
 *
 * <p>Format: 4-byte big-endian signed integer length prefix, followed by
 * exactly that many bytes of UTF-8 JSON. Maximum frame size is 256 KB;
 * frames larger than that are rejected to prevent memory exhaustion.
 *
 * <p>Both {@link #write} and {@link #read} are blocking and must be called
 * from a thread that owns the socket — they are not internally synchronised.
 * {@link MeshLink} serialises writes via a per-link lock and owns the single
 * read thread.
 */
public final class MeshFrame {

    private static final int MAX_FRAME_BYTES = 256 * 1024;

    private MeshFrame() {}

    /**
     * Writes one JSON frame to {@code out}. Flushes after writing.
     *
     * @throws Exception on any I/O error or JSON serialisation failure
     */
    public static void write(DataOutputStream out, JSONObject json) throws Exception {
        byte[] bytes = json.toString().getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
        out.flush();
    }

    /**
     * Reads one JSON frame from {@code in}. Blocks until all bytes arrive.
     *
     * @throws IllegalStateException if the length prefix is out of range
     * @throws Exception             on any I/O or JSON parse error
     */
    public static JSONObject read(DataInputStream in) throws Exception {
        int len = in.readInt();
        if (len <= 0 || len > MAX_FRAME_BYTES)
            throw new IllegalStateException("Bad frame length: " + len);
        byte[] buf = new byte[len];
        in.readFully(buf);
        return new JSONObject(new String(buf, StandardCharsets.UTF_8));
    }
}
