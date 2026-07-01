package com.mesh;

import org.json.JSONObject;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Wire format: 4-byte big-endian length prefix, then UTF-8 JSON body.
 */
public final class MeshFrame {

    private MeshFrame() {}

    public static void write(DataOutputStream out, JSONObject json) throws Exception {
        byte[] bytes = json.toString().getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
        out.flush();
    }

    public static JSONObject read(DataInputStream in) throws Exception {
        int len = in.readInt();
        if (len <= 0 || len > 256 * 1024) throw new IllegalStateException("Bad frame length: " + len);
        byte[] buf = new byte[len];
        in.readFully(buf);
        return new JSONObject(new String(buf, StandardCharsets.UTF_8));
    }
}
