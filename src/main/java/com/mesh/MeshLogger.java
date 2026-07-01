package com.mesh;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Pluggable logger. Default backend uses java.util.logging.
 * Android host can swap in its own backend via MeshNode.setLogger().
 */
public interface MeshLogger {

    void d(String tag, String msg);
    void w(String tag, String msg);
    void e(String tag, String msg);

    MeshLogger DEFAULT = new MeshLogger() {
        private final Logger log = Logger.getLogger("Mesh");
        @Override public void d(String tag, String msg) { log.log(Level.FINE,    "[" + tag + "] " + msg); }
        @Override public void w(String tag, String msg) { log.log(Level.WARNING, "[" + tag + "] " + msg); }
        @Override public void e(String tag, String msg) { log.log(Level.SEVERE,  "[" + tag + "] " + msg); }
    };

    MeshLogger STDOUT = new MeshLogger() {
        @Override public void d(String tag, String msg) { System.out.println("D [" + tag + "] " + msg); }
        @Override public void w(String tag, String msg) { System.out.println("W [" + tag + "] " + msg); }
        @Override public void e(String tag, String msg) { System.err.println("E [" + tag + "] " + msg); }
    };
}
