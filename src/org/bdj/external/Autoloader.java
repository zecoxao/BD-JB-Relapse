/*
 * BD-J Relapse - autoloader hand-off.
 *
 * Relapse ends its chain by having kexp bootstrap elfldr, which listens for ELF
 * payloads on port 9021.  This class performs the same final step as
 * ps5-bdjb-autoloader's Autoloader payload: once elfldr is accepting
 * connections it streams the unified autoloader ELF into it.
 *
 * The unified autoloader then owns the rest of the boot:
 *   1. kills the disc player entry point (this app),
 *   2. finds ps5_autoloader/autoload.txt on USB (or /data/ps5_autoloader),
 *   3. launches every payload listed there through elfldr,
 *   4. falls back to the embedded Payload Manager when there is no config.
 *
 * The ELF is embedded in Relapse.jar (see PayloadPaths.AUTOLOADER), with the
 * disc-root layout of ps5-bdjb-autoloader as a fallback.
 */

package org.bdj.external;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.bdj.Status;

public class Autoloader {

    private static final String HOST = "127.0.0.1";
    private static final int PORT = 9021;

    /* elfldr is spawned by kexp right after the shellcode returns; give it time
     * to bind before giving up. */
    private static final int CONNECT_TIMEOUT_MS = 1000;
    private static final int READY_TIMEOUT_MS = 20000;
    private static final int READY_POLL_MS = 200;

    /* 32 KiB keeps every write inside the socket buffers the BD-J VM gives us;
     * elfldr reads the ELF with MSG_WAITALL so any chunking is fine. */
    private static final int CHUNK_SIZE = 32768;
    private static final int PROGRESS_STEP = 1024 * 1024;

    /* Mirrors ps5-bdjb-autoloader, which ships the ELF at the disc root. */
    private static final String DISC_FALLBACK = "/mnt/disc/ps5-unified-autoloader.elf";

    /**
     * Waits for elfldr and streams the unified autoloader into it.
     *
     * @return true when the whole payload was handed to elfldr
     */
    public static boolean run() {
        Status.println("autoloader: waiting for elfldr on " + HOST + ":" + PORT);

        if (!waitForElfldr()) {
            Status.println("autoloader: elfldr did not accept connections on port " + PORT
                           + "; payloads were not autoloaded");
            return false;
        }

        InputStream payload = openPayload();
        if (payload == null) {
            Status.println("autoloader: unified autoloader ELF is missing ("
                           + PayloadPaths.AUTOLOADER + " / " + DISC_FALLBACK + ")");
            return false;
        }

        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(HOST, PORT), CONNECT_TIMEOUT_MS);
            socket.setTcpNoDelay(true);

            OutputStream out = socket.getOutputStream();
            byte[] buffer = new byte[CHUNK_SIZE];
            long total = 0;
            long nextProgress = PROGRESS_STEP;
            int n;

            while ((n = payload.read(buffer)) != -1) {
                out.write(buffer, 0, n);
                total += n;
                if (total >= nextProgress) {
                    Status.println("autoloader: sent " + total + " bytes");
                    nextProgress += PROGRESS_STEP;
                }
            }
            out.flush();

            Status.println("autoloader: sent " + total + " bytes; unified autoloader takes over");
            return total > 0;

        } catch (IOException e) {
            Status.printStackTrace("autoloader: failed to send payload: ", e);
            return false;
        } finally {
            if (socket != null) {
                try { socket.close(); } catch (IOException ignored) {}
            }
            try { payload.close(); } catch (IOException ignored) {}
        }
    }

    /**
     * Polls port 9021 until elfldr accepts a connection.  The probe connection
     * is closed immediately; elfldr drops it when no payload follows.
     */
    private static boolean waitForElfldr() {
        long deadline = System.currentTimeMillis() + READY_TIMEOUT_MS;

        while (System.currentTimeMillis() < deadline) {
            Socket probe = null;
            try {
                probe = new Socket();
                probe.connect(new InetSocketAddress(HOST, PORT), CONNECT_TIMEOUT_MS);
                return true;
            } catch (IOException notYet) {
                /* elfldr is still bootstrapping */
            } finally {
                if (probe != null) {
                    try { probe.close(); } catch (IOException ignored) {}
                }
            }

            try {
                Thread.sleep(READY_POLL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    /** Embedded ELF first, disc-root copy second. */
    private static InputStream openPayload() {
        InputStream in = Autoloader.class.getResourceAsStream(PayloadPaths.AUTOLOADER);
        if (in != null) {
            return in;
        }

        Status.println("autoloader: " + PayloadPaths.AUTOLOADER
                       + " not embedded, trying " + DISC_FALLBACK);
        try {
            return new FileInputStream(DISC_FALLBACK);
        } catch (Exception e) {
            /* IOException, or a SecurityException if the sandbox re-enabled */
            return null;
        }
    }
}
