/*
 * Autoloader - after Relapse has started elfldr, push a user-supplied ELF to
 * it (127.0.0.1:9021) and then close the Disc Player app.
 *
 * ELF lookup order (first hit wins):
 *   1. /mnt/usb0..7/autoload.elf   swap payloads without reburning the disc
 *   2. /data/autoload.elf          console internal storage
 *   3. /mnt/disc/autoload.elf      root of the disc
 *   4. /autoload.elf in the jar    bundled at build time (make AUTOLOAD_ELF=...)
 *
 * If no ELF is found the app is still closed (elfldr keeps running on :9021 as
 * a system service).  If elfldr never comes up, or the send fails, the app is
 * left open so the on-screen log stays readable.
 *
 * Modelled on itsPLK/ps5-bdjb-autoloader (Autoloader.java): native open/read
 * for files outside the BD-J VFS, a plain java.net.Socket to elfldr, and
 * kill(getpid(), SIGKILL) to end the host app.
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

package org.bdj.external;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import org.bdj.Status;
import org.bdj.api.API;
import org.bdj.api.NativeInvoke;
import org.bdj.api.Text;

public class Autoloader {

    private static final String HOST = "127.0.0.1";
    private static final int ELFLDR_PORT = 9021;
    private static final int SIGKILL = 9;
    private static final int O_RDONLY = 0;

    /* elfldr migrates to a system service after kexp returns; give it time to
     * bind :9021 before giving up. */
    private static final int CONNECT_TIMEOUT_MS = 30000;
    private static final int CONNECT_RETRY_MS = 250;
    /* After the ELF is handed over, let elfldr spawn it (and the UDP logger
     * flush) before this process goes away. */
    private static final int CLOSE_DELAY_MS = 3000;
    private static final int CHUNK = 0x10000;

    private static final String FILE_NAME = "autoload.elf";
    private static final String JAR_RESOURCE = "/" + FILE_NAME;

    /* Close the Disc Player once elfldr is up and the ELF (if any) was sent. */
    private static final boolean CLOSE_APP = true;

    private static API api;

    private Autoloader() {}

    /** Runs the autoload step; returns true when an ELF was delivered. */
    public static boolean run() {
        try {
            api = API.getInstance();

            String[] source = new String[1];
            byte[] elf = findElf(source);

            Socket s = connectElfldr();
            if (s == null) {
                Status.println("Autoloader: elfldr not reachable on :" + ELFLDR_PORT
                               + ", leaving the app open");
                NativeInvoke.sendNotificationRequest("Autoloader: elfldr not reachable");
                return false;
            }

            if (elf == null) {
                closeQuietly(s);
                Status.println("Autoloader: no " + FILE_NAME + " (usb/data/disc/jar); nothing to send");
                NativeInvoke.sendNotificationRequest("elfldr ready on :" + ELFLDR_PORT
                                                     + "\nno " + FILE_NAME + " found");
                closeApp();
                return false;
            }

            Status.println("Autoloader: " + source[0] + " (" + elf.length + " bytes)");
            if (!isElf(elf)) {
                closeQuietly(s);
                Status.println("Autoloader: " + source[0] + " is not an ELF, leaving the app open");
                NativeInvoke.sendNotificationRequest("Autoloader: not an ELF\n" + source[0]);
                return false;
            }

            try {
                OutputStream os = s.getOutputStream();
                os.write(elf);
                os.flush();
            } catch (IOException e) {
                Status.printStackTrace("Autoloader: send failed: ", e);
                NativeInvoke.sendNotificationRequest("Autoloader: send failed");
                return false;
            } finally {
                closeQuietly(s);   /* EOF tells elfldr the ELF is complete */
            }

            Status.println("Autoloader: sent " + elf.length + " bytes to elfldr");
            NativeInvoke.sendNotificationRequest("Autoloader: loaded\n" + source[0]);
            closeApp();
            return true;
        } catch (Throwable t) {
            Status.printStackTrace("Autoloader failed: ", t);
            return false;
        }
    }

    /* ------------------------------------------------------------------ */
    /* ELF lookup                                                          */
    /* ------------------------------------------------------------------ */

    private static byte[] findElf(String[] source) {
        String[] paths = new String[10];
        for (int i = 0; i < 8; i++) paths[i] = "/mnt/usb" + i + "/" + FILE_NAME;
        paths[8] = "/data/" + FILE_NAME;
        paths[9] = "/mnt/disc/" + FILE_NAME;

        for (int i = 0; i < paths.length; i++) {
            byte[] data = readFileNative(paths[i]);
            if (data != null && data.length > 0) {
                source[0] = paths[i];
                return data;
            }
        }

        InputStream in = Autoloader.class.getResourceAsStream(JAR_RESOURCE);
        if (in != null) {
            try {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buf = new byte[CHUNK];
                int n;
                while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
                if (out.size() > 0) {
                    source[0] = "jar:" + JAR_RESOURCE;
                    return out.toByteArray();
                }
            } catch (IOException e) {
                Status.println("Autoloader: cannot read bundled ELF: " + e);
            } finally {
                try { in.close(); } catch (IOException ignored) {}
            }
        }
        return null;
    }

    /* Native open/read: /mnt/usb*, /data and /mnt/disc are outside the BD-J
     * VM's file view but reachable now that the process root is rootvnode. */
    private static byte[] readFileNative(String path) {
        long fnOpen = api.dlsym(API.LIBKERNEL_MODULE_HANDLE, "open");
        long fnRead = api.dlsym(API.LIBKERNEL_MODULE_HANDLE, "read");
        long fnClose = api.dlsym(API.LIBKERNEL_MODULE_HANDLE, "close");
        if (fnOpen == 0 || fnRead == 0 || fnClose == 0) return null;

        int fd = (int) api.call(fnOpen, new Text(path).address(), O_RDONLY);
        if (fd < 0) return null;

        long buf = api.malloc(CHUNK);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            while (true) {
                long n = api.call(fnRead, fd, buf, CHUNK);
                if (n < 0) {
                    Status.println("Autoloader: read error on " + path + " errno=" + api.errno());
                    return null;
                }
                if (n == 0) break;
                byte[] chunk = new byte[(int) n];
                api.memcpy(chunk, buf, n);
                out.write(chunk, 0, chunk.length);
            }
            return out.toByteArray();
        } finally {
            api.free(buf);
            api.call(fnClose, fd);
        }
    }

    private static boolean isElf(byte[] d) {
        return d.length > 4 && d[0] == 0x7f && d[1] == 'E' && d[2] == 'L' && d[3] == 'F';
    }

    /* ------------------------------------------------------------------ */
    /* elfldr / app control                                               */
    /* ------------------------------------------------------------------ */

    private static Socket connectElfldr() {
        long deadline = System.currentTimeMillis() + CONNECT_TIMEOUT_MS;
        int attempts = 0;
        while (true) {
            attempts++;
            try {
                Socket s = new Socket(HOST, ELFLDR_PORT);
                Status.println("Autoloader: elfldr up (attempt " + attempts + ")");
                return s;
            } catch (IOException e) {
                if (System.currentTimeMillis() >= deadline) return null;
                sleep(CONNECT_RETRY_MS);
            }
        }
    }

    /* Same exit the ps5-bdjb-autoloader / unified autoloader use for the host
     * app.  Relapse has already repaired the crossed pipes by this point. */
    private static void closeApp() {
        if (!CLOSE_APP) return;
        Status.println("Autoloader: closing the Disc Player in " + (CLOSE_DELAY_MS / 1000) + "s");
        sleep(CLOSE_DELAY_MS);
        long fnGetpid = api.dlsym(API.LIBKERNEL_MODULE_HANDLE, "getpid");
        long fnKill = api.dlsym(API.LIBKERNEL_MODULE_HANDLE, "kill");
        if (fnGetpid == 0 || fnKill == 0) {
            Status.println("Autoloader: getpid/kill not exported, close the app manually");
            return;
        }
        int pid = (int) api.call(fnGetpid);
        api.call(fnKill, pid, SIGKILL);
        Status.println("Autoloader: kill(" + pid + ") returned; close the app manually");
    }

    private static void closeQuietly(Socket s) {
        try { s.close(); } catch (IOException ignored) {}
    }

    private static void sleep(int ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
