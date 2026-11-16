package org.bdj.external;

import java.util.Hashtable;

/**
 * Per-firmware kernel R/W offsets for the relapse exploit, translated from
 * Relapse-Exploit-main/offsets/*.js (window.KRW, window.SYMBOLS and
 * syscall_map blocks).
 *
 * Supports firmware versions 7.00 through 13.60.
 */
public class RelapseOffsets {

    public String FW_VERSION;

    /* ---- syscall_map stub offsets (libkernel_web RVAs) ----
     * These are the values from Relapse's WebKit offsets.  The BD-J
     * process maps libkernel.prx/libkernel_sys.prx instead, so the
     * payload does NOT use these addresses; it scans the mapped
     * libkernel for the raw stubs at runtime.  Kept for reference
     * and for the offset verifier. */
    public static class Syscalls {
        public long socket; // syscall 0x61
        public long setsockopt; // syscall 0x69
        public long read; // syscall 0x3
        public long write; // syscall 0x4
        public long recvfrom; // syscall 0x1d
        public long getrlimit; // syscall 0xc2
        public long setrlimit; // syscall 0xc3
        public long socketpair; // syscall 0x87
        public long pipe2; // syscall 0x2af
        public long aioSubmitCmd; // syscall 0x29d
        public long aioMultiWait; // syscall 0x297
        public long aioMultiPoll; // syscall 0x298
        public long aioMultiCancel; // syscall 0x29a
        public long getpid; // syscall 0x14
        public long getuid; // syscall 0x18
        public long isInSandbox; // syscall 0x249
        public long mmap; // syscall 0x1dd
        public long jitshmCreate; // syscall 0x215
        public long cpusetGetAffinity; // syscall 0x1e7
        public long cpusetSetAffinity; // syscall 0x1e8
        public long rtprioThread; // syscall 0x1d2
        public long sysctl; // syscall 0xca
        public long netgetiflist; // syscall 0x7d
        public long close; // syscall 0x6
        public long ioctl; // syscall 0x36
    }

    public Syscalls syscalls;

    /* ---- KRW block (kernel-relative offsets) ---- */

    public long kernelData;
    public long allproc;
    public long rootvnode;

    /* kaslr */
    public long kaslrRetStatic;
    public int kaslrRetLow16;

    /* oid */
    public int oidOriginalKind;
    public int oidWritableKind;

    /* oid.a */
    public long oidA_base;
    public long oidA_kind;
    public long oidA_kindByte3;
    public long oidA_arg1;
    public long oidA_arg1Byte1;
    public long oidA_arg1Value;
    public long oidA_deadSink;

    /* oid.b */
    public long oidB_base;
    public long oidB_kind;
    public long oidB_kindByte3;
    public long oidB_arg1;
    public long oidB_arg1Value;
    public long oidB_visible;

    /* oid.c */
    public long oidC_base;
    public long oidC_kind;
    public long oidC_arg1;
    public long oidC_arg1Value;
    public int[] oidC_mib;

    /* walkCounter */
    public long walkCounterAddr;
    public int[] walkCounterMib;

    public long nodeMutex;

    /* rodataProbe */
    public long rodataProbeRva;
    public String rodataProbeText;

    /* aio */
    public int aioWaiterSize;
    public int aioRequestSize;
    public int aioGroupNum;
    public int aioGroupState;
    public int aioGroupWaiters;
    public int aioIdTablePages;
    public int aioIdTableSlotStride;
    public int aioIdTableEntryType;

    /* proc */
    public int procPid;
    public int procUcred;
    public int procFd;
    public int procAioInfo;
    public int procDynlib;

    public long kernelPid;

    /* ucred */
    public int ucredUid;
    public int ucredRuid;
    public int ucredSvuid;
    public int ucredNgroups;
    public int ucredRgid;
    public int ucredSvgid;
    public long ucredSceAuthId;
    public long ucredSceCaps;
    public long ucredSceCaps1;
    public int ucredSceAttrs;

    /* sysCoreAuthId */
    public long sysCoreAuthIdLo;
    public long sysCoreAuthIdHi;

    /* filedesc */
    public int filedescFiles;
    public int filedescCdir;
    public int filedescRdir;
    public int filedescJdir;

    /* filedescTable */
    public int filedescTableNfiles;
    public int filedescTableOfiles;
    public int filedescTableEntryStride;
    public int filedescTableFileData;

    /* pipe */
    public int pipeCount;
    public int pipeIn;
    public int pipeOut;
    public int pipeSize;
    public int pipeBuffer;
    public int pipePair;
    public int pipeDefaultSize;

    /* dynlib */
    public int dynlibSyscallStart;
    public int dynlibSyscallEnd;
    public int dynlibRestrictFlags;
    public int dynlibLibkernelRef;

    private static Hashtable firmwareOffsets;

    static {
        firmwareOffsets = new Hashtable();
        initialize700();
        initialize701();
        initialize720();
        initialize740();
        initialize760();
        initialize761();
        initialize800();
        initialize820();
        initialize840();
        initialize860();
        initialize900();
        initialize920();
        initialize940();
        initialize960();
        initialize1000();
        initialize1001();
        initialize1020();
        initialize1040();
        initialize1060();
        initialize1100();
        initialize1120();
        initialize1140();
        initialize1160();
        initialize1200();
        initialize1202();
        initialize1220();
        initialize1240();
        initialize1260();
        initialize1270();
        initialize1300();
        initialize1320();
        initialize1340();
        initialize1342();
        initialize1360();
    }

    private static void initialize700() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "7.00";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x36820L;
        off.syscalls.setsockopt = 0x37130L;
        off.syscalls.read = 0x365e0L;
        off.syscalls.write = 0x36540L;
        off.syscalls.recvfrom = 0x37a60L;
        off.syscalls.getrlimit = 0x36d20L;
        off.syscalls.setrlimit = 0x36900L;
        off.syscalls.socketpair = 0x377f0L;
        off.syscalls.pipe2 = 0x363a0L;
        off.syscalls.aioSubmitCmd = 0x382a0L;
        off.syscalls.aioMultiWait = 0x37190L;
        off.syscalls.aioMultiPoll = 0x36240L;
        off.syscalls.aioMultiCancel = 0x37170L;
        off.syscalls.getpid = 0x36760L;
        off.syscalls.getuid = 0x37890L;
        off.syscalls.isInSandbox = 0x37f00L;
        off.syscalls.mmap = 0x38120L;
        off.syscalls.jitshmCreate = 0x36ff0L;
        off.syscalls.cpusetGetAffinity = 0x38500L;
        off.syscalls.cpusetSetAffinity = 0x37cc0L;
        off.syscalls.rtprioThread = 0x36f90L;
        off.syscalls.sysctl = 0x37d20L;
        off.syscalls.netgetiflist = 0x372d0L;
        off.syscalls.close = 0x37210L;
        off.syscalls.ioctl = 0x36480L;

        off.kernelData = 0xc50000L;
        off.allproc = 0x34a9d50L;
        off.rootvnode = 0x3d17510L;

        off.kaslrRetStatic = 0xa83731L;
        off.kaslrRetLow16 = 0x3731;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x27706c8L;
        off.oidA_kind = 0x27706dcL;
        off.oidA_kindByte3 = 0x27706dfL;
        off.oidA_arg1 = 0x27706e0L;
        off.oidA_arg1Byte1 = 0x27706e1L;
        off.oidA_arg1Value = 0x27706b8L;
        off.oidA_deadSink = 0x27706e8L;

        off.oidB_base = 0x27705a0L;
        off.oidB_kind = 0x27705b4L;
        off.oidB_kindByte3 = 0x27705b7L;
        off.oidB_arg1 = 0x27705b8L;
        off.oidB_arg1Value = 0x27704d0L;
        off.oidB_visible = 0x27705f0L;

        off.oidC_base = 0x2a92fa8L;
        off.oidC_kind = 0x2a92fbcL;
        off.oidC_arg1 = 0x2a92fc0L;
        off.oidC_arg1Value = 0x3c93f3cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3c93f38L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a6fe18L;

        off.rodataProbeRva = 0x1010a7aL;
        off.rodataProbeText = "_aio_submit_cmd";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("7.00", off);
    }

    private static void initialize701() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "7.01";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x36820L;
        off.syscalls.setsockopt = 0x37130L;
        off.syscalls.read = 0x365e0L;
        off.syscalls.write = 0x36540L;
        off.syscalls.recvfrom = 0x37a60L;
        off.syscalls.getrlimit = 0x36d20L;
        off.syscalls.setrlimit = 0x36900L;
        off.syscalls.socketpair = 0x377f0L;
        off.syscalls.pipe2 = 0x363a0L;
        off.syscalls.aioSubmitCmd = 0x382a0L;
        off.syscalls.aioMultiWait = 0x37190L;
        off.syscalls.aioMultiPoll = 0x36240L;
        off.syscalls.aioMultiCancel = 0x37170L;
        off.syscalls.getpid = 0x36760L;
        off.syscalls.getuid = 0x37890L;
        off.syscalls.isInSandbox = 0x37f00L;
        off.syscalls.mmap = 0x38120L;
        off.syscalls.jitshmCreate = 0x36ff0L;
        off.syscalls.cpusetGetAffinity = 0x38500L;
        off.syscalls.cpusetSetAffinity = 0x37cc0L;
        off.syscalls.rtprioThread = 0x36f90L;
        off.syscalls.sysctl = 0x37d20L;
        off.syscalls.netgetiflist = 0x372d0L;
        off.syscalls.close = 0x37210L;
        off.syscalls.ioctl = 0x36480L;

        off.kernelData = 0xc50000L;
        off.allproc = 0x34a9d50L;
        off.rootvnode = 0x3d17510L;

        off.kaslrRetStatic = 0xa83731L;
        off.kaslrRetLow16 = 0x3731;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x27706c8L;
        off.oidA_kind = 0x27706dcL;
        off.oidA_kindByte3 = 0x27706dfL;
        off.oidA_arg1 = 0x27706e0L;
        off.oidA_arg1Byte1 = 0x27706e1L;
        off.oidA_arg1Value = 0x27706b8L;
        off.oidA_deadSink = 0x27706e8L;

        off.oidB_base = 0x27705a0L;
        off.oidB_kind = 0x27705b4L;
        off.oidB_kindByte3 = 0x27705b7L;
        off.oidB_arg1 = 0x27705b8L;
        off.oidB_arg1Value = 0x27704d0L;
        off.oidB_visible = 0x27705f0L;

        off.oidC_base = 0x2a92fa8L;
        off.oidC_kind = 0x2a92fbcL;
        off.oidC_arg1 = 0x2a92fc0L;
        off.oidC_arg1Value = 0x3c93f3cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3c93f38L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a6fe18L;

        off.rodataProbeRva = 0x1010fa2L;
        off.rodataProbeText = "_aio_submit_cmd";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("7.01", off);
    }

    private static void initialize720() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "7.20";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x36860L;
        off.syscalls.setsockopt = 0x37170L;
        off.syscalls.read = 0x36620L;
        off.syscalls.write = 0x36580L;
        off.syscalls.recvfrom = 0x37ac0L;
        off.syscalls.getrlimit = 0x36d60L;
        off.syscalls.setrlimit = 0x36940L;
        off.syscalls.socketpair = 0x37850L;
        off.syscalls.pipe2 = 0x363e0L;
        off.syscalls.aioSubmitCmd = 0x38300L;
        off.syscalls.aioMultiWait = 0x371d0L;
        off.syscalls.aioMultiPoll = 0x36280L;
        off.syscalls.aioMultiCancel = 0x371b0L;
        off.syscalls.getpid = 0x367a0L;
        off.syscalls.getuid = 0x378f0L;
        off.syscalls.isInSandbox = 0x37f60L;
        off.syscalls.mmap = 0x38180L;
        off.syscalls.jitshmCreate = 0x37030L;
        off.syscalls.cpusetGetAffinity = 0x38560L;
        off.syscalls.cpusetSetAffinity = 0x37d20L;
        off.syscalls.rtprioThread = 0x36fd0L;
        off.syscalls.sysctl = 0x37d80L;
        off.syscalls.netgetiflist = 0x37310L;
        off.syscalls.close = 0x37250L;
        off.syscalls.ioctl = 0x364c0L;

        off.kernelData = 0xc50000L;
        off.allproc = 0x34a9d50L;
        off.rootvnode = 0x3d17510L;

        off.kaslrRetStatic = 0xa83b81L;
        off.kaslrRetLow16 = 0x3b81;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x2770788L;
        off.oidA_kind = 0x277079cL;
        off.oidA_kindByte3 = 0x277079fL;
        off.oidA_arg1 = 0x27707a0L;
        off.oidA_arg1Byte1 = 0x27707a1L;
        off.oidA_arg1Value = 0x2770778L;
        off.oidA_deadSink = 0x27707a8L;

        off.oidB_base = 0x2770660L;
        off.oidB_kind = 0x2770674L;
        off.oidB_kindByte3 = 0x2770677L;
        off.oidB_arg1 = 0x2770678L;
        off.oidB_arg1Value = 0x2770590L;
        off.oidB_visible = 0x27706b0L;

        off.oidC_base = 0x2a93068L;
        off.oidC_kind = 0x2a9307cL;
        off.oidC_arg1 = 0x2a93080L;
        off.oidC_arg1Value = 0x3c93f7cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3c93f78L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a6fed8L;

        off.rodataProbeRva = 0x1010b71L;
        off.rodataProbeText = "_aio_submit_cmd";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("7.20", off);
    }

    private static void initialize740() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "7.40";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x36860L;
        off.syscalls.setsockopt = 0x37170L;
        off.syscalls.read = 0x36620L;
        off.syscalls.write = 0x36580L;
        off.syscalls.recvfrom = 0x37ac0L;
        off.syscalls.getrlimit = 0x36d60L;
        off.syscalls.setrlimit = 0x36940L;
        off.syscalls.socketpair = 0x37850L;
        off.syscalls.pipe2 = 0x363e0L;
        off.syscalls.aioSubmitCmd = 0x38300L;
        off.syscalls.aioMultiWait = 0x371d0L;
        off.syscalls.aioMultiPoll = 0x36280L;
        off.syscalls.aioMultiCancel = 0x371b0L;
        off.syscalls.getpid = 0x367a0L;
        off.syscalls.getuid = 0x378f0L;
        off.syscalls.isInSandbox = 0x37f60L;
        off.syscalls.mmap = 0x38180L;
        off.syscalls.jitshmCreate = 0x37030L;
        off.syscalls.cpusetGetAffinity = 0x38560L;
        off.syscalls.cpusetSetAffinity = 0x37d20L;
        off.syscalls.rtprioThread = 0x36fd0L;
        off.syscalls.sysctl = 0x37d80L;
        off.syscalls.netgetiflist = 0x37310L;
        off.syscalls.close = 0x37250L;
        off.syscalls.ioctl = 0x364c0L;

        off.kernelData = 0xc50000L;
        off.allproc = 0x34a9d50L;
        off.rootvnode = 0x3d17510L;

        off.kaslrRetStatic = 0xa83b81L;
        off.kaslrRetLow16 = 0x3b81;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x2770788L;
        off.oidA_kind = 0x277079cL;
        off.oidA_kindByte3 = 0x277079fL;
        off.oidA_arg1 = 0x27707a0L;
        off.oidA_arg1Byte1 = 0x27707a1L;
        off.oidA_arg1Value = 0x2770778L;
        off.oidA_deadSink = 0x27707a8L;

        off.oidB_base = 0x2770660L;
        off.oidB_kind = 0x2770674L;
        off.oidB_kindByte3 = 0x2770677L;
        off.oidB_arg1 = 0x2770678L;
        off.oidB_arg1Value = 0x2770590L;
        off.oidB_visible = 0x27706b0L;

        off.oidC_base = 0x2a93068L;
        off.oidC_kind = 0x2a9307cL;
        off.oidC_arg1 = 0x2a93080L;
        off.oidC_arg1Value = 0x3c93f7cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3c93f78L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a6fed8L;

        off.rodataProbeRva = 0x10110b6L;
        off.rodataProbeText = "_aio_submit_cmd";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("7.40", off);
    }

    private static void initialize760() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "7.60";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x36860L;
        off.syscalls.setsockopt = 0x37170L;
        off.syscalls.read = 0x36620L;
        off.syscalls.write = 0x36580L;
        off.syscalls.recvfrom = 0x37ac0L;
        off.syscalls.getrlimit = 0x36d60L;
        off.syscalls.setrlimit = 0x36940L;
        off.syscalls.socketpair = 0x37850L;
        off.syscalls.pipe2 = 0x363e0L;
        off.syscalls.aioSubmitCmd = 0x38300L;
        off.syscalls.aioMultiWait = 0x371d0L;
        off.syscalls.aioMultiPoll = 0x36280L;
        off.syscalls.aioMultiCancel = 0x371b0L;
        off.syscalls.getpid = 0x367a0L;
        off.syscalls.getuid = 0x378f0L;
        off.syscalls.isInSandbox = 0x37f60L;
        off.syscalls.mmap = 0x38180L;
        off.syscalls.jitshmCreate = 0x37030L;
        off.syscalls.cpusetGetAffinity = 0x38560L;
        off.syscalls.cpusetSetAffinity = 0x37d20L;
        off.syscalls.rtprioThread = 0x36fd0L;
        off.syscalls.sysctl = 0x37d80L;
        off.syscalls.netgetiflist = 0x37310L;
        off.syscalls.close = 0x37250L;
        off.syscalls.ioctl = 0x364c0L;

        off.kernelData = 0xc50000L;
        off.allproc = 0x34a9d50L;
        off.rootvnode = 0x3d17510L;

        off.kaslrRetStatic = 0xa84191L;
        off.kaslrRetLow16 = 0x4191;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x2770808L;
        off.oidA_kind = 0x277081cL;
        off.oidA_kindByte3 = 0x277081fL;
        off.oidA_arg1 = 0x2770820L;
        off.oidA_arg1Byte1 = 0x2770821L;
        off.oidA_arg1Value = 0x27707f8L;
        off.oidA_deadSink = 0x2770828L;

        off.oidB_base = 0x27706e0L;
        off.oidB_kind = 0x27706f4L;
        off.oidB_kindByte3 = 0x27706f7L;
        off.oidB_arg1 = 0x27706f8L;
        off.oidB_arg1Value = 0x2770610L;
        off.oidB_visible = 0x2770730L;

        off.oidC_base = 0x2a930e8L;
        off.oidC_kind = 0x2a930fcL;
        off.oidC_arg1 = 0x2a93100L;
        off.oidC_arg1Value = 0x3c93f7cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3c93f78L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a6fed8L;

        off.rodataProbeRva = 0x1010bcaL;
        off.rodataProbeText = "_aio_submit_cmd";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("7.60", off);
    }

    private static void initialize761() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "7.61";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x36860L;
        off.syscalls.setsockopt = 0x37170L;
        off.syscalls.read = 0x36620L;
        off.syscalls.write = 0x36580L;
        off.syscalls.recvfrom = 0x37ac0L;
        off.syscalls.getrlimit = 0x36d60L;
        off.syscalls.setrlimit = 0x36940L;
        off.syscalls.socketpair = 0x37850L;
        off.syscalls.pipe2 = 0x363e0L;
        off.syscalls.aioSubmitCmd = 0x38300L;
        off.syscalls.aioMultiWait = 0x371d0L;
        off.syscalls.aioMultiPoll = 0x36280L;
        off.syscalls.aioMultiCancel = 0x371b0L;
        off.syscalls.getpid = 0x367a0L;
        off.syscalls.getuid = 0x378f0L;
        off.syscalls.isInSandbox = 0x37f60L;
        off.syscalls.mmap = 0x38180L;
        off.syscalls.jitshmCreate = 0x37030L;
        off.syscalls.cpusetGetAffinity = 0x38560L;
        off.syscalls.cpusetSetAffinity = 0x37d20L;
        off.syscalls.rtprioThread = 0x36fd0L;
        off.syscalls.sysctl = 0x37d80L;
        off.syscalls.netgetiflist = 0x37310L;
        off.syscalls.close = 0x37250L;
        off.syscalls.ioctl = 0x364c0L;

        off.kernelData = 0xc50000L;
        off.allproc = 0x34a9d50L;
        off.rootvnode = 0x3d17510L;

        off.kaslrRetStatic = 0xa84191L;
        off.kaslrRetLow16 = 0x4191;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x2770808L;
        off.oidA_kind = 0x277081cL;
        off.oidA_kindByte3 = 0x277081fL;
        off.oidA_arg1 = 0x2770820L;
        off.oidA_arg1Byte1 = 0x2770821L;
        off.oidA_arg1Value = 0x27707f8L;
        off.oidA_deadSink = 0x2770828L;

        off.oidB_base = 0x27706e0L;
        off.oidB_kind = 0x27706f4L;
        off.oidB_kindByte3 = 0x27706f7L;
        off.oidB_arg1 = 0x27706f8L;
        off.oidB_arg1Value = 0x2770610L;
        off.oidB_visible = 0x2770730L;

        off.oidC_base = 0x2a930e8L;
        off.oidC_kind = 0x2a930fcL;
        off.oidC_arg1 = 0x2a93100L;
        off.oidC_arg1Value = 0x3c93f7cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3c93f78L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a6fed8L;

        off.rodataProbeRva = 0x101114fL;
        off.rodataProbeText = "_aio_submit_cmd";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("7.61", off);
    }

    private static void initialize800() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "8.00";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1a5a0L;
        off.syscalls.setsockopt = 0x1aeb0L;
        off.syscalls.read = 0x1a360L;
        off.syscalls.write = 0x1a2c0L;
        off.syscalls.recvfrom = 0x1b800L;
        off.syscalls.getrlimit = 0x1aaa0L;
        off.syscalls.setrlimit = 0x1a680L;
        off.syscalls.socketpair = 0x1b590L;
        off.syscalls.pipe2 = 0x1a120L;
        off.syscalls.aioSubmitCmd = 0x1c060L;
        off.syscalls.aioMultiWait = 0x1af10L;
        off.syscalls.aioMultiPoll = 0x19fc0L;
        off.syscalls.aioMultiCancel = 0x1aef0L;
        off.syscalls.getpid = 0x1a4e0L;
        off.syscalls.getuid = 0x1b630L;
        off.syscalls.isInSandbox = 0x1bcc0L;
        off.syscalls.mmap = 0x1bee0L;
        off.syscalls.jitshmCreate = 0x1ad70L;
        off.syscalls.cpusetGetAffinity = 0x1c2c0L;
        off.syscalls.cpusetSetAffinity = 0x1ba80L;
        off.syscalls.rtprioThread = 0x1ad10L;
        off.syscalls.sysctl = 0x1bae0L;
        off.syscalls.netgetiflist = 0x1b050L;
        off.syscalls.close = 0x1af90L;
        off.syscalls.ioctl = 0x1a200L;

        off.kernelData = 0xc70000L;
        off.allproc = 0x34e5d50L;
        off.rootvnode = 0x3d6b510L;

        off.kaslrRetStatic = 0xa9cac5L;
        off.kaslrRetLow16 = 0xcac5;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x27914e8L;
        off.oidA_kind = 0x27914fcL;
        off.oidA_kindByte3 = 0x27914ffL;
        off.oidA_arg1 = 0x2791500L;
        off.oidA_arg1Byte1 = 0x2791501L;
        off.oidA_arg1Value = 0x27914d8L;
        off.oidA_deadSink = 0x2791508L;

        off.oidB_base = 0x27913c0L;
        off.oidB_kind = 0x27913d4L;
        off.oidB_kindByte3 = 0x27913d7L;
        off.oidB_arg1 = 0x27913d8L;
        off.oidB_arg1Value = 0x27912f0L;
        off.oidB_visible = 0x2791410L;

        off.oidC_base = 0x2ab3dc8L;
        off.oidC_kind = 0x2ab3ddcL;
        off.oidC_arg1 = 0x2ab3de0L;
        off.oidC_arg1Value = 0x3ce7f7cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3ce7f78L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a8ff48L;

        off.rodataProbeRva = 0x10254e9L;
        off.rodataProbeText = "_aio_submit_cmd";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("8.00", off);
    }

    private static void initialize820() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "8.20";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1a5a0L;
        off.syscalls.setsockopt = 0x1aeb0L;
        off.syscalls.read = 0x1a360L;
        off.syscalls.write = 0x1a2c0L;
        off.syscalls.recvfrom = 0x1b800L;
        off.syscalls.getrlimit = 0x1aaa0L;
        off.syscalls.setrlimit = 0x1a680L;
        off.syscalls.socketpair = 0x1b590L;
        off.syscalls.pipe2 = 0x1a120L;
        off.syscalls.aioSubmitCmd = 0x1c060L;
        off.syscalls.aioMultiWait = 0x1af10L;
        off.syscalls.aioMultiPoll = 0x19fc0L;
        off.syscalls.aioMultiCancel = 0x1aef0L;
        off.syscalls.getpid = 0x1a4e0L;
        off.syscalls.getuid = 0x1b630L;
        off.syscalls.isInSandbox = 0x1bcc0L;
        off.syscalls.mmap = 0x1bee0L;
        off.syscalls.jitshmCreate = 0x1ad70L;
        off.syscalls.cpusetGetAffinity = 0x1c2c0L;
        off.syscalls.cpusetSetAffinity = 0x1ba80L;
        off.syscalls.rtprioThread = 0x1ad10L;
        off.syscalls.sysctl = 0x1bae0L;
        off.syscalls.netgetiflist = 0x1b050L;
        off.syscalls.close = 0x1af90L;
        off.syscalls.ioctl = 0x1a200L;

        off.kernelData = 0xc70000L;
        off.allproc = 0x34e5d50L;
        off.rootvnode = 0x3d6b510L;

        off.kaslrRetStatic = 0xa9dec5L;
        off.kaslrRetLow16 = 0xdec5;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x27913a8L;
        off.oidA_kind = 0x27913bcL;
        off.oidA_kindByte3 = 0x27913bfL;
        off.oidA_arg1 = 0x27913c0L;
        off.oidA_arg1Byte1 = 0x27913c1L;
        off.oidA_arg1Value = 0x2791398L;
        off.oidA_deadSink = 0x27913c8L;

        off.oidB_base = 0x2791280L;
        off.oidB_kind = 0x2791294L;
        off.oidB_kindByte3 = 0x2791297L;
        off.oidB_arg1 = 0x2791298L;
        off.oidB_arg1Value = 0x27911b0L;
        off.oidB_visible = 0x27912d0L;

        off.oidC_base = 0x2ab3c88L;
        off.oidC_kind = 0x2ab3c9cL;
        off.oidC_arg1 = 0x2ab3ca0L;
        off.oidC_arg1Value = 0x3ce7f7cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3ce7f78L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a8ff48L;

        off.rodataProbeRva = 0x102527fL;
        off.rodataProbeText = "_aio_submit_cmd";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("8.20", off);
    }

    private static void initialize840() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "8.40";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1a5a0L;
        off.syscalls.setsockopt = 0x1aeb0L;
        off.syscalls.read = 0x1a360L;
        off.syscalls.write = 0x1a2c0L;
        off.syscalls.recvfrom = 0x1b800L;
        off.syscalls.getrlimit = 0x1aaa0L;
        off.syscalls.setrlimit = 0x1a680L;
        off.syscalls.socketpair = 0x1b590L;
        off.syscalls.pipe2 = 0x1a120L;
        off.syscalls.aioSubmitCmd = 0x1c060L;
        off.syscalls.aioMultiWait = 0x1af10L;
        off.syscalls.aioMultiPoll = 0x19fc0L;
        off.syscalls.aioMultiCancel = 0x1aef0L;
        off.syscalls.getpid = 0x1a4e0L;
        off.syscalls.getuid = 0x1b630L;
        off.syscalls.isInSandbox = 0x1bcc0L;
        off.syscalls.mmap = 0x1bee0L;
        off.syscalls.jitshmCreate = 0x1ad70L;
        off.syscalls.cpusetGetAffinity = 0x1c2c0L;
        off.syscalls.cpusetSetAffinity = 0x1ba80L;
        off.syscalls.rtprioThread = 0x1ad10L;
        off.syscalls.sysctl = 0x1bae0L;
        off.syscalls.netgetiflist = 0x1b050L;
        off.syscalls.close = 0x1af90L;
        off.syscalls.ioctl = 0x1a200L;

        off.kernelData = 0xc70000L;
        off.allproc = 0x34e5d50L;
        off.rootvnode = 0x3d6b510L;

        off.kaslrRetStatic = 0xa9e155L;
        off.kaslrRetLow16 = 0xe155;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x27913a8L;
        off.oidA_kind = 0x27913bcL;
        off.oidA_kindByte3 = 0x27913bfL;
        off.oidA_arg1 = 0x27913c0L;
        off.oidA_arg1Byte1 = 0x27913c1L;
        off.oidA_arg1Value = 0x2791398L;
        off.oidA_deadSink = 0x27913c8L;

        off.oidB_base = 0x2791280L;
        off.oidB_kind = 0x2791294L;
        off.oidB_kindByte3 = 0x2791297L;
        off.oidB_arg1 = 0x2791298L;
        off.oidB_arg1Value = 0x27911b0L;
        off.oidB_visible = 0x27912d0L;

        off.oidC_base = 0x2ab3c88L;
        off.oidC_kind = 0x2ab3c9cL;
        off.oidC_arg1 = 0x2ab3ca0L;
        off.oidC_arg1Value = 0x3ce7f7cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3ce7f78L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a8ff48L;

        off.rodataProbeRva = 0x1024d9fL;
        off.rodataProbeText = "_aio_submit_cmd";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("8.40", off);
    }

    private static void initialize860() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "8.60";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1a5a0L;
        off.syscalls.setsockopt = 0x1aeb0L;
        off.syscalls.read = 0x1a360L;
        off.syscalls.write = 0x1a2c0L;
        off.syscalls.recvfrom = 0x1b800L;
        off.syscalls.getrlimit = 0x1aaa0L;
        off.syscalls.setrlimit = 0x1a680L;
        off.syscalls.socketpair = 0x1b590L;
        off.syscalls.pipe2 = 0x1a120L;
        off.syscalls.aioSubmitCmd = 0x1c060L;
        off.syscalls.aioMultiWait = 0x1af10L;
        off.syscalls.aioMultiPoll = 0x19fc0L;
        off.syscalls.aioMultiCancel = 0x1aef0L;
        off.syscalls.getpid = 0x1a4e0L;
        off.syscalls.getuid = 0x1b630L;
        off.syscalls.isInSandbox = 0x1bcc0L;
        off.syscalls.mmap = 0x1bee0L;
        off.syscalls.jitshmCreate = 0x1ad70L;
        off.syscalls.cpusetGetAffinity = 0x1c2c0L;
        off.syscalls.cpusetSetAffinity = 0x1ba80L;
        off.syscalls.rtprioThread = 0x1ad10L;
        off.syscalls.sysctl = 0x1bae0L;
        off.syscalls.netgetiflist = 0x1b050L;
        off.syscalls.close = 0x1af90L;
        off.syscalls.ioctl = 0x1a200L;

        off.kernelData = 0xc70000L;
        off.allproc = 0x34e5d50L;
        off.rootvnode = 0x3d6b510L;

        off.kaslrRetStatic = 0xa9e3d5L;
        off.kaslrRetLow16 = 0xe3d5;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x27913a8L;
        off.oidA_kind = 0x27913bcL;
        off.oidA_kindByte3 = 0x27913bfL;
        off.oidA_arg1 = 0x27913c0L;
        off.oidA_arg1Byte1 = 0x27913c1L;
        off.oidA_arg1Value = 0x2791398L;
        off.oidA_deadSink = 0x27913c8L;

        off.oidB_base = 0x2791280L;
        off.oidB_kind = 0x2791294L;
        off.oidB_kindByte3 = 0x2791297L;
        off.oidB_arg1 = 0x2791298L;
        off.oidB_arg1Value = 0x27911b0L;
        off.oidB_visible = 0x27912d0L;

        off.oidC_base = 0x2ab3c88L;
        off.oidC_kind = 0x2ab3c9cL;
        off.oidC_arg1 = 0x2ab3ca0L;
        off.oidC_arg1Value = 0x3ce7f7cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3ce7f78L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a8ff48L;

        off.rodataProbeRva = 0x102534fL;
        off.rodataProbeText = "_aio_submit_cmd";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("8.60", off);
    }

    private static void initialize900() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "9.00";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1adc0L;
        off.syscalls.setsockopt = 0x1b6d0L;
        off.syscalls.read = 0x1ab80L;
        off.syscalls.write = 0x1aae0L;
        off.syscalls.recvfrom = 0x1c020L;
        off.syscalls.getrlimit = 0x1b2c0L;
        off.syscalls.setrlimit = 0x1aea0L;
        off.syscalls.socketpair = 0x1bdb0L;
        off.syscalls.pipe2 = 0x1a940L;
        off.syscalls.aioSubmitCmd = 0x1c880L;
        off.syscalls.aioMultiWait = 0x1b730L;
        off.syscalls.aioMultiPoll = 0x1a7c0L;
        off.syscalls.aioMultiCancel = 0x1b710L;
        off.syscalls.getpid = 0x1ad00L;
        off.syscalls.getuid = 0x1be50L;
        off.syscalls.isInSandbox = 0x1c4e0L;
        off.syscalls.mmap = 0x1c700L;
        off.syscalls.jitshmCreate = 0x1b590L;
        off.syscalls.cpusetGetAffinity = 0x1cae0L;
        off.syscalls.cpusetSetAffinity = 0x1c2a0L;
        off.syscalls.rtprioThread = 0x1b530L;
        off.syscalls.sysctl = 0x1c300L;
        off.syscalls.netgetiflist = 0x1b870L;
        off.syscalls.close = 0x1b7b0L;
        off.syscalls.ioctl = 0x1aa20L;

        off.kernelData = 0xca0000L;
        off.allproc = 0x33f5d50L;
        off.rootvnode = 0x3c7b510L;

        off.kaslrRetStatic = 0xac1451L;
        off.kaslrRetLow16 = 0x1451;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x2787ab8L;
        off.oidA_kind = 0x2787accL;
        off.oidA_kindByte3 = 0x2787acfL;
        off.oidA_arg1 = 0x2787ad0L;
        off.oidA_arg1Byte1 = 0x2787ad1L;
        off.oidA_arg1Value = 0x2787aa8L;
        off.oidA_deadSink = 0x2787ad8L;

        off.oidB_base = 0x2787990L;
        off.oidB_kind = 0x27879a4L;
        off.oidB_kindByte3 = 0x27879a7L;
        off.oidB_arg1 = 0x27879a8L;
        off.oidB_arg1Value = 0x27878c0L;
        off.oidB_visible = 0x27879e0L;

        off.oidC_base = 0x2aaa678L;
        off.oidC_kind = 0x2aaa68cL;
        off.oidC_arg1 = 0x2aaa690L;
        off.oidC_arg1Value = 0x3bf8f3cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3bf8f38L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a588e8L;

        off.rodataProbeRva = 0x110791aL;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("9.00", off);
    }

    private static void initialize920() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "9.20";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1adc0L;
        off.syscalls.setsockopt = 0x1b6d0L;
        off.syscalls.read = 0x1ab80L;
        off.syscalls.write = 0x1aae0L;
        off.syscalls.recvfrom = 0x1c020L;
        off.syscalls.getrlimit = 0x1b2c0L;
        off.syscalls.setrlimit = 0x1aea0L;
        off.syscalls.socketpair = 0x1bdb0L;
        off.syscalls.pipe2 = 0x1a940L;
        off.syscalls.aioSubmitCmd = 0x1c880L;
        off.syscalls.aioMultiWait = 0x1b730L;
        off.syscalls.aioMultiPoll = 0x1a7c0L;
        off.syscalls.aioMultiCancel = 0x1b710L;
        off.syscalls.getpid = 0x1ad00L;
        off.syscalls.getuid = 0x1be50L;
        off.syscalls.isInSandbox = 0x1c4e0L;
        off.syscalls.mmap = 0x1c700L;
        off.syscalls.jitshmCreate = 0x1b590L;
        off.syscalls.cpusetGetAffinity = 0x1cae0L;
        off.syscalls.cpusetSetAffinity = 0x1c2a0L;
        off.syscalls.rtprioThread = 0x1b530L;
        off.syscalls.sysctl = 0x1c300L;
        off.syscalls.netgetiflist = 0x1b870L;
        off.syscalls.close = 0x1b7b0L;
        off.syscalls.ioctl = 0x1aa20L;

        off.kernelData = 0xca0000L;
        off.allproc = 0x33f5d50L;
        off.rootvnode = 0x3c7b510L;

        off.kaslrRetStatic = 0xac1471L;
        off.kaslrRetLow16 = 0x1471;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x2787ab8L;
        off.oidA_kind = 0x2787accL;
        off.oidA_kindByte3 = 0x2787acfL;
        off.oidA_arg1 = 0x2787ad0L;
        off.oidA_arg1Byte1 = 0x2787ad1L;
        off.oidA_arg1Value = 0x2787aa8L;
        off.oidA_deadSink = 0x2787ad8L;

        off.oidB_base = 0x2787990L;
        off.oidB_kind = 0x27879a4L;
        off.oidB_kindByte3 = 0x27879a7L;
        off.oidB_arg1 = 0x27879a8L;
        off.oidB_arg1Value = 0x27878c0L;
        off.oidB_visible = 0x27879e0L;

        off.oidC_base = 0x2aaa678L;
        off.oidC_kind = 0x2aaa68cL;
        off.oidC_arg1 = 0x2aaa690L;
        off.oidC_arg1Value = 0x3bf8f3cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3bf8f38L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a588e8L;

        off.rodataProbeRva = 0x11077cfL;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("9.20", off);
    }

    private static void initialize940() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "9.40";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1adc0L;
        off.syscalls.setsockopt = 0x1b6d0L;
        off.syscalls.read = 0x1ab80L;
        off.syscalls.write = 0x1aae0L;
        off.syscalls.recvfrom = 0x1c020L;
        off.syscalls.getrlimit = 0x1b2c0L;
        off.syscalls.setrlimit = 0x1aea0L;
        off.syscalls.socketpair = 0x1bdb0L;
        off.syscalls.pipe2 = 0x1a940L;
        off.syscalls.aioSubmitCmd = 0x1c880L;
        off.syscalls.aioMultiWait = 0x1b730L;
        off.syscalls.aioMultiPoll = 0x1a7c0L;
        off.syscalls.aioMultiCancel = 0x1b710L;
        off.syscalls.getpid = 0x1ad00L;
        off.syscalls.getuid = 0x1be50L;
        off.syscalls.isInSandbox = 0x1c4e0L;
        off.syscalls.mmap = 0x1c700L;
        off.syscalls.jitshmCreate = 0x1b590L;
        off.syscalls.cpusetGetAffinity = 0x1cae0L;
        off.syscalls.cpusetSetAffinity = 0x1c2a0L;
        off.syscalls.rtprioThread = 0x1b530L;
        off.syscalls.sysctl = 0x1c300L;
        off.syscalls.netgetiflist = 0x1b870L;
        off.syscalls.close = 0x1b7b0L;
        off.syscalls.ioctl = 0x1aa20L;

        off.kernelData = 0xca0000L;
        off.allproc = 0x33f5d50L;
        off.rootvnode = 0x3c7b510L;

        off.kaslrRetStatic = 0xac19e1L;
        off.kaslrRetLow16 = 0x19e1;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x2787ab8L;
        off.oidA_kind = 0x2787accL;
        off.oidA_kindByte3 = 0x2787acfL;
        off.oidA_arg1 = 0x2787ad0L;
        off.oidA_arg1Byte1 = 0x2787ad1L;
        off.oidA_arg1Value = 0x2787aa8L;
        off.oidA_deadSink = 0x2787ad8L;

        off.oidB_base = 0x2787990L;
        off.oidB_kind = 0x27879a4L;
        off.oidB_kindByte3 = 0x27879a7L;
        off.oidB_arg1 = 0x27879a8L;
        off.oidB_arg1Value = 0x27878c0L;
        off.oidB_visible = 0x27879e0L;

        off.oidC_base = 0x2aaa678L;
        off.oidC_kind = 0x2aaa68cL;
        off.oidC_arg1 = 0x2aaa690L;
        off.oidC_arg1Value = 0x3bf8f3cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3bf8f38L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a588e8L;

        off.rodataProbeRva = 0x110790fL;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("9.40", off);
    }

    private static void initialize960() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "9.60";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1adc0L;
        off.syscalls.setsockopt = 0x1b6d0L;
        off.syscalls.read = 0x1ab80L;
        off.syscalls.write = 0x1aae0L;
        off.syscalls.recvfrom = 0x1c020L;
        off.syscalls.getrlimit = 0x1b2c0L;
        off.syscalls.setrlimit = 0x1aea0L;
        off.syscalls.socketpair = 0x1bdb0L;
        off.syscalls.pipe2 = 0x1a940L;
        off.syscalls.aioSubmitCmd = 0x1c880L;
        off.syscalls.aioMultiWait = 0x1b730L;
        off.syscalls.aioMultiPoll = 0x1a7c0L;
        off.syscalls.aioMultiCancel = 0x1b710L;
        off.syscalls.getpid = 0x1ad00L;
        off.syscalls.getuid = 0x1be50L;
        off.syscalls.isInSandbox = 0x1c4e0L;
        off.syscalls.mmap = 0x1c700L;
        off.syscalls.jitshmCreate = 0x1b590L;
        off.syscalls.cpusetGetAffinity = 0x1cae0L;
        off.syscalls.cpusetSetAffinity = 0x1c2a0L;
        off.syscalls.rtprioThread = 0x1b530L;
        off.syscalls.sysctl = 0x1c300L;
        off.syscalls.netgetiflist = 0x1b870L;
        off.syscalls.close = 0x1b7b0L;
        off.syscalls.ioctl = 0x1aa20L;

        off.kernelData = 0xca0000L;
        off.allproc = 0x33f5d50L;
        off.rootvnode = 0x3c7b510L;

        off.kaslrRetStatic = 0xac1bc1L;
        off.kaslrRetLow16 = 0x1bc1;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x2787ab8L;
        off.oidA_kind = 0x2787accL;
        off.oidA_kindByte3 = 0x2787acfL;
        off.oidA_arg1 = 0x2787ad0L;
        off.oidA_arg1Byte1 = 0x2787ad1L;
        off.oidA_arg1Value = 0x2787aa8L;
        off.oidA_deadSink = 0x2787ad8L;

        off.oidB_base = 0x2787990L;
        off.oidB_kind = 0x27879a4L;
        off.oidB_kindByte3 = 0x27879a7L;
        off.oidB_arg1 = 0x27879a8L;
        off.oidB_arg1Value = 0x27878c0L;
        off.oidB_visible = 0x27879e0L;

        off.oidC_base = 0x2aaa678L;
        off.oidC_kind = 0x2aaa68cL;
        off.oidC_arg1 = 0x2aaa690L;
        off.oidC_arg1Value = 0x3bf8f3cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3bf8f38L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a588e8L;

        off.rodataProbeRva = 0x1107bfaL;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc38;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("9.60", off);
    }

    private static void initialize1000() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "10.00";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b020L;
        off.syscalls.setsockopt = 0x1b930L;
        off.syscalls.read = 0x1ade0L;
        off.syscalls.write = 0x1ad40L;
        off.syscalls.recvfrom = 0x1c280L;
        off.syscalls.getrlimit = 0x1b520L;
        off.syscalls.setrlimit = 0x1b100L;
        off.syscalls.socketpair = 0x1c010L;
        off.syscalls.pipe2 = 0x1aba0L;
        off.syscalls.aioSubmitCmd = 0x1cae0L;
        off.syscalls.aioMultiWait = 0x1b990L;
        off.syscalls.aioMultiPoll = 0x1aa20L;
        off.syscalls.aioMultiCancel = 0x1b970L;
        off.syscalls.getpid = 0x1af60L;
        off.syscalls.getuid = 0x1c0b0L;
        off.syscalls.isInSandbox = 0x1c740L;
        off.syscalls.mmap = 0x1c960L;
        off.syscalls.jitshmCreate = 0x1b7f0L;
        off.syscalls.cpusetGetAffinity = 0x1cd40L;
        off.syscalls.cpusetSetAffinity = 0x1c500L;
        off.syscalls.rtprioThread = 0x1b790L;
        off.syscalls.sysctl = 0x1c560L;
        off.syscalls.netgetiflist = 0x1bad0L;
        off.syscalls.close = 0x1ba10L;
        off.syscalls.ioctl = 0x1ac80L;

        off.kernelData = 0xcc0000L;
        off.allproc = 0x3425d70L;
        off.rootvnode = 0x3c63510L;

        off.kaslrRetStatic = 0xadf87fL;
        off.kaslrRetLow16 = 0xf87f;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x27a8138L;
        off.oidA_kind = 0x27a814cL;
        off.oidA_kindByte3 = 0x27a814fL;
        off.oidA_arg1 = 0x27a8150L;
        off.oidA_arg1Byte1 = 0x27a8151L;
        off.oidA_arg1Value = 0x27a8128L;
        off.oidA_deadSink = 0x27a8158L;

        off.oidB_base = 0x27a8010L;
        off.oidB_kind = 0x27a8024L;
        off.oidB_kindByte3 = 0x27a8027L;
        off.oidB_arg1 = 0x27a8028L;
        off.oidB_arg1Value = 0x27a7f40L;
        off.oidB_visible = 0x27a8060L;

        off.oidC_base = 0x2acadd8L;
        off.oidC_kind = 0x2acadecL;
        off.oidC_arg1 = 0x2acadf0L;
        off.oidC_arg1Value = 0x3be307cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3be3078L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a78978L;

        off.rodataProbeRva = 0x112dae5L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc40;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("10.00", off);
    }

    private static void initialize1001() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "10.01";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b020L;
        off.syscalls.setsockopt = 0x1b930L;
        off.syscalls.read = 0x1ade0L;
        off.syscalls.write = 0x1ad40L;
        off.syscalls.recvfrom = 0x1c280L;
        off.syscalls.getrlimit = 0x1b520L;
        off.syscalls.setrlimit = 0x1b100L;
        off.syscalls.socketpair = 0x1c010L;
        off.syscalls.pipe2 = 0x1aba0L;
        off.syscalls.aioSubmitCmd = 0x1cae0L;
        off.syscalls.aioMultiWait = 0x1b990L;
        off.syscalls.aioMultiPoll = 0x1aa20L;
        off.syscalls.aioMultiCancel = 0x1b970L;
        off.syscalls.getpid = 0x1af60L;
        off.syscalls.getuid = 0x1c0b0L;
        off.syscalls.isInSandbox = 0x1c740L;
        off.syscalls.mmap = 0x1c960L;
        off.syscalls.jitshmCreate = 0x1b7f0L;
        off.syscalls.cpusetGetAffinity = 0x1cd40L;
        off.syscalls.cpusetSetAffinity = 0x1c500L;
        off.syscalls.rtprioThread = 0x1b790L;
        off.syscalls.sysctl = 0x1c560L;
        off.syscalls.netgetiflist = 0x1bad0L;
        off.syscalls.close = 0x1ba10L;
        off.syscalls.ioctl = 0x1ac80L;

        off.kernelData = 0xcc0000L;
        off.allproc = 0x3425d70L;
        off.rootvnode = 0x3c63510L;

        off.kaslrRetStatic = 0xadf87fL;
        off.kaslrRetLow16 = 0xf87f;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x27a8138L;
        off.oidA_kind = 0x27a814cL;
        off.oidA_kindByte3 = 0x27a814fL;
        off.oidA_arg1 = 0x27a8150L;
        off.oidA_arg1Byte1 = 0x27a8151L;
        off.oidA_arg1Value = 0x27a8128L;
        off.oidA_deadSink = 0x27a8158L;

        off.oidB_base = 0x27a8010L;
        off.oidB_kind = 0x27a8024L;
        off.oidB_kindByte3 = 0x27a8027L;
        off.oidB_arg1 = 0x27a8028L;
        off.oidB_arg1Value = 0x27a7f40L;
        off.oidB_visible = 0x27a8060L;

        off.oidC_base = 0x2acadd8L;
        off.oidC_kind = 0x2acadecL;
        off.oidC_arg1 = 0x2acadf0L;
        off.oidC_arg1Value = 0x3be307cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3be3078L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a78978L;

        off.rodataProbeRva = 0x112db73L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc40;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("10.01", off);
    }

    private static void initialize1020() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "10.20";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b020L;
        off.syscalls.setsockopt = 0x1b930L;
        off.syscalls.read = 0x1ade0L;
        off.syscalls.write = 0x1ad40L;
        off.syscalls.recvfrom = 0x1c280L;
        off.syscalls.getrlimit = 0x1b520L;
        off.syscalls.setrlimit = 0x1b100L;
        off.syscalls.socketpair = 0x1c010L;
        off.syscalls.pipe2 = 0x1aba0L;
        off.syscalls.aioSubmitCmd = 0x1cae0L;
        off.syscalls.aioMultiWait = 0x1b990L;
        off.syscalls.aioMultiPoll = 0x1aa20L;
        off.syscalls.aioMultiCancel = 0x1b970L;
        off.syscalls.getpid = 0x1af60L;
        off.syscalls.getuid = 0x1c0b0L;
        off.syscalls.isInSandbox = 0x1c740L;
        off.syscalls.mmap = 0x1c960L;
        off.syscalls.jitshmCreate = 0x1b7f0L;
        off.syscalls.cpusetGetAffinity = 0x1cd40L;
        off.syscalls.cpusetSetAffinity = 0x1c500L;
        off.syscalls.rtprioThread = 0x1b790L;
        off.syscalls.sysctl = 0x1c560L;
        off.syscalls.netgetiflist = 0x1bad0L;
        off.syscalls.close = 0x1ba10L;
        off.syscalls.ioctl = 0x1ac80L;

        off.kernelData = 0xcc0000L;
        off.allproc = 0x3425d70L;
        off.rootvnode = 0x3c63510L;

        off.kaslrRetStatic = 0xadfa9fL;
        off.kaslrRetLow16 = 0xfa9f;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x27a8138L;
        off.oidA_kind = 0x27a814cL;
        off.oidA_kindByte3 = 0x27a814fL;
        off.oidA_arg1 = 0x27a8150L;
        off.oidA_arg1Byte1 = 0x27a8151L;
        off.oidA_arg1Value = 0x27a8128L;
        off.oidA_deadSink = 0x27a8158L;

        off.oidB_base = 0x27a8010L;
        off.oidB_kind = 0x27a8024L;
        off.oidB_kindByte3 = 0x27a8027L;
        off.oidB_arg1 = 0x27a8028L;
        off.oidB_arg1Value = 0x27a7f40L;
        off.oidB_visible = 0x27a8060L;

        off.oidC_base = 0x2acadd8L;
        off.oidC_kind = 0x2acadecL;
        off.oidC_arg1 = 0x2acadf0L;
        off.oidC_arg1Value = 0x3be307cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3be3078L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a78978L;

        off.rodataProbeRva = 0x112daf5L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc40;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("10.20", off);
    }

    private static void initialize1040() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "10.40";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b020L;
        off.syscalls.setsockopt = 0x1b930L;
        off.syscalls.read = 0x1ade0L;
        off.syscalls.write = 0x1ad40L;
        off.syscalls.recvfrom = 0x1c280L;
        off.syscalls.getrlimit = 0x1b520L;
        off.syscalls.setrlimit = 0x1b100L;
        off.syscalls.socketpair = 0x1c010L;
        off.syscalls.pipe2 = 0x1aba0L;
        off.syscalls.aioSubmitCmd = 0x1cae0L;
        off.syscalls.aioMultiWait = 0x1b990L;
        off.syscalls.aioMultiPoll = 0x1aa20L;
        off.syscalls.aioMultiCancel = 0x1b970L;
        off.syscalls.getpid = 0x1af60L;
        off.syscalls.getuid = 0x1c0b0L;
        off.syscalls.isInSandbox = 0x1c740L;
        off.syscalls.mmap = 0x1c960L;
        off.syscalls.jitshmCreate = 0x1b7f0L;
        off.syscalls.cpusetGetAffinity = 0x1cd40L;
        off.syscalls.cpusetSetAffinity = 0x1c500L;
        off.syscalls.rtprioThread = 0x1b790L;
        off.syscalls.sysctl = 0x1c560L;
        off.syscalls.netgetiflist = 0x1bad0L;
        off.syscalls.close = 0x1ba10L;
        off.syscalls.ioctl = 0x1ac80L;

        off.kernelData = 0xcc0000L;
        off.allproc = 0x3425d70L;
        off.rootvnode = 0x3c63510L;

        off.kaslrRetStatic = 0xadfa9fL;
        off.kaslrRetLow16 = 0xfa9f;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x27a8138L;
        off.oidA_kind = 0x27a814cL;
        off.oidA_kindByte3 = 0x27a814fL;
        off.oidA_arg1 = 0x27a8150L;
        off.oidA_arg1Byte1 = 0x27a8151L;
        off.oidA_arg1Value = 0x27a8128L;
        off.oidA_deadSink = 0x27a8158L;

        off.oidB_base = 0x27a8010L;
        off.oidB_kind = 0x27a8024L;
        off.oidB_kindByte3 = 0x27a8027L;
        off.oidB_arg1 = 0x27a8028L;
        off.oidB_arg1Value = 0x27a7f40L;
        off.oidB_visible = 0x27a8060L;

        off.oidC_base = 0x2acadd8L;
        off.oidC_kind = 0x2acadecL;
        off.oidC_arg1 = 0x2acadf0L;
        off.oidC_arg1Value = 0x3be307cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3be3078L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a78978L;

        off.rodataProbeRva = 0x112db1fL;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc40;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("10.40", off);
    }

    private static void initialize1060() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "10.60";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b020L;
        off.syscalls.setsockopt = 0x1b930L;
        off.syscalls.read = 0x1ade0L;
        off.syscalls.write = 0x1ad40L;
        off.syscalls.recvfrom = 0x1c280L;
        off.syscalls.getrlimit = 0x1b520L;
        off.syscalls.setrlimit = 0x1b100L;
        off.syscalls.socketpair = 0x1c010L;
        off.syscalls.pipe2 = 0x1aba0L;
        off.syscalls.aioSubmitCmd = 0x1cae0L;
        off.syscalls.aioMultiWait = 0x1b990L;
        off.syscalls.aioMultiPoll = 0x1aa20L;
        off.syscalls.aioMultiCancel = 0x1b970L;
        off.syscalls.getpid = 0x1af60L;
        off.syscalls.getuid = 0x1c0b0L;
        off.syscalls.isInSandbox = 0x1c740L;
        off.syscalls.mmap = 0x1c960L;
        off.syscalls.jitshmCreate = 0x1b7f0L;
        off.syscalls.cpusetGetAffinity = 0x1cd40L;
        off.syscalls.cpusetSetAffinity = 0x1c500L;
        off.syscalls.rtprioThread = 0x1b790L;
        off.syscalls.sysctl = 0x1c560L;
        off.syscalls.netgetiflist = 0x1bad0L;
        off.syscalls.close = 0x1ba10L;
        off.syscalls.ioctl = 0x1ac80L;

        off.kernelData = 0xcc0000L;
        off.allproc = 0x3425d70L;
        off.rootvnode = 0x3c63510L;

        off.kaslrRetStatic = 0xadfa7fL;
        off.kaslrRetLow16 = 0xfa7f;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x27a8138L;
        off.oidA_kind = 0x27a814cL;
        off.oidA_kindByte3 = 0x27a814fL;
        off.oidA_arg1 = 0x27a8150L;
        off.oidA_arg1Byte1 = 0x27a8151L;
        off.oidA_arg1Value = 0x27a8128L;
        off.oidA_deadSink = 0x27a8158L;

        off.oidB_base = 0x27a8010L;
        off.oidB_kind = 0x27a8024L;
        off.oidB_kindByte3 = 0x27a8027L;
        off.oidB_arg1 = 0x27a8028L;
        off.oidB_arg1Value = 0x27a7f40L;
        off.oidB_visible = 0x27a8060L;

        off.oidC_base = 0x2acadd8L;
        off.oidC_kind = 0x2acadecL;
        off.oidC_arg1 = 0x2acadf0L;
        off.oidC_arg1Value = 0x3be307cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3be3078L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a78978L;

        off.rodataProbeRva = 0x112d569L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc40;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("10.60", off);
    }

    private static void initialize1100() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "11.00";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b340L;
        off.syscalls.setsockopt = 0x1bc50L;
        off.syscalls.read = 0x1b100L;
        off.syscalls.write = 0x1b060L;
        off.syscalls.recvfrom = 0x1c5a0L;
        off.syscalls.getrlimit = 0x1b840L;
        off.syscalls.setrlimit = 0x1b420L;
        off.syscalls.socketpair = 0x1c330L;
        off.syscalls.pipe2 = 0x1aec0L;
        off.syscalls.aioSubmitCmd = 0x1ce00L;
        off.syscalls.aioMultiWait = 0x1bcb0L;
        off.syscalls.aioMultiPoll = 0x1ad40L;
        off.syscalls.aioMultiCancel = 0x1bc90L;
        off.syscalls.getpid = 0x1b280L;
        off.syscalls.getuid = 0x1c3d0L;
        off.syscalls.isInSandbox = 0x1ca60L;
        off.syscalls.mmap = 0x1cc80L;
        off.syscalls.jitshmCreate = 0x1bb10L;
        off.syscalls.cpusetGetAffinity = 0x1d060L;
        off.syscalls.cpusetSetAffinity = 0x1c820L;
        off.syscalls.rtprioThread = 0x1bab0L;
        off.syscalls.sysctl = 0x1c880L;
        off.syscalls.netgetiflist = 0x1bdf0L;
        off.syscalls.close = 0x1bd30L;
        off.syscalls.ioctl = 0x1afa0L;

        off.kernelData = 0xd30000L;
        off.allproc = 0x35a5d70L;
        off.rootvnode = 0x3de7510L;

        off.kaslrRetStatic = 0xb52b61L;
        off.kaslrRetLow16 = 0x2b61;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x2929e58L;
        off.oidA_kind = 0x2929e6cL;
        off.oidA_kindByte3 = 0x2929e6fL;
        off.oidA_arg1 = 0x2929e70L;
        off.oidA_arg1Byte1 = 0x2929e71L;
        off.oidA_arg1Value = 0x2929e48L;
        off.oidA_deadSink = 0x2929e78L;

        off.oidB_base = 0x2929d30L;
        off.oidB_kind = 0x2929d44L;
        off.oidB_kindByte3 = 0x2929d47L;
        off.oidB_arg1 = 0x2929d48L;
        off.oidB_arg1Value = 0x2929c60L;
        off.oidB_visible = 0x2929d80L;

        off.oidC_base = 0x2c4cb18L;
        off.oidC_kind = 0x2c4cb2cL;
        off.oidC_arg1 = 0x2c4cb30L;
        off.oidC_arg1Value = 0x3d670bcL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3d670b8L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1af9f18L;

        off.rodataProbeRva = 0x11a7abaL;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc40;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("11.00", off);
    }

    private static void initialize1120() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "11.20";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b340L;
        off.syscalls.setsockopt = 0x1bc50L;
        off.syscalls.read = 0x1b100L;
        off.syscalls.write = 0x1b060L;
        off.syscalls.recvfrom = 0x1c5a0L;
        off.syscalls.getrlimit = 0x1b840L;
        off.syscalls.setrlimit = 0x1b420L;
        off.syscalls.socketpair = 0x1c330L;
        off.syscalls.pipe2 = 0x1aec0L;
        off.syscalls.aioSubmitCmd = 0x1ce00L;
        off.syscalls.aioMultiWait = 0x1bcb0L;
        off.syscalls.aioMultiPoll = 0x1ad40L;
        off.syscalls.aioMultiCancel = 0x1bc90L;
        off.syscalls.getpid = 0x1b280L;
        off.syscalls.getuid = 0x1c3d0L;
        off.syscalls.isInSandbox = 0x1ca60L;
        off.syscalls.mmap = 0x1cc80L;
        off.syscalls.jitshmCreate = 0x1bb10L;
        off.syscalls.cpusetGetAffinity = 0x1d060L;
        off.syscalls.cpusetSetAffinity = 0x1c820L;
        off.syscalls.rtprioThread = 0x1bab0L;
        off.syscalls.sysctl = 0x1c880L;
        off.syscalls.netgetiflist = 0x1bdf0L;
        off.syscalls.close = 0x1bd30L;
        off.syscalls.ioctl = 0x1afa0L;

        off.kernelData = 0xd30000L;
        off.allproc = 0x35a5d70L;
        off.rootvnode = 0x3de7510L;

        off.kaslrRetStatic = 0xb52b61L;
        off.kaslrRetLow16 = 0x2b61;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x2929e58L;
        off.oidA_kind = 0x2929e6cL;
        off.oidA_kindByte3 = 0x2929e6fL;
        off.oidA_arg1 = 0x2929e70L;
        off.oidA_arg1Byte1 = 0x2929e71L;
        off.oidA_arg1Value = 0x2929e48L;
        off.oidA_deadSink = 0x2929e78L;

        off.oidB_base = 0x2929d30L;
        off.oidB_kind = 0x2929d44L;
        off.oidB_kindByte3 = 0x2929d47L;
        off.oidB_arg1 = 0x2929d48L;
        off.oidB_arg1Value = 0x2929c60L;
        off.oidB_visible = 0x2929d80L;

        off.oidC_base = 0x2c4cb18L;
        off.oidC_kind = 0x2c4cb2cL;
        off.oidC_arg1 = 0x2c4cb30L;
        off.oidC_arg1Value = 0x3d670bcL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3d670b8L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1af9f18L;

        off.rodataProbeRva = 0x11a7625L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc40;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("11.20", off);
    }

    /* 11.40 is absent from the original Relapse-Exploit offset set (that
     * firmware image is missing the modules the offsets are read out of).
     * These values come from notmaj0r's relapse port, as integrated by
     * itsPLK/ps5-y2jb-autoloader. */
    private static void initialize1140() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "11.40";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b340L;
        off.syscalls.setsockopt = 0x1bc50L;
        off.syscalls.read = 0x1b100L;
        off.syscalls.write = 0x1b060L;
        off.syscalls.recvfrom = 0x1c5a0L;
        off.syscalls.getrlimit = 0x1b840L;
        off.syscalls.setrlimit = 0x1b420L;
        off.syscalls.socketpair = 0x1c330L;
        off.syscalls.pipe2 = 0x1aec0L;
        off.syscalls.aioSubmitCmd = 0x1ce00L;
        off.syscalls.aioMultiWait = 0x1bcb0L;
        off.syscalls.aioMultiPoll = 0x1ad40L;
        off.syscalls.aioMultiCancel = 0x1bc90L;
        off.syscalls.getpid = 0x1b280L;
        off.syscalls.getuid = 0x1c3d0L;
        off.syscalls.isInSandbox = 0x1ca60L;
        off.syscalls.mmap = 0x1cc80L;
        off.syscalls.jitshmCreate = 0x1bb10L;
        off.syscalls.cpusetGetAffinity = 0x1d060L;
        off.syscalls.cpusetSetAffinity = 0x1c820L;
        off.syscalls.rtprioThread = 0x1bab0L;
        off.syscalls.sysctl = 0x1c880L;
        off.syscalls.netgetiflist = 0x1bdf0L;
        off.syscalls.close = 0x1bd30L;
        off.syscalls.ioctl = 0x1afa0L;

        off.kernelData = 0xd30000L;
        off.allproc = 0x35a5d70L;
        off.rootvnode = 0x3de7510L;

        off.kaslrRetStatic = 0xb53751L;
        off.kaslrRetLow16 = 0x3751;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x2929e90L;
        off.oidA_kind = 0x2929eacL;
        off.oidA_kindByte3 = 0x2929eafL;
        off.oidA_arg1 = 0x2929eb0L;
        off.oidA_arg1Byte1 = 0x2929eb1L;
        off.oidA_arg1Value = 0x2929e88L;
        off.oidA_deadSink = 0x2929eb8L;

        off.oidB_base = 0x2929d68L;
        off.oidB_kind = 0x2929d84L;
        off.oidB_kindByte3 = 0x2929d87L;
        off.oidB_arg1 = 0x2929d88L;
        off.oidB_arg1Value = 0x2929ca0L;
        off.oidB_visible = 0x2929dc0L;

        off.oidC_base = 0x2c4cb50L;
        off.oidC_kind = 0x2c4cb6cL;
        off.oidC_arg1 = 0x2c4cb70L;
        off.oidC_arg1Value = 0x3d670bcL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3d670b8L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x35686d0L;

        off.rodataProbeRva = 0x11a7c0eL;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc40;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("11.40", off);
    }

    private static void initialize1160() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "11.60";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b340L;
        off.syscalls.setsockopt = 0x1bc50L;
        off.syscalls.read = 0x1b100L;
        off.syscalls.write = 0x1b060L;
        off.syscalls.recvfrom = 0x1c5a0L;
        off.syscalls.getrlimit = 0x1b840L;
        off.syscalls.setrlimit = 0x1b420L;
        off.syscalls.socketpair = 0x1c330L;
        off.syscalls.pipe2 = 0x1aec0L;
        off.syscalls.aioSubmitCmd = 0x1ce00L;
        off.syscalls.aioMultiWait = 0x1bcb0L;
        off.syscalls.aioMultiPoll = 0x1ad40L;
        off.syscalls.aioMultiCancel = 0x1bc90L;
        off.syscalls.getpid = 0x1b280L;
        off.syscalls.getuid = 0x1c3d0L;
        off.syscalls.isInSandbox = 0x1ca60L;
        off.syscalls.mmap = 0x1cc80L;
        off.syscalls.jitshmCreate = 0x1bb10L;
        off.syscalls.cpusetGetAffinity = 0x1d060L;
        off.syscalls.cpusetSetAffinity = 0x1c820L;
        off.syscalls.rtprioThread = 0x1bab0L;
        off.syscalls.sysctl = 0x1c880L;
        off.syscalls.netgetiflist = 0x1bdf0L;
        off.syscalls.close = 0x1bd30L;
        off.syscalls.ioctl = 0x1afa0L;

        off.kernelData = 0xd30000L;
        off.allproc = 0x35a5d70L;
        off.rootvnode = 0x3de7510L;

        off.kaslrRetStatic = 0xb53301L;
        off.kaslrRetLow16 = 0x3301;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x2929ed0L;
        off.oidA_kind = 0x2929eecL;
        off.oidA_kindByte3 = 0x2929eefL;
        off.oidA_arg1 = 0x2929ef0L;
        off.oidA_arg1Byte1 = 0x2929ef1L;
        off.oidA_arg1Value = 0x2929ec8L;
        off.oidA_deadSink = 0x2929ef8L;

        off.oidB_base = 0x2929da8L;
        off.oidB_kind = 0x2929dc4L;
        off.oidB_kindByte3 = 0x2929dc7L;
        off.oidB_arg1 = 0x2929dc8L;
        off.oidB_arg1Value = 0x2929ce0L;
        off.oidB_visible = 0x2929e00L;

        off.oidC_base = 0x2c4cb90L;
        off.oidC_kind = 0x2c4cbacL;
        off.oidC_arg1 = 0x2c4cbb0L;
        off.oidC_arg1Value = 0x3d670bcL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3d670b8L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x3b77e20L;

        off.rodataProbeRva = 0x11a7987L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc40;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("11.60", off);
    }

    private static void initialize1200() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "12.00";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b890L;
        off.syscalls.setsockopt = 0x1c1a0L;
        off.syscalls.read = 0x1b650L;
        off.syscalls.write = 0x1b5b0L;
        off.syscalls.recvfrom = 0x1caf0L;
        off.syscalls.getrlimit = 0x1bd90L;
        off.syscalls.setrlimit = 0x1b970L;
        off.syscalls.socketpair = 0x1c880L;
        off.syscalls.pipe2 = 0x1b410L;
        off.syscalls.aioSubmitCmd = 0x1d350L;
        off.syscalls.aioMultiWait = 0x1c200L;
        off.syscalls.aioMultiPoll = 0x1b290L;
        off.syscalls.aioMultiCancel = 0x1c1e0L;
        off.syscalls.getpid = 0x1b7d0L;
        off.syscalls.getuid = 0x1c920L;
        off.syscalls.isInSandbox = 0x1cfb0L;
        off.syscalls.mmap = 0x1d1d0L;
        off.syscalls.jitshmCreate = 0x1c060L;
        off.syscalls.cpusetGetAffinity = 0x1d5b0L;
        off.syscalls.cpusetSetAffinity = 0x1cd70L;
        off.syscalls.rtprioThread = 0x1c000L;
        off.syscalls.sysctl = 0x1cdd0L;
        off.syscalls.netgetiflist = 0x1c340L;
        off.syscalls.close = 0x1c280L;
        off.syscalls.ioctl = 0x1b4f0L;

        off.kernelData = 0xd50000L;
        off.allproc = 0x35d5e00L;
        off.rootvnode = 0x3e27510L;

        off.kaslrRetStatic = 0xb6ec71L;
        off.kaslrRetLow16 = 0xec71;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x294b408L;
        off.oidA_kind = 0x294b41cL;
        off.oidA_kindByte3 = 0x294b41fL;
        off.oidA_arg1 = 0x294b420L;
        off.oidA_arg1Byte1 = 0x294b421L;
        off.oidA_arg1Value = 0x294b3f8L;
        off.oidA_deadSink = 0x294b428L;

        off.oidB_base = 0x294b2e0L;
        off.oidB_kind = 0x294b2f4L;
        off.oidB_kindByte3 = 0x294b2f7L;
        off.oidB_arg1 = 0x294b2f8L;
        off.oidB_arg1Value = 0x294b210L;
        off.oidB_visible = 0x294b330L;

        off.oidC_base = 0x2c6e108L;
        off.oidC_kind = 0x2c6e11cL;
        off.oidC_arg1 = 0x2c6e120L;
        off.oidC_arg1Value = 0x3da32bcL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3da32b8L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1b4dd78L;

        off.rodataProbeRva = 0x11c8f51L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc48;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("12.00", off);
    }

    private static void initialize1202() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "12.02";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b890L;
        off.syscalls.setsockopt = 0x1c1a0L;
        off.syscalls.read = 0x1b650L;
        off.syscalls.write = 0x1b5b0L;
        off.syscalls.recvfrom = 0x1caf0L;
        off.syscalls.getrlimit = 0x1bd90L;
        off.syscalls.setrlimit = 0x1b970L;
        off.syscalls.socketpair = 0x1c880L;
        off.syscalls.pipe2 = 0x1b410L;
        off.syscalls.aioSubmitCmd = 0x1d350L;
        off.syscalls.aioMultiWait = 0x1c200L;
        off.syscalls.aioMultiPoll = 0x1b290L;
        off.syscalls.aioMultiCancel = 0x1c1e0L;
        off.syscalls.getpid = 0x1b7d0L;
        off.syscalls.getuid = 0x1c920L;
        off.syscalls.isInSandbox = 0x1cfb0L;
        off.syscalls.mmap = 0x1d1d0L;
        off.syscalls.jitshmCreate = 0x1c060L;
        off.syscalls.cpusetGetAffinity = 0x1d5b0L;
        off.syscalls.cpusetSetAffinity = 0x1cd70L;
        off.syscalls.rtprioThread = 0x1c000L;
        off.syscalls.sysctl = 0x1cdd0L;
        off.syscalls.netgetiflist = 0x1c340L;
        off.syscalls.close = 0x1c280L;
        off.syscalls.ioctl = 0x1b4f0L;

        off.kernelData = 0xd50000L;
        off.allproc = 0x35d5e00L;
        off.rootvnode = 0x3e27510L;

        off.kaslrRetStatic = 0xb6ec71L;
        off.kaslrRetLow16 = 0xec71;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x294b408L;
        off.oidA_kind = 0x294b41cL;
        off.oidA_kindByte3 = 0x294b41fL;
        off.oidA_arg1 = 0x294b420L;
        off.oidA_arg1Byte1 = 0x294b421L;
        off.oidA_arg1Value = 0x294b3f8L;
        off.oidA_deadSink = 0x294b428L;

        off.oidB_base = 0x294b2e0L;
        off.oidB_kind = 0x294b2f4L;
        off.oidB_kindByte3 = 0x294b2f7L;
        off.oidB_arg1 = 0x294b2f8L;
        off.oidB_arg1Value = 0x294b210L;
        off.oidB_visible = 0x294b330L;

        off.oidC_base = 0x2c6e108L;
        off.oidC_kind = 0x2c6e11cL;
        off.oidC_arg1 = 0x2c6e120L;
        off.oidC_arg1Value = 0x3da32bcL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3da32b8L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1b1ab78L;

        off.rodataProbeRva = 0x11c8da2L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc48;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("12.02", off);
    }

    private static void initialize1220() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "12.20";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b890L;
        off.syscalls.setsockopt = 0x1c1a0L;
        off.syscalls.read = 0x1b650L;
        off.syscalls.write = 0x1b5b0L;
        off.syscalls.recvfrom = 0x1caf0L;
        off.syscalls.getrlimit = 0x1bd90L;
        off.syscalls.setrlimit = 0x1b970L;
        off.syscalls.socketpair = 0x1c880L;
        off.syscalls.pipe2 = 0x1b410L;
        off.syscalls.aioSubmitCmd = 0x1d350L;
        off.syscalls.aioMultiWait = 0x1c200L;
        off.syscalls.aioMultiPoll = 0x1b290L;
        off.syscalls.aioMultiCancel = 0x1c1e0L;
        off.syscalls.getpid = 0x1b7d0L;
        off.syscalls.getuid = 0x1c920L;
        off.syscalls.isInSandbox = 0x1cfb0L;
        off.syscalls.mmap = 0x1d1d0L;
        off.syscalls.jitshmCreate = 0x1c060L;
        off.syscalls.cpusetGetAffinity = 0x1d5b0L;
        off.syscalls.cpusetSetAffinity = 0x1cd70L;
        off.syscalls.rtprioThread = 0x1c000L;
        off.syscalls.sysctl = 0x1cdd0L;
        off.syscalls.netgetiflist = 0x1c340L;
        off.syscalls.close = 0x1c280L;
        off.syscalls.ioctl = 0x1b4f0L;

        off.kernelData = 0xd50000L;
        off.allproc = 0x35d5e00L;
        off.rootvnode = 0x3e27510L;

        off.kaslrRetStatic = 0xb6eaf1L;
        off.kaslrRetLow16 = 0xeaf1;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x294b408L;
        off.oidA_kind = 0x294b41cL;
        off.oidA_kindByte3 = 0x294b41fL;
        off.oidA_arg1 = 0x294b420L;
        off.oidA_arg1Byte1 = 0x294b421L;
        off.oidA_arg1Value = 0x294b3f8L;
        off.oidA_deadSink = 0x294b428L;

        off.oidB_base = 0x294b2e0L;
        off.oidB_kind = 0x294b2f4L;
        off.oidB_kindByte3 = 0x294b2f7L;
        off.oidB_arg1 = 0x294b2f8L;
        off.oidB_arg1Value = 0x294b210L;
        off.oidB_visible = 0x294b330L;

        off.oidC_base = 0x2c6e108L;
        off.oidC_kind = 0x2c6e11cL;
        off.oidC_arg1 = 0x2c6e120L;
        off.oidC_arg1Value = 0x3da32bcL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3da32b8L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1b1ab78L;

        off.rodataProbeRva = 0x11c9013L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc48;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("12.20", off);
    }

    private static void initialize1240() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "12.40";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b8b0L;
        off.syscalls.setsockopt = 0x1c1c0L;
        off.syscalls.read = 0x1b670L;
        off.syscalls.write = 0x1b5d0L;
        off.syscalls.recvfrom = 0x1cb10L;
        off.syscalls.getrlimit = 0x1bdb0L;
        off.syscalls.setrlimit = 0x1b990L;
        off.syscalls.socketpair = 0x1c8a0L;
        off.syscalls.pipe2 = 0x1b430L;
        off.syscalls.aioSubmitCmd = 0x1d370L;
        off.syscalls.aioMultiWait = 0x1c220L;
        off.syscalls.aioMultiPoll = 0x1b2b0L;
        off.syscalls.aioMultiCancel = 0x1c200L;
        off.syscalls.getpid = 0x1b7f0L;
        off.syscalls.getuid = 0x1c940L;
        off.syscalls.isInSandbox = 0x1cfd0L;
        off.syscalls.mmap = 0x1d1f0L;
        off.syscalls.jitshmCreate = 0x1c080L;
        off.syscalls.cpusetGetAffinity = 0x1d5d0L;
        off.syscalls.cpusetSetAffinity = 0x1cd90L;
        off.syscalls.rtprioThread = 0x1c020L;
        off.syscalls.sysctl = 0x1cdf0L;
        off.syscalls.netgetiflist = 0x1c360L;
        off.syscalls.close = 0x1c2a0L;
        off.syscalls.ioctl = 0x1b510L;

        off.kernelData = 0xd50000L;
        off.allproc = 0x35d5e00L;
        off.rootvnode = 0x3e27510L;

        off.kaslrRetStatic = 0xb6eaf1L;
        off.kaslrRetLow16 = 0xeaf1;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x294b408L;
        off.oidA_kind = 0x294b41cL;
        off.oidA_kindByte3 = 0x294b41fL;
        off.oidA_arg1 = 0x294b420L;
        off.oidA_arg1Byte1 = 0x294b421L;
        off.oidA_arg1Value = 0x294b3f8L;
        off.oidA_deadSink = 0x294b428L;

        off.oidB_base = 0x294b2e0L;
        off.oidB_kind = 0x294b2f4L;
        off.oidB_kindByte3 = 0x294b2f7L;
        off.oidB_arg1 = 0x294b2f8L;
        off.oidB_arg1Value = 0x294b210L;
        off.oidB_visible = 0x294b330L;

        off.oidC_base = 0x2c6e108L;
        off.oidC_kind = 0x2c6e11cL;
        off.oidC_arg1 = 0x2c6e120L;
        off.oidC_arg1Value = 0x3da32bcL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3da32b8L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1b1ab78L;

        off.rodataProbeRva = 0x11c8e15L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc48;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("12.40", off);
    }

    private static void initialize1260() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "12.60";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b8b0L;
        off.syscalls.setsockopt = 0x1c1c0L;
        off.syscalls.read = 0x1b670L;
        off.syscalls.write = 0x1b5d0L;
        off.syscalls.recvfrom = 0x1cb10L;
        off.syscalls.getrlimit = 0x1bdb0L;
        off.syscalls.setrlimit = 0x1b990L;
        off.syscalls.socketpair = 0x1c8a0L;
        off.syscalls.pipe2 = 0x1b430L;
        off.syscalls.aioSubmitCmd = 0x1d370L;
        off.syscalls.aioMultiWait = 0x1c220L;
        off.syscalls.aioMultiPoll = 0x1b2b0L;
        off.syscalls.aioMultiCancel = 0x1c200L;
        off.syscalls.getpid = 0x1b7f0L;
        off.syscalls.getuid = 0x1c940L;
        off.syscalls.isInSandbox = 0x1cfd0L;
        off.syscalls.mmap = 0x1d1f0L;
        off.syscalls.jitshmCreate = 0x1c080L;
        off.syscalls.cpusetGetAffinity = 0x1d5d0L;
        off.syscalls.cpusetSetAffinity = 0x1cd90L;
        off.syscalls.rtprioThread = 0x1c020L;
        off.syscalls.sysctl = 0x1cdf0L;
        off.syscalls.netgetiflist = 0x1c360L;
        off.syscalls.close = 0x1c2a0L;
        off.syscalls.ioctl = 0x1b510L;

        off.kernelData = 0xd50000L;
        off.allproc = 0x35d5e00L;
        off.rootvnode = 0x3e27510L;

        off.kaslrRetStatic = 0xb6eb51L;
        off.kaslrRetLow16 = 0xeb51;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x294b408L;
        off.oidA_kind = 0x294b41cL;
        off.oidA_kindByte3 = 0x294b41fL;
        off.oidA_arg1 = 0x294b420L;
        off.oidA_arg1Byte1 = 0x294b421L;
        off.oidA_arg1Value = 0x294b3f8L;
        off.oidA_deadSink = 0x294b428L;

        off.oidB_base = 0x294b2e0L;
        off.oidB_kind = 0x294b2f4L;
        off.oidB_kindByte3 = 0x294b2f7L;
        off.oidB_arg1 = 0x294b2f8L;
        off.oidB_arg1Value = 0x294b210L;
        off.oidB_visible = 0x294b330L;

        off.oidC_base = 0x2c6e108L;
        off.oidC_kind = 0x2c6e11cL;
        off.oidC_arg1 = 0x2c6e120L;
        off.oidC_arg1Value = 0x3da32bcL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3da32b8L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1b1ab78L;

        off.rodataProbeRva = 0x11c8e92L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc48;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("12.60", off);
    }

    private static void initialize1270() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "12.70";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b8b0L;
        off.syscalls.setsockopt = 0x1c1c0L;
        off.syscalls.read = 0x1b670L;
        off.syscalls.write = 0x1b5d0L;
        off.syscalls.recvfrom = 0x1cb10L;
        off.syscalls.getrlimit = 0x1bdb0L;
        off.syscalls.setrlimit = 0x1b990L;
        off.syscalls.socketpair = 0x1c8a0L;
        off.syscalls.pipe2 = 0x1b430L;
        off.syscalls.aioSubmitCmd = 0x1d370L;
        off.syscalls.aioMultiWait = 0x1c220L;
        off.syscalls.aioMultiPoll = 0x1b2b0L;
        off.syscalls.aioMultiCancel = 0x1c200L;
        off.syscalls.getpid = 0x1b7f0L;
        off.syscalls.getuid = 0x1c940L;
        off.syscalls.isInSandbox = 0x1cfd0L;
        off.syscalls.mmap = 0x1d1f0L;
        off.syscalls.jitshmCreate = 0x1c080L;
        off.syscalls.cpusetGetAffinity = 0x1d5d0L;
        off.syscalls.cpusetSetAffinity = 0x1cd90L;
        off.syscalls.rtprioThread = 0x1c020L;
        off.syscalls.sysctl = 0x1cdf0L;
        off.syscalls.netgetiflist = 0x1c360L;
        off.syscalls.close = 0x1c2a0L;
        off.syscalls.ioctl = 0x1b510L;

        off.kernelData = 0xd50000L;
        off.allproc = 0x35d5e00L;
        off.rootvnode = 0x3e27510L;

        off.kaslrRetStatic = 0xb6eb51L;
        off.kaslrRetLow16 = 0xeb51;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x294b408L;
        off.oidA_kind = 0x294b41cL;
        off.oidA_kindByte3 = 0x294b41fL;
        off.oidA_arg1 = 0x294b420L;
        off.oidA_arg1Byte1 = 0x294b421L;
        off.oidA_arg1Value = 0x294b3f8L;
        off.oidA_deadSink = 0x294b428L;

        off.oidB_base = 0x294b2e0L;
        off.oidB_kind = 0x294b2f4L;
        off.oidB_kindByte3 = 0x294b2f7L;
        off.oidB_arg1 = 0x294b2f8L;
        off.oidB_arg1Value = 0x294b210L;
        off.oidB_visible = 0x294b330L;

        off.oidC_base = 0x2c6e108L;
        off.oidC_kind = 0x2c6e11cL;
        off.oidC_arg1 = 0x2c6e120L;
        off.oidC_arg1Value = 0x3da32bcL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3da32b8L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1b1ab78L;

        off.rodataProbeRva = 0x11c86d5L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc48;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("12.70", off);
    }

    private static void initialize1300() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "13.00";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b920L;
        off.syscalls.setsockopt = 0x1c230L;
        off.syscalls.read = 0x1b6e0L;
        off.syscalls.write = 0x1b640L;
        off.syscalls.recvfrom = 0x1cb80L;
        off.syscalls.getrlimit = 0x1be20L;
        off.syscalls.setrlimit = 0x1ba00L;
        off.syscalls.socketpair = 0x1c910L;
        off.syscalls.pipe2 = 0x1b4a0L;
        off.syscalls.aioSubmitCmd = 0x1d3e0L;
        off.syscalls.aioMultiWait = 0x1c290L;
        off.syscalls.aioMultiPoll = 0x1b320L;
        off.syscalls.aioMultiCancel = 0x1c270L;
        off.syscalls.getpid = 0x1b860L;
        off.syscalls.getuid = 0x1c9b0L;
        off.syscalls.isInSandbox = 0x1d040L;
        off.syscalls.mmap = 0x1d260L;
        off.syscalls.jitshmCreate = 0x1c0f0L;
        off.syscalls.cpusetGetAffinity = 0x1d640L;
        off.syscalls.cpusetSetAffinity = 0x1ce00L;
        off.syscalls.rtprioThread = 0x1c090L;
        off.syscalls.sysctl = 0x1ce60L;
        off.syscalls.netgetiflist = 0x1c3d0L;
        off.syscalls.close = 0x1c310L;
        off.syscalls.ioctl = 0x1b580L;

        off.kernelData = 0xcb0000L;
        off.allproc = 0x3575e00L;
        off.rootvnode = 0x3de3510L;

        off.kaslrRetStatic = 0xad8582L;
        off.kaslrRetLow16 = 0x8582;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x28bec88L;
        off.oidA_kind = 0x28bec9cL;
        off.oidA_kindByte3 = 0x28bec9fL;
        off.oidA_arg1 = 0x28beca0L;
        off.oidA_arg1Byte1 = 0x28beca1L;
        off.oidA_arg1Value = 0x28bec78L;
        off.oidA_deadSink = 0x28beca8L;

        off.oidB_base = 0x28beb60L;
        off.oidB_kind = 0x28beb74L;
        off.oidB_kindByte3 = 0x28beb77L;
        off.oidB_arg1 = 0x28beb78L;
        off.oidB_arg1Value = 0x28bea90L;
        off.oidB_visible = 0x28bebb0L;

        off.oidC_base = 0x2be1958L;
        off.oidC_kind = 0x2be196cL;
        off.oidC_arg1 = 0x2be1970L;
        off.oidC_arg1Value = 0x3d5e73cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3d5e738L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a8ba78L;

        off.rodataProbeRva = 0x13678a5L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc48;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("13.00", off);
    }

    private static void initialize1320() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "13.20";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b920L;
        off.syscalls.setsockopt = 0x1c230L;
        off.syscalls.read = 0x1b6e0L;
        off.syscalls.write = 0x1b640L;
        off.syscalls.recvfrom = 0x1cb80L;
        off.syscalls.getrlimit = 0x1be20L;
        off.syscalls.setrlimit = 0x1ba00L;
        off.syscalls.socketpair = 0x1c910L;
        off.syscalls.pipe2 = 0x1b4a0L;
        off.syscalls.aioSubmitCmd = 0x1d3e0L;
        off.syscalls.aioMultiWait = 0x1c290L;
        off.syscalls.aioMultiPoll = 0x1b320L;
        off.syscalls.aioMultiCancel = 0x1c270L;
        off.syscalls.getpid = 0x1b860L;
        off.syscalls.getuid = 0x1c9b0L;
        off.syscalls.isInSandbox = 0x1d040L;
        off.syscalls.mmap = 0x1d260L;
        off.syscalls.jitshmCreate = 0x1c0f0L;
        off.syscalls.cpusetGetAffinity = 0x1d640L;
        off.syscalls.cpusetSetAffinity = 0x1ce00L;
        off.syscalls.rtprioThread = 0x1c090L;
        off.syscalls.sysctl = 0x1ce60L;
        off.syscalls.netgetiflist = 0x1c3d0L;
        off.syscalls.close = 0x1c310L;
        off.syscalls.ioctl = 0x1b580L;

        off.kernelData = 0xcb0000L;
        off.allproc = 0x3575e00L;
        off.rootvnode = 0x3de3510L;

        off.kaslrRetStatic = 0xad8790L;
        off.kaslrRetLow16 = 0x8790;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x28bec88L;
        off.oidA_kind = 0x28bec9cL;
        off.oidA_kindByte3 = 0x28bec9fL;
        off.oidA_arg1 = 0x28beca0L;
        off.oidA_arg1Byte1 = 0x28beca1L;
        off.oidA_arg1Value = 0x28bec78L;
        off.oidA_deadSink = 0x28beca8L;

        off.oidB_base = 0x28beb60L;
        off.oidB_kind = 0x28beb74L;
        off.oidB_kindByte3 = 0x28beb77L;
        off.oidB_arg1 = 0x28beb78L;
        off.oidB_arg1Value = 0x28bea90L;
        off.oidB_visible = 0x28bebb0L;

        off.oidC_base = 0x2be1958L;
        off.oidC_kind = 0x2be196cL;
        off.oidC_arg1 = 0x2be1970L;
        off.oidC_arg1Value = 0x3d5e73cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3d5e738L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a8ba78L;

        off.rodataProbeRva = 0x1367c97L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc48;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("13.20", off);
    }

    private static void initialize1340() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "13.40";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b920L;
        off.syscalls.setsockopt = 0x1c230L;
        off.syscalls.read = 0x1b6e0L;
        off.syscalls.write = 0x1b640L;
        off.syscalls.recvfrom = 0x1cb80L;
        off.syscalls.getrlimit = 0x1be20L;
        off.syscalls.setrlimit = 0x1ba00L;
        off.syscalls.socketpair = 0x1c910L;
        off.syscalls.pipe2 = 0x1b4a0L;
        off.syscalls.aioSubmitCmd = 0x1d3e0L;
        off.syscalls.aioMultiWait = 0x1c290L;
        off.syscalls.aioMultiPoll = 0x1b320L;
        off.syscalls.aioMultiCancel = 0x1c270L;
        off.syscalls.getpid = 0x1b860L;
        off.syscalls.getuid = 0x1c9b0L;
        off.syscalls.isInSandbox = 0x1d040L;
        off.syscalls.mmap = 0x1d260L;
        off.syscalls.jitshmCreate = 0x1c0f0L;
        off.syscalls.cpusetGetAffinity = 0x1d640L;
        off.syscalls.cpusetSetAffinity = 0x1ce00L;
        off.syscalls.rtprioThread = 0x1c090L;
        off.syscalls.sysctl = 0x1ce60L;
        off.syscalls.netgetiflist = 0x1c3d0L;
        off.syscalls.close = 0x1c310L;
        off.syscalls.ioctl = 0x1b580L;

        off.kernelData = 0xcb0000L;
        off.allproc = 0x3579e80L;
        off.rootvnode = 0x3de7510L;

        off.kaslrRetStatic = 0xad8aa0L;
        off.kaslrRetLow16 = 0x8aa0;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x28bee88L;
        off.oidA_kind = 0x28bee9cL;
        off.oidA_kindByte3 = 0x28bee9fL;
        off.oidA_arg1 = 0x28beea0L;
        off.oidA_arg1Byte1 = 0x28beea1L;
        off.oidA_arg1Value = 0x28bee78L;
        off.oidA_deadSink = 0x28beea8L;

        off.oidB_base = 0x28bed60L;
        off.oidB_kind = 0x28bed74L;
        off.oidB_kindByte3 = 0x28bed77L;
        off.oidB_arg1 = 0x28bed78L;
        off.oidB_arg1Value = 0x28bec90L;
        off.oidB_visible = 0x28bedb0L;

        off.oidC_base = 0x2be1b58L;
        off.oidC_kind = 0x2be1b6cL;
        off.oidC_arg1 = 0x2be1b70L;
        off.oidC_arg1Value = 0x3d6273cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3d62738L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a8bab8L;

        off.rodataProbeRva = 0x1367a24L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc48;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("13.40", off);
    }

    private static void initialize1342() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "13.42";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b920L;
        off.syscalls.setsockopt = 0x1c230L;
        off.syscalls.read = 0x1b6e0L;
        off.syscalls.write = 0x1b640L;
        off.syscalls.recvfrom = 0x1cb80L;
        off.syscalls.getrlimit = 0x1be20L;
        off.syscalls.setrlimit = 0x1ba00L;
        off.syscalls.socketpair = 0x1c910L;
        off.syscalls.pipe2 = 0x1b4a0L;
        off.syscalls.aioSubmitCmd = 0x1d3e0L;
        off.syscalls.aioMultiWait = 0x1c290L;
        off.syscalls.aioMultiPoll = 0x1b320L;
        off.syscalls.aioMultiCancel = 0x1c270L;
        off.syscalls.getpid = 0x1b860L;
        off.syscalls.getuid = 0x1c9b0L;
        off.syscalls.isInSandbox = 0x1d040L;
        off.syscalls.mmap = 0x1d260L;
        off.syscalls.jitshmCreate = 0x1c0f0L;
        off.syscalls.cpusetGetAffinity = 0x1d640L;
        off.syscalls.cpusetSetAffinity = 0x1ce00L;
        off.syscalls.rtprioThread = 0x1c090L;
        off.syscalls.sysctl = 0x1ce60L;
        off.syscalls.netgetiflist = 0x1c3d0L;
        off.syscalls.close = 0x1c310L;
        off.syscalls.ioctl = 0x1b580L;

        off.kernelData = 0xcb0000L;
        off.allproc = 0x3579e80L;
        off.rootvnode = 0x3de7510L;

        off.kaslrRetStatic = 0xad8aa0L;
        off.kaslrRetLow16 = 0x8aa0;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x28bee88L;
        off.oidA_kind = 0x28bee9cL;
        off.oidA_kindByte3 = 0x28bee9fL;
        off.oidA_arg1 = 0x28beea0L;
        off.oidA_arg1Byte1 = 0x28beea1L;
        off.oidA_arg1Value = 0x28bee78L;
        off.oidA_deadSink = 0x28beea8L;

        off.oidB_base = 0x28bed60L;
        off.oidB_kind = 0x28bed74L;
        off.oidB_kindByte3 = 0x28bed77L;
        off.oidB_arg1 = 0x28bed78L;
        off.oidB_arg1Value = 0x28bec90L;
        off.oidB_visible = 0x28bedb0L;

        off.oidC_base = 0x2be1b58L;
        off.oidC_kind = 0x2be1b6cL;
        off.oidC_arg1 = 0x2be1b70L;
        off.oidC_arg1Value = 0x3d6273cL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3d62738L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a8bab8L;

        off.rodataProbeRva = 0x1367e06L;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc48;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("13.42", off);
    }

    private static void initialize1360() {
        RelapseOffsets off = new RelapseOffsets();
        off.FW_VERSION = "13.60";

        off.syscalls = new Syscalls();
        off.syscalls.socket = 0x1b920L;
        off.syscalls.setsockopt = 0x1c230L;
        off.syscalls.read = 0x1b6e0L;
        off.syscalls.write = 0x1b640L;
        off.syscalls.recvfrom = 0x1cb80L;
        off.syscalls.getrlimit = 0x1be20L;
        off.syscalls.setrlimit = 0x1ba00L;
        off.syscalls.socketpair = 0x1c910L;
        off.syscalls.pipe2 = 0x1b4a0L;
        off.syscalls.aioSubmitCmd = 0x1d3e0L;
        off.syscalls.aioMultiWait = 0x1c290L;
        off.syscalls.aioMultiPoll = 0x1b320L;
        off.syscalls.aioMultiCancel = 0x1c270L;
        off.syscalls.getpid = 0x1b860L;
        off.syscalls.getuid = 0x1c9b0L;
        off.syscalls.isInSandbox = 0x1d040L;
        off.syscalls.mmap = 0x1d260L;
        off.syscalls.jitshmCreate = 0x1c0f0L;
        off.syscalls.cpusetGetAffinity = 0x1d640L;
        off.syscalls.cpusetSetAffinity = 0x1ce00L;
        off.syscalls.rtprioThread = 0x1c090L;
        off.syscalls.sysctl = 0x1ce60L;
        off.syscalls.netgetiflist = 0x1c3d0L;
        off.syscalls.close = 0x1c310L;
        off.syscalls.ioctl = 0x1b580L;

        off.kernelData = 0xcc0000L;
        off.allproc = 0x3589e80L;
        off.rootvnode = 0x3e0b510L;

        off.kaslrRetStatic = 0xae2da0L;
        off.kaslrRetLow16 = 0x2da0;

        off.oidOriginalKind = 0x80048002;
        off.oidWritableKind = 0x70048002;

        off.oidA_base = 0x28cef68L;
        off.oidA_kind = 0x28cef7cL;
        off.oidA_kindByte3 = 0x28cef7fL;
        off.oidA_arg1 = 0x28cef80L;
        off.oidA_arg1Byte1 = 0x28cef81L;
        off.oidA_arg1Value = 0x28cef58L;
        off.oidA_deadSink = 0x28cef88L;

        off.oidB_base = 0x28cee40L;
        off.oidB_kind = 0x28cee54L;
        off.oidB_kindByte3 = 0x28cee57L;
        off.oidB_arg1 = 0x28cee58L;
        off.oidB_arg1Value = 0x28ced70L;
        off.oidB_visible = 0x28cee90L;

        off.oidC_base = 0x2bf1c38L;
        off.oidC_kind = 0x2bf1c4cL;
        off.oidC_arg1 = 0x2bf1c50L;
        off.oidC_arg1Value = 0x3d831bcL;
        off.oidC_mib = new int[] {9, 8 };

        off.walkCounterAddr = 0x3d831b8L;
        off.walkCounterMib = new int[] {9, 7 };

        off.nodeMutex = 0x1a9bab8L;

        off.rodataProbeRva = 0x1379d6cL;
        off.rodataProbeText = "_aio_submit_cmd\0_aio_multi_wait";

        off.aioWaiterSize = 0x38;
        off.aioRequestSize = 0x28;
        off.aioGroupNum = 0x0;
        off.aioGroupState = 0x8;
        off.aioGroupWaiters = 0x50;
        off.aioIdTablePages = 0x220;
        off.aioIdTableSlotStride = 0x30;
        off.aioIdTableEntryType = 0x160;

        off.procPid = 0xbc;
        off.procUcred = 0x40;
        off.procFd = 0x48;
        off.procAioInfo = 0xc48;
        off.procDynlib = 0x3e8;

        off.kernelPid = 0x0L;

        off.ucredUid = 0x4;
        off.ucredRuid = 0x8;
        off.ucredSvuid = 0xc;
        off.ucredNgroups = 0x10;
        off.ucredRgid = 0x14;
        off.ucredSvgid = 0x18;
        off.ucredSceAuthId = 0x58;
        off.ucredSceCaps = 0x60;
        off.ucredSceCaps1 = 0x68;
        off.ucredSceAttrs = 0x80;

        off.sysCoreAuthIdLo = 0x7L;
        off.sysCoreAuthIdHi = 0x48000000L;

        off.filedescFiles = 0x0;
        off.filedescCdir = 0x8;
        off.filedescRdir = 0x10;
        off.filedescJdir = 0x18;

        off.filedescTableNfiles = 0x0;
        off.filedescTableOfiles = 0x8;
        off.filedescTableEntryStride = 0x30;
        off.filedescTableFileData = 0x0;

        off.pipeCount = 0x0;
        off.pipeIn = 0x4;
        off.pipeOut = 0x8;
        off.pipeSize = 0xc;
        off.pipeBuffer = 0x10;
        off.pipePair = 0xe8;
        off.pipeDefaultSize = 0x4000;

        off.dynlibSyscallStart = 0xf0;
        off.dynlibSyscallEnd = 0xf8;
        off.dynlibRestrictFlags = 0x118;
        off.dynlibLibkernelRef = 0x18;

        firmwareOffsets.put("13.60", off);
    }

    public static RelapseOffsets get(String fw) {
        RelapseOffsets off = (RelapseOffsets) firmwareOffsets.get(fw);
        if (off == null) {
            throw new RuntimeException("No relapse offsets available for firmware " + fw);
        }
        return off;
    }
}
