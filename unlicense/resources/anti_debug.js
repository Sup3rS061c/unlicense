"use strict";
/*
 * ScyllaHide-equivalent anti-anti-debug hooks for unlicense.
 *
 * Loaded by frida_exec.spawn_and_instrument() right after the main agent
 * (frida.js) and BEFORE frida.resume(pid). At that point the target is still
 * suspended at its first instruction, so every hook installed here is active
 * before WinLicense/Themida executes a single anti-debug instruction.
 *
 * Coverage mirrors ScyllaHide's default "Themida/WinLicense" profile:
 *   - PEB.BeingDebugged / PEB.NtGlobalFlag / Heap.Flags / Heap.ForceFlags
 *   - NtQueryInformationProcess (ProcessDebugPort / DebugObjectHandle / DebugFlags)
 *   - NtSetInformationThread (ThreadHideFromDebugger)
 *   - NtQuerySystemInformation (SystemKernelDebuggerInformation)
 *   - NtQueryObject (hide the "DebugObject" type)
 *   - IsDebuggerPresent / CheckRemoteDebuggerPresent / OutputDebugString*
 *   - (optional, off by default) timing anti-attach fakes
 *
 * Set ANTI_DEBUG_TIMING = true to also fake GetTickCount/QueryPerformanceCounter
 * (only needed if the target uses RDTSC/timing checks; can disturb legit timing).
 */

const green = "\x1b[1;36m";
const reset = "\x1b[0m";
function log(message) {
    console.log(`${green}anti-debug${reset}: ${message}`);
}

const ANTI_DEBUG_TIMING = false;

const STATUS_SUCCESS = 0;

// ---- PEB / heap patching (done once, at load) --------------------------------

function patchPeb() {
    try {
        const NtCurrentTeb = new NativeFunction(
            Module.getExportByName("ntdll", "NtCurrentTeb"), "pointer", []);
        const teb = NtCurrentTeb();
        const peb = (Process.arch === "x64")
            ? teb.add(0x60).readPointer()
            : teb.add(0x30).readPointer();

        // PEB.BeingDebugged (offset 0x2)
        peb.add(0x2).writeU8(0);

        // PEB.NtGlobalFlag: clear the 3 heap debug bits (0x10|0x20|0x40 = 0x70)
        const ngfOff = (Process.arch === "x64") ? 0xBC : 0x68;
        const ngf = peb.add(ngfOff).readU32();
        peb.add(ngfOff).writeU32(ngf & ~0x70);

        // PEB.ProcessHeap -> HEAP.Flags / HEAP.ForceFlags
        const phOff = (Process.arch === "x64") ? 0x30 : 0x18;
        const heap = peb.add(phOff).readPointer();
        if (!heap.isNull()) {
            const hfOff = (Process.arch === "x64") ? 0x70 : 0x0C;
            const ffOff = (Process.arch === "x64") ? 0x74 : 0x10;
            heap.add(hfOff).writeU32(0);
            heap.add(ffOff).writeU32(0);
        }
    } catch (e) {
        log("PEB patch skipped: " + e);
    }
}

// ---- NtQueryObject: erase "DebugObject" from the returned type list ----------

const DEBUG_OBJECT_UTF16 = [
    0x44, 0x00, 0x65, 0x00, 0x62, 0x00, 0x75, 0x00, 0x67, 0x00,
    0x4F, 0x00, 0x62, 0x00, 0x6A, 0x00, 0x65, 0x00, 0x63, 0x00, 0x74, 0x00
];

function eraseDebugObjectName(buf, len) {
    const bytes = new Uint8Array(buf.readByteArray(len));
    for (let i = 0; i + DEBUG_OBJECT_UTF16.length <= bytes.length; i++) {
        let match = true;
        for (let j = 0; j < DEBUG_OBJECT_UTF16.length; j++) {
            if (bytes[i + j] !== DEBUG_OBJECT_UTF16[j]) { match = false; break; }
        }
        if (match) {
            for (let j = 0; j < DEBUG_OBJECT_UTF16.length; j++) bytes[i + j] = 0;
        }
    }
    buf.writeByteArray(bytes.buffer);
}

// ---- ntdll hooks (available at entry) ----------------------------------------

function installNtdllHooks() {
    // NtQueryInformationProcess
    const NtQueryInformationProcess = Module.getExportByName("ntdll", "NtQueryInformationProcess");
    Interceptor.attach(NtQueryInformationProcess, {
        onEnter(args) {
            this.cls = args[1].toInt32();
            this.out = args[2];
            this.outLen = args[3];
            this.retLen = args[4];
        },
        onLeave(retval) {
            if (this.out.isNull()) return;
            const cls = this.cls;
            try {
                if (cls === 7 /* ProcessDebugPort */) {
                    if (this.outLen.toInt32() >= 4) this.out.writeU32(0);
                } else if (cls === 30 /* ProcessDebugObjectHandle */) {
                    if (this.outLen.toInt32() >= Process.pointerSize) this.out.writePointer(ptr(0));
                } else if (cls === 31 /* ProcessDebugFlags */) {
                    if (this.outLen.toInt32() >= 4) this.out.writeU32(1);
                }
            } catch (e) { /* ignore */ }
        }
    });

    // NtSetInformationThread -> short-circuit ThreadHideFromDebugger
    const NtSetInformationThread = Module.getExportByName("ntdll", "NtSetInformationThread");
    Interceptor.attach(NtSetInformationThread, {
        onEnter(args) {
            this.skip = (args[1].toInt32() === 0x11); /* ThreadHideFromDebugger */
        },
        onLeave(retval) {
            return this.skip ? ptr(STATUS_SUCCESS) : retval;
        }
    });

    // NtQuerySystemInformation -> hide kernel debugger
    const NtQuerySystemInformation = Module.getExportByName("ntdll", "NtQuerySystemInformation");
    Interceptor.attach(NtQuerySystemInformation, {
        onEnter(args) {
            this.cls = args[0].toInt32();
            this.out = args[1];
            this.outLen = args[2];
            this.retLen = args[3];
        },
        onLeave(retval) {
            if (this.cls === 0x23 /* SystemKernelDebuggerInformation */ && !this.out.isNull()) {
                try {
                    if (this.outLen.toInt32() >= 8) {
                        this.out.writeU32(0);          // KernelDebuggerEnabled
                        this.out.add(4).writeU32(0);   // Reserved
                    }
                } catch (e) { /* ignore */ }
            }
        }
    });

    // NtQueryObject -> hide DebugObject type
    const NtQueryObject = Module.getExportByName("ntdll", "NtQueryObject");
    Interceptor.attach(NtQueryObject, {
        onEnter(args) {
            this.cls = args[1].toInt32();
            this.out = args[2];
            this.outLen = args[3];
            this.retLen = args[4];
        },
        onLeave(retval) {
            if (!retval.equals(STATUS_SUCCESS)) return;
            if (this.cls === 2 /* ObjectTypeInformation */ ||
                this.cls === 3 /* ObjectAllTypesInformation */) {
                try {
                    let len = (!this.retLen.isNull()) ? this.retLen.readU32() : 0;
                    if (len === 0 && !this.outLen.isNull()) len = this.outLen.readU32();
                    if (len > 0 && !this.out.isNull()) eraseDebugObjectName(this.out, len);
                } catch (e) { /* ignore */ }
            }
        }
    });

    log("ntdll anti-debug hooks installed");
}

// ---- kernel32 hooks (deferred until kernel32 is loaded) ----------------------

let kernel32HooksInstalled = false;

function installKernel32Hooks() {
    if (kernel32HooksInstalled) return;
    kernel32HooksInstalled = true;

    try {
        const IsDebuggerPresent = Module.getExportByName("kernel32", "IsDebuggerPresent");
        if (IsDebuggerPresent)
            Interceptor.replace(IsDebuggerPresent,
                new NativeCallback(function () { return 0; }, "int", []));
    } catch (e) { /* ignore */ }

    try {
        const CheckRemote = Module.getExportByName("kernel32", "CheckRemoteDebuggerPresent");
        if (CheckRemote)
            Interceptor.replace(CheckRemote,
                new NativeCallback(function (_h, pb) {
                    if (!pb.isNull()) pb.writeU32(0);
                    return 1; /* TRUE */
                }, "int", ["pointer", "pointer"]));
    } catch (e) { /* ignore */ }

    // Make OutputDebugString a no-op so the "last error" debugger probe fails.
    try {
        const ODSA = Module.getExportByName("kernel32", "OutputDebugStringA");
        if (ODSA) Interceptor.replace(ODSA, new NativeCallback(function () { }, "void", ["pointer"]));
        const ODSW = Module.getExportByName("kernel32", "OutputDebugStringW");
        if (ODSW) Interceptor.replace(ODSW, new NativeCallback(function () { }, "void", ["pointer"]));
    } catch (e) { /* ignore */ }

    if (ANTI_DEBUG_TIMING) installTimingHooks();

    log("kernel32 anti-debug hooks installed");
}

function ensureKernel32Hooks() {
    if (Process.findModuleByName("kernel32.dll") != null) {
        installKernel32Hooks();
        return;
    }
    // kernel32 not loaded yet (we're at the entry point). Wait for LdrLoadDll.
    const LdrLoadDll = Module.getExportByName("ntdll", "LdrLoadDll");
    Interceptor.attach(LdrLoadDll, {
        onLeave() {
            if (!kernel32HooksInstalled &&
                Process.findModuleByName("kernel32.dll") != null) {
                installKernel32Hooks();
            }
        }
    });
}

function installTimingHooks() {
    const base = Date.now();
    try {
        const GetTickCount = Module.getExportByName("kernel32", "GetTickCount");
        if (GetTickCount)
            Interceptor.replace(GetTickCount,
                new NativeCallback(function () {
                    return (Date.now() - base) & 0xffffffff;
                }, "uint32", []));
    } catch (e) { /* ignore */ }
    try {
        const GetTickCount64 = Module.getExportByName("kernel32", "GetTickCount64");
        if (GetTickCount64)
            Interceptor.replace(GetTickCount64,
                new NativeCallback(function () {
                    return Date.now() - base;
                }, "uint64", []));
    } catch (e) { /* ignore */ }
    try {
        const QPC = Module.getExportByName("kernel32", "QueryPerformanceCounter");
        if (QPC)
            Interceptor.replace(QPC,
                new NativeCallback(function (lp) {
                    if (!lp.isNull()) lp.writeU64(BigInt(Date.now() - base) * 10000n);
                    return 1;
                }, "int", ["pointer"]));
    } catch (e) { /* ignore */ }
    log("timing anti-attach hooks installed");
}

// ---- entry point --------------------------------------------------------------

function installAntiDebug() {
    log("Installing ScyllaHide-equivalent anti-debug hooks ...");
    patchPeb();
    installNtdllHooks();
    ensureKernel32Hooks();
    log("Done. Debugger should now be invisible to the target.");
}

installAntiDebug();

rpc.exports = {
    installAntiDebug: installAntiDebug
};
