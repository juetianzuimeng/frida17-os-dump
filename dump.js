console.log("[frida-ios-dump]: Script loaded");

rpc.exports = {
    startDump: handleMessage
};

function handleMessage(message) {
    console.log("[frida-ios-dump]: handleMessage called");
    try {
        Module.ensureInitialized('Foundation');
    } catch (e) {
        console.log("[frida-ios-dump]: Foundation init failed: " + e);
    }

    modules = getAllAppModules();
    var app_path = ObjC.classes.NSBundle.mainBundle().bundlePath();
    // loadAllDynamicLibrary(app_path);
    // start dump
    modules = getAllAppModules();
    for (var i = 0; i < modules.length; i++) {
        console.log("start dump " + modules[i].path);
        var result = dumpModule(modules[i].path);
        send({ dump: result, path: modules[i].path });
    }
    send({ app: app_path.toString() });
    send({ done: "ok" });
}


var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_CREAT = 512;

var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var FAT_MAGIC = 0xcafebabe;
var FAT_CIGAM = 0xbebafeca;
var LC_SEGMENT = 0x1;
var LC_SEGMENT_64 = 0x19;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;

function allocStr(str) {
    return Memory.allocUtf8String(str);
}

// ... rest of vars

function putU8(addr, n) {
    if (typeof addr == "number") addr = ptr(addr);
    return addr.writeU8(n);
}

function getU16(addr) {
    if (typeof addr == "number") addr = ptr(addr);
    return addr.readU16();
}

function putU16(addr, n) {
    if (typeof addr == "number") addr = ptr(addr);
    return addr.writeU16(n);
}

function getU32(addr) {
    if (typeof addr == "number") addr = ptr(addr);
    // return addr.readU32(); // Broken on some buffers?
    var b0 = addr.readU8();
    var b1 = addr.add(1).readU8();
    var b2 = addr.add(2).readU8();
    var b3 = addr.add(3).readU8();
    return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
}

function putU32(addr, n) {
    if (typeof addr == "number") addr = ptr(addr);
    return addr.writeU32(n);
}

function getU64(addr) {
    if (typeof addr == "number") addr = ptr(addr);
    return addr.readU64();
}

function putU64(addr, n) {
    if (typeof addr == "number") addr = ptr(addr);
    return addr.writeU64(n);
}

function getPt(addr) {
    if (typeof addr == "number") addr = ptr(addr);
    return addr.readPointer();
}

function putPt(addr, n) {
    if (typeof addr == "number") addr = ptr(addr);
    if (typeof n == "number") n = ptr(n);
    return addr.writePointer(n);
}

function malloc(size) {
    return Memory.alloc(size);
}

function getExportFunction(type, name, ret, args) {
    var nptr;
    nptr = Module.findExportByName(null, name);
    if (nptr === null) {
        nptr = Module.findExportByName("libSystem.B.dylib", name);
    }
    if (nptr === null) {
        console.log("cannot find " + name);
        return null;
    } else {
        if (type === "f") {
            var funclet = new NativeFunction(nptr, ret, args);
            if (typeof funclet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            console.log("[frida-ios-dump]: Resolved " + name + " at " + nptr);
            return funclet;
        } else if (type === "d") {
            var datalet = nptr.readPointer();
            if (typeof datalet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return datalet;
        }
    }
}

var NSSearchPathForDirectoriesInDomains = getExportFunction("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);

function resolveLibcFunc(name, ret, args) {
    var ptr = null;
    // Strategy 1: Module.findExportByName (Old Frida)
    if (typeof Module.findExportByName === 'function') {
        ptr = Module.findExportByName(null, name);
        if (!ptr) ptr = Module.findExportByName(null, "_" + name);
    }
    // Strategy 2: Module.getExportByName (New Frida) - not showing in keys but might exist? 
    // Strategy 3: Module.getGlobalExportByName (New Frida 17+?)
    else if (typeof Module.getGlobalExportByName === 'function') {
        try { ptr = Module.getGlobalExportByName(name); } catch (e) { }
        if (!ptr) try { ptr = Module.getGlobalExportByName("_" + name); } catch (e) { }
    }

    // Strategy 4: Explicit libSystem search
    if (!ptr) {
        try {
            var lib = Process.findModuleByName("libSystem.B.dylib");
            if (lib) {
                ptr = lib.findExportByName(name);
                if (!ptr) ptr = lib.findExportByName("_" + name);
            }
        } catch (e) { }
    }

    if (!ptr) {
        console.log("[frida-ios-dump] FATAL: Cannot resolve " + name);
        return null;
    }
    console.log("[frida-ios-dump] Resolved " + name + " to " + ptr);
    return new NativeFunction(ptr, ret, args);
}

var wrapper_open = resolveLibcFunc("open", "int", ["pointer", "int", "int"]);
var read = resolveLibcFunc("read", "int", ["int", "pointer", "int"]);
var write = resolveLibcFunc("write", "int", ["int", "pointer", "int"]);
var lseek = resolveLibcFunc("lseek", "int64", ["int", "int64", "int"]);
var close = resolveLibcFunc("close", "int", ["int"]);
var remove = resolveLibcFunc("remove", "int", ["pointer"]);
var access = resolveLibcFunc("access", "int", ["pointer", "int"]);
var dlopen = resolveLibcFunc("dlopen", "pointer", ["pointer", "int"]);


function getDocumentDir() {
    if (typeof ObjC === 'undefined') {
        console.log("[frida-ios-dump]: ObjC missing, using /tmp for fid files");
        return "/tmp";
    }

    var NSDocumentDirectory = 9;
    var NSUserDomainMask = 1;
    var npdirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, 1);
    return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function open(pathname, flags, mode) {
    if (typeof pathname == "string") {
        pathname = allocStr(pathname);
    }
    return wrapper_open(pathname, flags, mode);
}

var modules = null;
function getAllAppModules() {
    console.log("[frida-ios-dump]: getAllAppModules called");
    console.log("Process exists: " + (typeof Process !== 'undefined'));
    if (typeof Process !== 'undefined') {
        console.log("Process keys: " + Object.keys(Process));
    }
    console.log("ObjC exists: " + (typeof ObjC !== 'undefined'));

    modules = [];
    var tmpmods = [];
    if (typeof Process.enumerateModulesSync === 'function') {
        tmpmods = Process.enumerateModulesSync();
    } else {
        tmpmods = Process.enumerateModules();
    }
    for (var i = 0; i < tmpmods.length; i++) {
        // console.log("Check module: " + tmpmods[i].path);
        if (tmpmods[i].path.indexOf(".app") != -1) {
            console.log("[frida-ios-dump]: Adding target module: " + tmpmods[i].path);
            modules.push(tmpmods[i]);
        }
    }
    console.log("[frida-ios-dump]: Total modules found: " + tmpmods.length + ", Matching .app: " + modules.length);
    if (modules.length === 0 && tmpmods.length > 0) {
        console.log("[frida-ios-dump]: DUMPING FIRST 10 MODULES FOR DEBUG:");
        for (var k = 0; k < Math.min(10, tmpmods.length); k++) {
            console.log(" - " + tmpmods[k].path);
        }
        // Try to be more lenient?
        console.log("[frida-ios-dump]: Trying lenient search for main executable...");
        var mainMod = Process.enumerateModules()[0];
        if (mainMod) {
            console.log("[frida-ios-dump]: First module is: " + mainMod.path);
            modules.push(mainMod);
        }
    }

    return modules;
}

var FAT_MAGIC = 0xcafebabe;
var FAT_CIGAM = 0xbebafeca;
var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var LC_SEGMENT = 0x1;
var LC_SEGMENT_64 = 0x19;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;

function pad(str, n) {
    return Array(n - str.length + 1).join("0") + str;
}

function swap32(value) {
    value = pad(value.toString(16), 8)
    var result = "";
    for (var i = 0; i < value.length; i = i + 2) {
        result += value.charAt(value.length - i - 2);
        result += value.charAt(value.length - i - 1);
    }
    return parseInt(result, 16)
}

function dumpModule(name) {
    if (modules == null) {
        modules = getAllAppModules();
    }

    var targetmod = null;
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) != -1) {
            targetmod = modules[i];
            break;
        }
    }
    if (targetmod == null) {
        console.log("Cannot find module");
        return;
    }
    var modbase = modules[i].base;
    var modsize = modules[i].size;
    var newmodname = modules[i].name;
    var newmodpath = getDocumentDir() + "/" + newmodname + ".fid";
    var oldmodpath = modules[i].path;



    console.log("[frida-ios-dump]: Debugging libc functions...");
    console.log("[frida-ios-dump]: access type: " + typeof access);
    console.log("[frida-ios-dump]: remove type: " + typeof remove);
    console.log("[frida-ios-dump]: open type: " + typeof wrapper_open);

    if (typeof access === 'function') {
        if (!access(allocStr(newmodpath), 0)) {
            if (typeof remove === 'function') {
                remove(allocStr(newmodpath));
            }
        }
    } else {
        console.log("[frida-ios-dump]: access() function missing, skipping existence check.");
    }

    var fmodule = open(newmodpath, O_CREAT | O_RDWR, 0);
    var foldmodule = open(oldmodpath, O_RDONLY, 0);

    if (fmodule == -1 || foldmodule == -1) {
        console.log("Cannot open file" + newmodpath);
        return;
    }

    var is64bit = false;
    var size_of_mach_header = 0;
    var magic = getU32(modbase);
    var cur_cpu_type = getU32(modbase.add(4));
    var cur_cpu_subtype = getU32(modbase.add(8));

    console.log("[frida-ios-dump]: Module: " + newmodname + ", Base: " + modbase + ", Magic: " + magic.toString(16));

    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        is64bit = false;
        size_of_mach_header = 28;
    } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        is64bit = true;
        size_of_mach_header = 32;
    }

    // Debug for mismatch
    if (size_of_mach_header == 0) {
        console.log("[frida-ios-dump]: Magic mismatch! magic=" + magic + " (" + magic.toString(16) + "), MH_MAGIC_64=" + MH_MAGIC_64);
        if (magic.toString(16) == "feedfacf") {
            console.log("[frida-ios-dump]: Forced 64-bit match.");
            size_of_mach_header = 32;
            is64bit = true;
        }
    }

    console.log("[frida-ios-dump]: Resuming dump logic...");

    var BUFSIZE = 32768;
    var buffer = malloc(BUFSIZE);

    lseek(foldmodule, 0, SEEK_SET);
    var bytesRead = read(foldmodule, buffer, BUFSIZE);
    console.log("[frida-ios-dump]: Read " + bytesRead + " bytes from file to buffer.");

    // Debug readU32
    try {
        var head32 = buffer.readU32();
        console.log("[frida-ios-dump]: buffer.readU32() at 0: " + head32.toString(16));
        var headu8 = buffer.readU8();
        console.log("[frida-ios-dump]: buffer.readU8() at 0: " + headu8.toString(16));
    } catch (e) {
        console.log("Read error: " + e);
    }

    // Manual getU32 if needed
    function getU32Manual(addr) {
        if (typeof addr == "number") addr = ptr(addr);
        var b0 = addr.readU8();
        var b1 = addr.add(1).readU8();
        var b2 = addr.add(2).readU8();
        var b3 = addr.add(3).readU8();
        return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
    }
    console.log("[frida-ios-dump]: Manual read at 0: " + getU32Manual(buffer).toString(16));
    console.log("[frida-ios-dump]: Manual read at 16: " + getU32Manual(buffer.add(16)).toString(16));

    var fileoffset = 0;
    var filesize = 0;
    magic = getU32(buffer);
    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        var off = 4;
        var archs = swap32(getU32(buffer.add(off)));
        for (var i = 0; i < archs; i++) {
            var cputype = swap32(getU32(buffer.add(off + 4)));
            var cpusubtype = swap32(getU32(buffer.add(off + 8)));
            if (cur_cpu_type == cputype && cur_cpu_subtype == cpusubtype) {
                fileoffset = swap32(getU32(buffer.add(off + 12)));
                filesize = swap32(getU32(buffer.add(off + 16)));
                break;
            }
            off += 20;
        }

        if (fileoffset == 0 || filesize == 0)
            return;

        lseek(fmodule, 0, SEEK_SET);
        lseek(foldmodule, fileoffset, SEEK_SET);
        for (var i = 0; i < parseInt(filesize / BUFSIZE); i++) {
            read(foldmodule, buffer, BUFSIZE);
            write(fmodule, buffer, BUFSIZE);
        }
        if (filesize % BUFSIZE) {
            read(foldmodule, buffer, filesize % BUFSIZE);
            write(fmodule, buffer, filesize % BUFSIZE);
        }
    } else {
        var readLen = 0;
        lseek(foldmodule, 0, SEEK_SET);
        lseek(fmodule, 0, SEEK_SET);
        while (readLen = read(foldmodule, buffer, BUFSIZE)) {
            write(fmodule, buffer, readLen);
        }
    }

    // Reload header into buffer because it was used for copying
    lseek(foldmodule, 0, SEEK_SET);
    read(foldmodule, buffer, BUFSIZE);

    var ncmdsRef = buffer.add(16);
    var ncmds = getU32(ncmdsRef);
    console.log("[frida-ios-dump]: ncmds (from buffer): " + ncmds);
    console.log("[frida-ios-dump]: ncmds raw read: " + ncmdsRef.readU32());

    // Brute force scan
    console.log("[frida-ios-dump]: Brute scanning buffer for LC_ENCRYPTION_INFO (" + BUFSIZE + " bytes)...");
    var offset_cryptid = -1;
    var crypt_off = 0;
    var crypt_size = 0;

    // Standard Parsing
    var load_cmd_off = size_of_mach_header;
    if (load_cmd_off == 0) load_cmd_off = 32;

    for (var i = 0; i < ncmds; i++) {
        if (load_cmd_off + 8 >= BUFSIZE) break;

        var cmd = getU32(buffer.add(load_cmd_off));
        var cmdsize = getU32(buffer.add(load_cmd_off + 4));

        // console.log("Cmd " + i + ": " + cmd.toString(16) + " size=" + cmdsize + " off=" + load_cmd_off);

        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
            offset_cryptid = load_cmd_off + 16;
            crypt_off = getU32(buffer.add(load_cmd_off + 8));
            crypt_size = getU32(buffer.add(load_cmd_off + 12));
            console.log("[frida-ios-dump]: Found LC_ENCRYPTION_INFO off=" + load_cmd_off + ", crypt_off=" + crypt_off);
        }
        load_cmd_off += cmdsize;
    }

    if (offset_cryptid != -1) {
        console.log("[frida-ios-dump]: Patching cryptid to 0 at offset " + offset_cryptid);
        var tpbuf = malloc(8);
        putU64(tpbuf, 0);
        lseek(fmodule, offset_cryptid, SEEK_SET);
        write(fmodule, tpbuf, 4);
        lseek(fmodule, crypt_off, SEEK_SET);
        write(fmodule, modbase.add(crypt_off), crypt_size);
        console.log("[frida-ios-dump]: Patching complete.");
    } else {
        console.log("[frida-ios-dump]: WARN: No LC_ENCRYPTION_INFO found for module: " + name);
    }

    close(fmodule);
    close(foldmodule);
    return newmodpath
}

function loadAllDynamicLibrary(app_path) {
    var defaultManager = ObjC.classes.NSFileManager.defaultManager();
    var errorPtr = Memory.alloc(Process.pointerSize);
    Memory.writePointer(errorPtr, NULL);
    var filenames = defaultManager.contentsOfDirectoryAtPath_error_(app_path, errorPtr);
    for (var i = 0, l = filenames.count(); i < l; i++) {
        var file_name = filenames.objectAtIndex_(i);
        var file_path = app_path.stringByAppendingPathComponent_(file_name);
        if (file_name.hasSuffix_(".framework")) {
            var bundle = ObjC.classes.NSBundle.bundleWithPath_(file_path);
            if (bundle.isLoaded()) {
                console.log("[frida-ios-dump]: " + file_name + " has been loaded. ");
            } else {
                if (bundle.load()) {
                    console.log("[frida-ios-dump]: Load " + file_name + " success. ");
                } else {
                    console.log("[frida-ios-dump]: Load " + file_name + " failed. ");
                }
            }
        } else if (file_name.hasSuffix_(".bundle") ||
            file_name.hasSuffix_(".momd") ||
            file_name.hasSuffix_(".strings") ||
            file_name.hasSuffix_(".appex") ||
            file_name.hasSuffix_(".app") ||
            file_name.hasSuffix_(".lproj") ||
            file_name.hasSuffix_(".storyboardc")) {
            continue;
        } else {
            var isDirPtr = Memory.alloc(Process.pointerSize);
            Memory.writePointer(isDirPtr, NULL);
            defaultManager.fileExistsAtPath_isDirectory_(file_path, isDirPtr);
            if (Memory.readPointer(isDirPtr) == 1) {
                loadAllDynamicLibrary(file_path);
            } else {
                if (file_name.hasSuffix_(".dylib")) {
                    var is_loaded = 0;
                    for (var j = 0; j < modules.length; j++) {
                        if (modules[j].path.indexOf(file_name) != -1) {
                            is_loaded = 1;
                            console.log("[frida-ios-dump]: " + file_name + " has been dlopen.");
                            break;
                        }
                    }

                    if (!is_loaded) {
                        if (dlopen(allocStr(file_path.UTF8String()), 9)) {
                            console.log("[frida-ios-dump]: dlopen " + file_name + " success. ");
                        } else {
                            console.log("[frida-ios-dump]: dlopen " + file_name + " failed. ");
                        }
                    }
                }
            }
        }
    }
}

function handleMessage(message) {
    console.log("[frida-ios-dump]: handleMessage called");
    try {
        Module.ensureInitialized('Foundation');
    } catch (e) {
        console.log("[frida-ios-dump]: Foundation init failed: " + e);
    }

    modules = getAllAppModules();

    console.log("[frida-ios-dump]: DEBUG: Checking libSystem...");
    var libSystem = Process.findModuleByName("libSystem.B.dylib");
    if (libSystem) {
        console.log("[frida-ios-dump]: libSystem found: " + libSystem.base);
        try {
            console.log("Frida version: " + Frida.version);
            console.log("Module keys: " + Object.keys(Module));
            console.log("typeof Module.findExportByName: " + typeof Module.findExportByName);
            console.log("typeof ptr: " + typeof ptr);
            console.log("typeof Memory.readU32: " + typeof Memory.readU32);

            if (libSystem.findExportByName) {
                var openPtr = libSystem.findExportByName("open");
                console.log("[frida-ios-dump]: open symbol via libSystem.findExportByName: " + openPtr);
            } else {
                var openPtr = Module.findExportByName("libSystem.B.dylib", "open");
                console.log("[frida-ios-dump]: open symbol via Module.findExportByName: " + openPtr);
            }
        } catch (e) {
            console.log("Error probing Module: " + e);
        }

        console.log("[frida-ios-dump]: open symbol in libSystem: " + openPtr);
    } else {
        console.log("[frida-ios-dump]: libSystem.B.dylib NOT FOUND!");
        var mods = Process.enumerateModules();
        console.log("[frida-ios-dump]: First 5 modules:");
        for (var i = 0; i < Math.min(5, mods.length); i++) console.log(" - " + mods[i].name);
    }

    // Re-bind libc functions if they are missing
    if (typeof wrapper_open !== 'function') {
        console.log("[frida-ios-dump]: Re-binding wrapper_open...");
        wrapper_open = resolveLibcFunc("open", "int", ["pointer", "int", "int"]);
        read = resolveLibcFunc("read", "int", ["int", "pointer", "int"]);
        write = resolveLibcFunc("write", "int", ["int", "pointer", "int"]);
        lseek = resolveLibcFunc("lseek", "int64", ["int", "int64", "int"]);
        close = resolveLibcFunc("close", "int", ["int"]);
        remove = resolveLibcFunc("remove", "int", ["pointer"]);
        access = resolveLibcFunc("access", "int", ["pointer", "int"]);
    }

    var app_path = null;

    // Use path from Python if available
    if (message && message.app_path) {
        app_path = message.app_path;
        console.log("[frida-ios-dump]: Received app path from Python: " + app_path);
    }

    // Try ObjC first if not provided
    if (!app_path && typeof ObjC !== 'undefined') {
        try {
            app_path = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
        } catch (e) {
            console.log("[frida-ios-dump]: NSBundle failed: " + e);
        }
    }

    // Fallback if ObjC failed or undefined
    if (!app_path) {
        console.log("[frida-ios-dump]: ObjC undefined or failed, trying to find app_path from modules...");

        // Try Process.mainModule if available (Frida 12.11+)
        // if (Process.mainModule) {
        //    console.log("Process.mainModule: " + Process.mainModule.path);
        //}

        console.log("Modules found: " + modules.length);
        for (var i = 0; i < modules.length; i++) {
            var mpath = modules[i].path;
            console.log("Module: " + mpath); // Uncomment for verbose debug
            var idx = mpath.indexOf(".app/");
            if (idx !== -1) {
                // Extract /path/to/Something.app
                app_path = mpath.substring(0, idx + 4);
                console.log("[frida-ios-dump]: Found potential app path (via .app/): " + app_path);
                break;
            }
            // Sometimes it ends with .app/Binary
            var idx2 = mpath.indexOf(".app");
            if (idx2 !== -1 && mpath.indexOf("/System/") === -1 && mpath.indexOf("/Developer/") === -1) {
                // heuristic: usually app path is like .../Bundle/Application/.../Name.app/Name
                // We want the folder ending in .app
                var parts = mpath.split("/");
                for (var p = 0; p < parts.length; p++) {
                    if (parts[p].endsWith(".app")) {
                        // Reconstruct path up to .app
                        app_path = parts.slice(0, p + 1).join("/");
                        console.log("[frida-ios-dump]: Found potential app path (via split): " + app_path);
                        break;
                    }
                }
                if (app_path) break;
            }
        }
    }

    if (!app_path) {
        console.log("[frida-ios-dump]: FATAL - Could not resolve app path.");
        send({ done: "error" });
        return;
    }

    if (typeof ObjC !== 'undefined') {
        loadAllDynamicLibrary(ObjC.classes.NSBundle.mainBundle().bundlePath());
    } else {
        console.log("[frida-ios-dump]: Skipping loadAllDynamicLibrary (ObjC undefined)");
    }

    // start dump
    // Refresh modules in case loading changed anything (only if ObjC was avail)
    if (typeof ObjC !== 'undefined') {
        modules = getAllAppModules();
    }

    for (var i = 0; i < modules.length; i++) {
        console.log("start dump " + modules[i].path);
        var result = dumpModule(modules[i].path);
        send({ dump: result, path: modules[i].path });
    }
    send({ app: app_path.toString() });
    send({ done: "ok" });
}

rpc.exports = {
    startDump: handleMessage
};