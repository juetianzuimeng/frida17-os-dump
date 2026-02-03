
console.log("Frida Version: " + Frida.version);
try {
    var mods = Process.enumerateModules();
    console.log("Process.enumerateModules() count: " + mods.length);
    if (mods.length > 0) {
        console.log("First module: " + mods[0].path);
    }
} catch (e) {
    console.log("Error enumerating modules: " + e);
}

try {
    if (Process.enumerateModulesSync) {
        var modsSync = Process.enumerateModulesSync();
        console.log("Process.enumerateModulesSync() count: " + modsSync.length);
    } else {
        console.log("Process.enumerateModulesSync is undefined");
    }
} catch (e) {
    console.log("Error enumerateModulesSync: " + e);
}
