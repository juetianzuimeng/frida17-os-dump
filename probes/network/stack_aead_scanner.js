'use strict';

// ============================================================================
// 通用安全捞明文探针 (General Stack AEAD Scanner)
// 原理:
//   网络 socket 写触发时, AEAD 后的明文帧对象通常仍被当前线程的栈槽 /
//   被调用者保存寄存器(x19-x28) 引用着。
//   扫描 [sp, sp+0x800] 与 x19..x28, 每个指针根据协议结构体解析,
//   符合协议特征即为明文帧, dump hex+ascii。
// ============================================================================

// [配置项] ====================================================================
var CONFIG = {
  // 目标模块名 (如果为空则扫描所有模块的导出函数)
  targetModule: 'LightSpeedEngine', 
  // 过滤目标端口 (如 443)
  targetPort: 443,
  // 扫描深度
  scanStackOffset: 0x800,
  // 最大抓取条数
  maxCaps: 40,
  // 结构体解析与特征验证函数 (返回解析后的明文数据和长度)
  // 参数 p 为内存中的指针对象
  verifyPointer: function(p) {
    try {
      // 示例: 解析 folly::IOBuf (data@+0x10, len@+0x20)
      var iobuf = p.add(0x10).readPointer();
      if (!iobuf || iobuf.isNull()) return null;
      var data = iobuf.add(0x10).readPointer();
      var len = iobuf.add(0x20).readU64().toNumber();
      
      if (!data || data.isNull() || len < 2 || len > 4096) return null;
      
      var head = new Uint8Array(Memory.readByteArray(data, Math.min(len, 8)));
      // 示例: MQTT 协议头特征判断
      var headByte = head[0];
      if ((headByte & 0xF0) === 0x30 || (headByte & 0xF0) === 0x10 || (headByte & 0xF0) === 0x20) {
          return { ptr: data, len: len };
      }
    } catch (e) {}
    return null;
  }
};
// =============================================================================

var TARGET_MOD = CONFIG.targetModule ? Process.findModuleByName(CONFIG.targetModule) : null;
console.log('[i] Target Module=' + (TARGET_MOD ? TARGET_MOD.base : 'ALL'));

function findExp(name) {
  var mods = [Process.findModuleByName('libsystem_kernel.dylib'), Process.findModuleByName('libsystem_c.dylib')];
  for (var i = 0; i < mods.length; i++) { try { if (mods[i]) { var e = mods[i].findExportByName(name); if (e) return e; } } catch (e) {} }
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name); } catch (e) {}
  return null;
}

var getpeername = null;
(function () { var l = Process.findModuleByName('libsystem_kernel.dylib'); try { if (l) { var e = l.findExportByName('getpeername'); if (e) getpeername = new NativeFunction(e, 'int', ['int', 'pointer', 'pointer']); } } catch (e) {} })();

function isTargetPort(fd) { 
    if (!CONFIG.targetPort) return true;
    if (!getpeername) return false; 
    try { 
        var sa = Memory.alloc(128), sl = Memory.alloc(4); sl.writeU32(128); 
        if (getpeername(fd, sa, sl) !== 0) return false; 
        if (sa.add(1).readU8() !== 2) return false; 
        var port = ((sa.add(2).readU8() << 8) | sa.add(3).readU8());
        return port === CONFIG.targetPort; 
    } catch (e) { return false; } 
}

var caps = 0, seenSig = {};

function readN(p, n) { try { return new Uint8Array(Memory.readByteArray(p, n)); } catch (e) { return null; } }

function checkPointer(src, p) {
  if (caps >= CONFIG.maxCaps) return;
  var result = CONFIG.verifyPointer(p);
  if (!result) return;
  
  var full = readN(result.ptr, Math.min(result.len, 400)); 
  if (!full) return;
  
  var h = '', a = '';
  for (var i = 0; i < full.length; i++) { 
      h += ('0' + full[i].toString(16)).slice(-2); 
      a += (full[i] >= 32 && full[i] < 127) ? String.fromCharCode(full[i]) : '.'; 
  }
  var sig = result.len + ':' + h.slice(0, 24);
  if (seenSig[sig]) return; 
  seenSig[sig] = true;
  
  caps++;
  console.log('\n[FRAME #' + caps + '] ' + src + ' len=' + result.len + '\n   ASC: ' + a + '\n   HEX: ' + h);
}

function scan(ctx) {
  try {
    // 扫描被调用者保存寄存器 (AArch64)
    if (Process.arch === 'arm64') {
        var regs = [ctx.x19, ctx.x20, ctx.x21, ctx.x22, ctx.x23, ctx.x24, ctx.x25, ctx.x26, ctx.x27, ctx.x28, ctx.x0, ctx.x1];
        for (var i = 0; i < regs.length; i++) { 
            var r = regs[i]; 
            if (r && !r.isNull()) { 
                checkPointer('reg_x' + (19+i), r); 
            } 
        }
    }
    
    // 扫描栈内存
    var sp = ctx.sp;
    for (var off = 0; off < CONFIG.scanStackOffset; off += Process.pointerSize) {
      var pv; try { pv = sp.add(off).readPointer(); } catch (e) { continue; }
      if (!pv || pv.isNull()) continue;
      checkPointer('stack+' + off.toString(16), pv);
    }
  } catch (e) {}
}

['write', 'sendmsg', 'send', 'sendto'].forEach(function (fn) {
  var p = findExp(fn); if (!p) return;
  Interceptor.attach(p, {
    onEnter: function (a) {
      try {
        var fd = a[0].toInt32();
        if (!isTargetPort(fd)) return;
        scan(this.context);
      } catch (e) {}
    }
  });
  console.log('[i] hooked ' + fn);
});

console.log('[i] 通用明文栈扫描探测器就绪...');
setInterval(function () { console.log('[stat] frames_captured=' + caps); }, 5000);
