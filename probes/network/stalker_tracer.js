'use strict';

// ============================================================================
// 通用 Frida Stalker 线程追踪探测器 (General Stalker Tracer)
// 原理:
//   当特定网络 socket 写触发时, 将当前写线程挂上 Stalker。
//   在目标模块的特定汇编偏移(通常是 ret / blr 之后的调用点)进行插桩 (callout),
//   提取寄存器中的明文数据。专门针对 OLLVM / CFG 平坦化环境。
// ============================================================================

// [配置项] ====================================================================
var CONFIG = {
  // 目标模块名
  targetModule: 'LightSpeedEngine',
  // 目标端口过滤
  targetPort: 443,
  // 需要监控提取的汇编指令偏移列表 (Relative offsets within the module)
  // 这些点通常是你分析到的 "明文装载/传递" 点
  callsiteOffsets: [
    0x1d4fbc, 
    0x3004bc, 
    0x3003f4, 
    0x3002fc, 
    0x300824
  ],
  // Stalker 挂接超时时间 (ms), 避免持续跟踪卡死
  stalkerTimeoutMs: 25000,
  maxCaps: 60,
  
  // 寄存器内容解析与验证函数
  parseRegister: function(tag, regName, regPtr) {
    if (this.caps >= this.maxCaps) return;
    try {
      if (regPtr.isNull()) return;
      // 示例: 尝试以直接内容或 IOBuf 格式解包
      var candidates = [];
      try { var d1 = regPtr.add(0x10).readPointer(); var l1 = regPtr.add(0x20).readU64().toNumber(); candidates.push([d1, l1]); } catch (e) {}
      try { candidates.push([regPtr, 64]); } catch (e) {}
      
      for (var i = 0; i < candidates.length; i++) {
        var d = candidates[i][0], l = candidates[i][1];
        if (!d || d.isNull() || l < 2 || l > 4096) continue;
        var r = hexAsc(d, Math.min(l, 300));
        if (!r) continue;
        
        // 自定义特征匹配逻辑
        var looksText = /[\/][a-z_]/i.test(r.a);
        if (looksText) {
          this.caps++;
          console.log('\n[PLAIN #' + this.caps + '] site=' + tag + ' reg=' + regName + ' len=' + l + '\n   ASC: ' + r.a + '\n   HEX: ' + r.h);
        }
      }
    } catch (e) {}
  },
  caps: 0
};
// =============================================================================

function hexAsc(p, n) {
  try {
    var ba = new Uint8Array(Memory.readByteArray(p, n));
    var h = '', a = '';
    for (var i = 0; i < ba.length; i++) { h += ('0' + ba[i].toString(16)).slice(-2); a += (ba[i] >= 32 && ba[i] < 127) ? String.fromCharCode(ba[i]) : '.'; }
    return { h: h, a: a };
  } catch (e) { return null; }
}

var TARGET_MOD = Process.findModuleByName(CONFIG.targetModule);
if (!TARGET_MOD) { console.log('[!] 模块未加载: ' + CONFIG.targetModule); }
var BASE = TARGET_MOD ? TARGET_MOD.base : ptr(0);
console.log('[i] Target Module base=' + BASE + ' size=' + (TARGET_MOD ? TARGET_MOD.size : 0));

var TARGETS = {};
CONFIG.callsiteOffsets.forEach(function (o) { 
    if (BASE.isNull()) return;
    TARGETS[BASE.add(o).toString()] = '0x' + o.toString(16); 
});

function findExp(name) {
  var mods = [Process.findModuleByName('libsystem_kernel.dylib'), Process.findModuleByName('libsystem_c.dylib')];
  for (var i = 0; i < mods.length; i++) { try { if (mods[i]) { var e = mods[i].findExportByName(name); if (e) return e; } } catch (e) {} }
  try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name); } catch (e) {}
  return null;
}

var getpeername = null;
(function () { var libs = [Process.findModuleByName('libsystem_kernel.dylib')]; for (var i = 0; i < libs.length; i++) { try { if (libs[i]) { var e = libs[i].findExportByName('getpeername'); if (e) { getpeername = new NativeFunction(e, 'int', ['int', 'pointer', 'pointer']); } } } catch (e) {} } })();

function isTargetPort(fd) {
  if (!getpeername || !CONFIG.targetPort) return true;
  try { 
      var sa = Memory.alloc(128), sl = Memory.alloc(4); sl.writeU32(128); 
      if (getpeername(fd, sa, sl) !== 0) return false; 
      var fam = sa.add(1).readU8(); if (fam !== 2) return false; 
      var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8(); 
      return port === CONFIG.targetPort; 
  } catch (e) { return false; }
}

var followed = false;
function startStalk() {
  if (followed) return; followed = true;
  console.log('[i] Stalker.follow 当前线程(探测到网络写), 准备在指定地址插桩...');
  Stalker.follow(Process.getCurrentThreadId(), {
    transform: function (iterator) {
      var insn = iterator.next();
      do {
        var key = insn.address.toString();
        var tag = TARGETS[key];
        if (tag) {
          iterator.putCallout(function (context) {
            if (Process.arch === 'arm64') {
                var regs = [context.x0, context.x1, context.x2, context.x3, context.x4, context.x5, context.x6, context.x7];
                for (var i = 0; i < regs.length; i++) {
                    CONFIG.parseRegister(tag, 'x' + i, regs[i]);
                }
            }
          });
        }
        iterator.keep();
      } while ((insn = iterator.next()) !== null);
    }
  });
  
  setTimeout(function () { 
      try { 
          Stalker.unfollow(Process.getCurrentThreadId()); 
          console.log('[i] Stalker.unfollow (达到超时时间 ' + CONFIG.stalkerTimeoutMs + 'ms)'); 
      } catch (e) {} 
  }, CONFIG.stalkerTimeoutMs);
}

['write', 'sendmsg', 'send'].forEach(function (fn) {
  var p = findExp(fn); if (!p) return;
  Interceptor.attach(p, { 
      onEnter: function (a) { 
          try { 
              if (isTargetPort(a[0].toInt32())) startStalk(); 
          } catch (e) {} 
      } 
  });
  console.log('[i] hooked ' + fn);
});

console.log('[i] 通用 Stalker 探测器就绪 — 等待网络写触发拦截...');
