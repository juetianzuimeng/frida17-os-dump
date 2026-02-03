
import frida
import time
import sys

def on_message(message, data):
    print(f"[PYTHON] Received message: {message}")

def main():
    try:
        device = frida.get_usb_device()
        print(f"[PYTHON] Device found: {device}")
        
        target = "net.whatsapp.WhatsApp"
        print(f"[PYTHON] Spawning {target}...")
        
        pid = device.spawn([target])
        session = device.attach(pid)
        device.resume(pid)
        print(f"[PYTHON] Attached to {target}, pid {pid}")

        js_code = """
        console.log("[JS] Script loaded");
        
        function checkEnv() {
            if (typeof ObjC !== 'undefined') {
                console.log("[JS] ObjC is AVAILABLE!");
            } else {
                console.log("[JS] ObjC is still undefined...");
            }
            if (typeof Process.enumerateModulesSync !== 'undefined') {
                 // console.log("[JS] Process.enumerateModulesSync is available");
            } else {
                 console.log("[JS] Process.enumerateModulesSync is undefined");
            }
        }
        
        // Check every 1 second
        setInterval(checkEnv, 1000);
        
        checkEnv(); // Check immediately
        
        rpc.exports = {
            ping: function() {
                return "Pong";
            }
        };
        """
        
        script = session.create_script(js_code)
        script.on('message', on_message)
        script.load()
        print("[PYTHON] Script loaded")
        
        time.sleep(1)
        print("[PYTHON] Calling ping via RPC...")
        response = script.exports.ping()
        print(f"[PYTHON] RPC Response: {response}")
        
        time.sleep(3)
        session.detach()
        print("[PYTHON] Done")

    except Exception as e:
        print(f"[PYTHON] Error: {e}")

if __name__ == "__main__":
    main()
