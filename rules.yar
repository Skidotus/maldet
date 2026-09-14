/*
MalDet YARA rules - source-code-level malicious-pattern detection.

Severity lives in each rule's `meta.severity`, read by scanner.py's
run_yara() via `yara -m` - adding a rule here doesn't need a scanner.py
change. Wherever a single signal is too common in legitimate code to mean
much on its own (e.g. "makes an HTTP request", "reads an env var"),
the rule requires it in combination with a second, separately-defined
signal group instead of firing on either alone - see NOTES.md for why.
*/

rule detect_reverse_shell {
    meta:
        severity = "high"
        description = "Reverse shell command patterns"
    strings:
        $a = "bash -i >& /dev/tcp"
        $b = "nc -e /bin/sh"
        $c = "nc -e /bin/bash"
        $d = "/bin/sh -i"
        $e = "/bin/bash -i"
        $f = "os.dup2(s.fileno()"
        $g = "pty.spawn(\"/bin/"
        $h = "pty.spawn('/bin/"
    condition:
        any of them
}

rule detect_base64_exec {
    meta:
        severity = "high"
        description = "Encoded payload decoded and then executed"
    strings:
        $dec1 = "base64.b64decode" nocase
        $dec2 = "base64 -d"
        $dec3 = "atob("
        $dec4 = "Buffer.from(" nocase
        $dec5 = "fromhex("
        $run1 = "eval("
        $run2 = "exec("
        $run3 = "Function("
        $run4 = "os.system("
        $run5 = "subprocess."
    condition:
        (1 of ($dec*)) and (1 of ($run*))
}

rule detect_credential_harvester {
    meta:
        severity = "high"
        description = "References credential/secret material by name AND a deliberate outbound-send API in the same file - narrower than 'reads any env var', which large legitimate codebases do constantly regardless of intent. Still not proof the two are connected (YARA can't trace data flow) - a known limitation, see NOTES.md"
    strings:
        $env1 = "AWS_SECRET" nocase
        $env2 = ".aws/credentials"
        $env3 = ".ssh/id_rsa"
        $env4 = /os\.environ.{0,15}(AWS|SECRET|TOKEN|API_KEY|PASSWORD)/ nocase
        $env5 = /process\.env\.[A-Z_]*(SECRET|TOKEN|KEY|PASSWORD)/
        $env6 = /["']?(api[_-]?key|password|secret|token)["']?\s*[:=]\s*["'][^"'\s]{6,}["']/ nocase
        $net1 = "requests.post"
        $net2 = "socket.send"
        $net3 = "urllib.request.urlopen"
        $net4 = "smtplib"
    condition:
        (1 of ($env*)) and (1 of ($net*))
}

rule detect_downloader {
    meta:
        severity = "low"
        description = "Downloads a remote resource - common and low-signal alone; see detect_download_and_execute for the composite version"
    strings:
        $a = "urllib.request"
        $b = "requests.get"
        $c = "wget "
        $d = "curl -o"
        $e = "curl -O"
    condition:
        any of them
}

rule detect_download_and_execute {
    meta:
        severity = "high"
        description = "Downloads a remote resource AND executes it - the actually dangerous combination, not just downloading alone"
    strings:
        $dl1 = "urllib.request"
        $dl2 = "requests.get"
        $dl3 = "wget "
        $dl4 = "curl "
        $dl5 = "urlopen("
        $ex1 = "os.system("
        $ex2 = "subprocess."
        $ex3 = "eval("
        $ex4 = "exec("
        $ex5 = "| sh"
        $ex6 = "| bash"
    condition:
        (1 of ($dl*)) and (1 of ($ex*))
}

rule detect_obfuscated_string_execution {
    meta:
        severity = "high"
        description = "Reconstructs a string character-by-character or from hex escapes, then immediately executes it - fromCharCode/chr() alone are common in ordinary text-processing code, so this requires both the reconstruction and an execution call together"
    strings:
        $build1 = /chr\(\d+\)\s*\+\s*chr\(\d+\)/
        $build2 = "String.fromCharCode("
        $build3 = /(\\x[0-9a-fA-F]{2}){4,}/
        $run1 = "eval("
        $run2 = "exec("
        $run3 = "document.write("
        $run4 = "Function("
        $combo1 = "exec(''.join"
        $combo2 = "exec(\"\".join"
    condition:
        ((1 of ($build*)) and (1 of ($run*))) or any of ($combo*)
}

rule detect_persistence_mechanism {
    meta:
        severity = "high"
        description = "Modifies a startup/scheduling location - legitimate application code essentially never does this"
    strings:
        $a = "crontab -"
        $b = "/etc/cron"
        $c = ".bashrc"
        $d = ".bash_profile"
        $e = ".zshrc"
        $f = "systemctl enable"
        $g = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $h = "LaunchAgents"
        $i = "New-ItemProperty"
    condition:
        any of them
}

rule detect_anti_analysis {
    meta:
        severity = "high"
        description = "Checks for a debugger, VM, or sandbox before continuing - a common malware evasion technique, essentially never present in ordinary application code"
    strings:
        $a = "IsDebuggerPresent"
        $b = "ptrace(PTRACE_TRACEME"
        $c = "VBoxService" nocase
        $d = "CheckRemoteDebuggerPresent"
        $e = "sandboxie" nocase
        $f = "/proc/self/status"
    condition:
        any of them
}

rule detect_crypto_miner {
    meta:
        severity = "high"
        description = "Cryptocurrency mining pool connection patterns"
    strings:
        $a = "stratum+tcp://"
        $b = "stratum+ssl://"
        $c = "xmrig" nocase
        $d = "cryptonight" nocase
        $e = "minergate" nocase
    condition:
        any of them
}

rule detect_process_injection {
    meta:
        severity = "high"
        description = "Windows process-injection API sequence"
    strings:
        $a = "CreateRemoteThread"
        $b = "VirtualAllocEx"
        $c = "WriteProcessMemory"
    condition:
        2 of them
}

rule detect_clipboard_hijack {
    meta:
        severity = "medium"
        description = "Reads the clipboard alongside crypto-wallet-address-shaped patterns - a known 'clipper' malware technique that swaps a copied address for the attacker's own"
    strings:
        $clip1 = "win32clipboard" nocase
        $clip2 = "pyperclip"
        $clip3 = "navigator.clipboard"
        $wallet1 = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/
        $wallet2 = /\b0x[a-fA-F0-9]{40}\b/
    condition:
        (1 of ($clip*)) and (1 of ($wallet*))
}
