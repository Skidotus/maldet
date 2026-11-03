/*
MalDet YARA rules - source-code-level malicious-pattern detection.

Severity lives in each rule's `meta.severity`, read by scanner.py's
run_yara() via `yara -m` - adding a rule here doesn't need a scanner.py
change.

These are BEHAVIOUR rules: they look for what code does (decode-then-run,
download-then-run, install persistence), which is how a brand-new payload
gets caught. Known-malware FINGERPRINTS come from YARA Forge instead
(rules/forge/, see its README) - the two are complementary.

Tightened 2026-11-03. The previous versions matched two signals ANYWHERE in
the same file ("contains base64.b64decode" and, 3000 lines later, "contains
exec("), so in large files they matched almost unconditionally: measured over
174 scanned repos, detect_downloader fired in 55%, download_and_execute in
49%, persistence in 41%, obfuscated_string_execution in 28% and base64_exec
in 26%. The FP classifier learned from that frequency that the rules were
noise, and scored a genuine exec(base64.b64decode(...)) in setup.py at 0.08.

The rules now require the two halves to be CONNECTED - one nested inside the
other, or on adjacent lines - via regexes. Gaps are bounded ([^\n]{0,N},
(\n[^\n]{0,N}){0,K}) so a match cannot run across a whole file, and so the
regex engine's work per candidate stays small. Where a pattern is common in
legitimate installers (curl | sh, appending to ~/.bashrc) it lives in its
own medium-severity rule rather than inflating a high one.
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
        description = "Decodes or decompresses a hidden payload and executes it directly (decode call nested in, or on the line before, an exec/eval)"
    strings:
        // Python: exec(base64.b64decode(...)), eval(zlib.decompress(...)), exec(marshal.loads(...))
        $py_nested = /\b(exec|eval)\s*\(\s*(base64\.(b64|b32|b16|a85|b85|urlsafe_b64)decode|codecs\.decode|zlib\.decompress|bz2\.decompress|lzma\.decompress|gzip\.decompress|marshal\.loads|bytes\.fromhex|binascii\.(unhexlify|a2b_base64)|__import__\s*\(\s*['"](base64|zlib|marshal|codecs|binascii)['"]\s*\))/
        // Python, two steps: payload = base64.b64decode(...) then exec(payload) on the next line(s)
        $py_two_step = /(b64decode|b32decode|zlib\.decompress|marshal\.loads|unhexlify|bytes\.fromhex)\s*\([^\n]{0,400}(\n[^\n]{0,300}){0,2}\n[^\n]{0,40}\b(exec|eval)\s*\(/
        // JavaScript: eval(atob(...)), new Function(atob(...)), eval(Buffer.from(x,'base64').toString())
        $js_atob = /\b(eval|Function)\s*\(\s*(window\.)?atob\s*\(/
        $js_buffer = /\b(eval|Function)\s*\(\s*Buffer\.from\s*\([^)\n]{0,4000},\s*['"](base64|hex)['"]\s*\)\s*\.toString\s*\(/
        // PHP webshell classic: eval(gzinflate(base64_decode(...)))
        $php = /\b(eval|assert)\s*\(\s*(gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode|hex2bin)\s*\(/ nocase
        // Shell: echo ... | base64 -d | sh
        $sh = /base64\s+(-d|--decode|-D)\s*\|\s*(sudo\s+)?(ba|z|da)?sh\b/
        // PowerShell: -EncodedCommand <long base64>, or iex of a FromBase64String result
        $ps_enc = /powershell(\.exe)?[^\n]{0,60}\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+\/]{40,}={0,2}/ nocase
        $ps_iex = /(iex|invoke-expression)[^\n]{0,120}frombase64string/ nocase
    condition:
        any of them
}

rule detect_credential_harvester {
    meta:
        severity = "high"
        description = "Reads stored credential files (SSH keys, cloud credentials, browser password stores) and also sends data out, or pairs secrets with a webhook/bot exfiltration channel"
    strings:
        $file1 = ".aws/credentials"
        $file2 = ".ssh/id_rsa"
        $file3 = ".ssh/id_ed25519"
        $file4 = "Login Data"
        $file5 = /Local State['"][^\n]{0,200}os_crypt|os_crypt[^\n]{0,200}encrypted_key/
        $file6 = ".git-credentials"
        $file7 = ".docker/config.json"
        $file8 = /wallet\.dat|Exodus[\\\/]exodus\.wallet/ nocase
        $secret1 = /os\.environ[^\n]{0,15}(AWS_SECRET|SECRET|TOKEN|API_KEY|PASSWORD)/ nocase
        $secret2 = /process\.env\.[A-Z_]*(SECRET|TOKEN|KEY|PASSWORD)/
        $net1 = "requests.post"
        $net2 = "socket.send"
        $net3 = "urllib.request.urlopen"
        $net4 = "smtplib"
        $net5 = /fetch\s*\([^\n]{0,200}method\s*:\s*['"]POST/
        $exfil1 = "discord.com/api/webhooks/"
        $exfil2 = "discordapp.com/api/webhooks/"
        $exfil3 = "api.telegram.org/bot"
        $exfil4 = "hooks.slack.com/services/"
    condition:
        ((1 of ($file*)) and (1 of ($net*, $exfil*)))
        or ((1 of ($secret*)) and (1 of ($exfil*)))
}

rule detect_downloader {
    meta:
        severity = "low"
        description = "Downloads an executable or script file (.exe, .dll, .sh, .ps1, .jar...) - low signal alone; see detect_download_and_execute"
    strings:
        $a = /(urlretrieve|requests\.get|urlopen|wget|curl|DownloadFile|Invoke-WebRequest|iwr|fetch)[^\n]{0,250}\.(exe|dll|scr|bat|cmd|ps1|vbs|hta|msi|jar|apk|elf|bin|so|sh)['"\s)]/ nocase
    condition:
        $a
}

rule detect_download_and_execute {
    meta:
        severity = "high"
        description = "Downloads a remote resource and runs it straight away (download nested in, or within a few lines of, an exec/eval/system call)"
    strings:
        // Python: exec(urlopen(...).read()), exec(requests.get(...).text)
        $py_nested = /\b(exec|eval)\s*\(\s*(urllib\.request\.|urllib2\.)?(urlopen\s*\(|requests\.get\s*\()/
        // Python: download, then within 3 lines run it
        $py_steps = /(urlretrieve|urlopen|requests\.get)\s*\([^\n]{0,300}(\n[^\n]{0,300}){0,3}\b(os\.system|os\.startfile|os\.popen|subprocess\.(call|run|Popen|check_call|check_output)|exec|eval)\s*\(/
        // PowerShell cradle: IEX (New-Object Net.WebClient).DownloadString(...)
        $ps1 = /(iex|invoke-expression)[^\n]{0,80}(downloadstring|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b)/ nocase
        $ps2 = /(downloadstring|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b)[^\n]{0,200}\|\s*(iex|invoke-expression)\b/ nocase
        // Windows LOLBins fetching and running
        $lol1 = /certutil(\.exe)?\s[^\n]{0,40}-urlcache[^\n]{0,40}-f\s/ nocase
        $lol2 = /mshta(\.exe)?\s+["']?https?:\/\// nocase
        $lol3 = /regsvr32[^\n]{0,60}\/i:https?:\/\// nocase
        // Shell: download to a file, then make it executable and run it within 3 lines
        $sh_steps = /(curl|wget)\s[^\n]{0,300}(\n[^\n]{0,300}){0,3}chmod\s+(\+x|[0-7]?[0-7]*[1357])\s[^\n]{0,120}(&&|;|\n)\s*(\.\/|\/tmp\/|nohup\s)/
        // Node: child_process exec of a downloaded script
        $node = /(exec|execSync|spawn)\s*\(\s*['"`](curl|wget)\s[^\n'"`]{0,300}\|\s*(ba)?sh/
    condition:
        any of them
}

rule detect_pipe_to_shell {
    meta:
        severity = "medium"
        description = "Pipes a downloaded script straight into a shell (curl ... | sh) - also how many legitimate installers work, so medium rather than high"
    strings:
        $a = /(curl|wget)\s[^\n|;]{0,300}\|\s*(sudo\s+)?(-E\s+)?(ba|z|da)?sh\b/
    condition:
        $a
}

rule detect_obfuscated_string_execution {
    meta:
        severity = "high"
        description = "Builds a string from character codes or hex escapes and executes it in the same expression"
    strings:
        $py_join = /\b(exec|eval)\s*\(\s*(''|"")\.join\s*\(/
        $py_chr = /\b(exec|eval)\s*\(\s*(chr\s*\(\s*\d+\s*\)\s*\+\s*){3,}/
        $py_hex = /\b(exec|eval)\s*\(\s*b?['"](\\x[0-9a-fA-F]{2}){8,}/
        $js_fcc = /\b(eval|Function)\s*\(\s*String\.fromCharCode\s*\(/
        $js_unescape = /\b(eval|document\.write)\s*\(\s*unescape\s*\(/
        $js_hex = /\b(eval|Function)\s*\(\s*['"](\\x[0-9a-fA-F]{2}){8,}/
        $js_docwrite = /document\.write\s*\(\s*(String\.fromCharCode|atob)\s*\(/
    condition:
        any of them
}

rule detect_known_obfuscator {
    meta:
        severity = "medium"
        description = "Output of a known code obfuscator or packer (javascript-obfuscator, Dean Edwards packer, PyArmor, JSFuck) - sometimes used to protect legitimate code, but hides what the code does from review"
    strings:
        $jsobf_decl = /var _0x[a-f0-9]{4,6}\s*=\s*\[/
        $jsobf_id = /\b_0x[a-f0-9]{4,6}\b/
        $packer = "eval(function(p,a,c,k,e,"
        $pyarmor1 = "__pyarmor__"
        $pyarmor2 = "from pytransform import pyarmor_runtime"
        $pyarmor3 = "pyarmor_runtime_0"
        $jsfuck = /(\(!\[\]\+\[\]\)\[|\[\]\[\(!\[\]\+\[\]\)\[\+\[\]\]|\(\+\[\]\+\[\]\))/
    condition:
        $jsobf_decl or #jsobf_id > 25 or $packer or any of ($pyarmor*) or #jsfuck > 5
}

rule detect_persistence_mechanism {
    meta:
        severity = "high"
        description = "Installs itself to run automatically: adds a cron job, writes a Windows Run registry key, or loads a macOS LaunchAgent"
    strings:
        $cron1 = /crontab\s+-l[^\n]{0,300}\|\s*crontab\s+-/
        $cron2 = /(>>|\btee\s+-a)\s*\/etc\/cron(tab|\.d\/)/
        $cron3 = /open\s*\(\s*['"]\/etc\/cron(tab|\.d\/[^'"]*)['"]\s*,\s*['"][aw]/
        $run1 = /(reg(\.exe)?\s+add|New-ItemProperty|Set-ItemProperty|RegSetValueEx[AW]?|SetValueEx)[^\n]{0,250}CurrentVersion\\{1,2}Run\b/ nocase
        $run2 = /CurrentVersion\\{1,2}Run\b[^\n]{0,250}(\n[^\n]{0,300}){0,4}(SetValueEx|RegSetValueEx|New-ItemProperty|Set-ItemProperty)/ nocase
        $launch1 = /LaunchAgents[^\n]{0,300}(\n[^\n]{0,300}){0,6}launchctl\s+(load|bootstrap)/
        $launch2 = /launchctl\s+(load|bootstrap)[^\n]{0,200}LaunchAgents/
        $schtask = /schtasks(\.exe)?\s+\/create[^\n]{0,200}\/sc\s+(onlogon|onstart|minute)/ nocase
    condition:
        any of them
}

rule detect_shell_profile_modification {
    meta:
        severity = "medium"
        description = "Appends to a shell startup file (~/.bashrc, ~/.zshrc, ~/.profile) - a persistence technique, but also what toolchain installers do to set PATH"
    strings:
        $redirect = /(>>|\btee\s+-a)\s*["']?(~|\$HOME|\$\{HOME\})\/\.(bashrc|bash_profile|zshrc|profile)\b/
        $py_open = /open\s*\([^\n]{0,120}\.(bashrc|bash_profile|zshrc|profile)['"][^\n]{0,40},\s*['"]a/
    condition:
        any of them
}

rule detect_anti_analysis {
    meta:
        severity = "high"
        description = "Checks for a debugger together with a VM or sandbox before continuing - a malware evasion technique; one check alone is common in legitimate crash handlers and games"
    strings:
        $dbg1 = "IsDebuggerPresent"
        $dbg2 = "CheckRemoteDebuggerPresent"
        $dbg3 = "ptrace(PTRACE_TRACEME"
        $dbg4 = "NtQueryInformationProcess"
        $vm1 = "VBoxService" nocase
        $vm2 = "VBoxGuest" nocase
        $vm3 = "vmtoolsd" nocase
        $vm4 = "SbieDll.dll" nocase
        $vm5 = "sandboxie" nocase
        $vm6 = "wine_get_unix_file_name"
        $vm7 = /\b(vmware|virtualbox|qemu)\b[^\n]{0,80}(exit|quit|sys\.exit|ExitProcess|return)/ nocase
    condition:
        (1 of ($dbg*) and 1 of ($vm*)) or 2 of ($vm*)
}

rule detect_crypto_miner {
    meta:
        severity = "high"
        description = "Connects to a cryptocurrency mining pool or carries an XMRig miner configuration"
    strings:
        $a = "stratum+tcp://"
        $b = "stratum+ssl://"
        $c = "stratum+tls://"
        $d = "--donate-level"
        $e = "\"donate-level\""
        $f = /xmrig[^\n]{0,200}\s(-o|--url)\s/ nocase
        $g = /(pool\.minergate\.com|xmrpool\.eu|supportxmr\.com|nanopool\.org|moneroocean\.stream)/ nocase
    condition:
        any of them
}

rule detect_process_injection {
    meta:
        severity = "high"
        description = "Windows remote process injection: allocate memory in another process, write to it, and start a thread there"
    strings:
        $alloc = "VirtualAllocEx"
        $write = "WriteProcessMemory"
        $thread1 = "CreateRemoteThread"
        $thread2 = "NtCreateThreadEx"
        $thread3 = "QueueUserAPC"
        $thread4 = "RtlCreateUserThread"
    condition:
        $alloc and $write and 1 of ($thread*)
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
