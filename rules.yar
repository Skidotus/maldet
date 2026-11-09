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

Every string is `ascii wide` (2026-11-09), so each rule also matches UTF-16
text, which is how Windows PowerShell often saves scripts. Before, a reverse
shell saved as UTF-16 matched nothing here. YARA applies `wide` per character,
so the {0,N} gaps still count characters, not bytes. Over the 43-repo trial set
it added one match (a UTF-16 malware stage in InQuest's samples) and none in
clean repos. tests/test_yara_rules.py checks every sample in UTF-16 as well;
keep `ascii wide` on any string you add.
*/

rule detect_reverse_shell {
    meta:
        severity = "high"
        attack = "T1059.004"
        description = "Reverse shell command patterns"
    strings:
        $a = "bash -i >& /dev/tcp" ascii wide
        $b = "nc -e /bin/sh" ascii wide
        $c = "nc -e /bin/bash" ascii wide
        $d = "/bin/sh -i" ascii wide
        $e = "/bin/bash -i" ascii wide
        $f = "os.dup2(s.fileno()" ascii wide
        $g = "pty.spawn(\"/bin/" ascii wide
        $h = "pty.spawn('/bin/" ascii wide
        // "#!/bin/bash -i" only asks for an interactive script: it is not a
        // reverse shell. Counted so that a header alone does not fire, while
        // the same text anywhere else in the file still does.
        $shebang = /#![ \t]*\/bin\/(ba)?sh -i/ ascii wide
    condition:
        any of ($a, $b, $c, $f, $g, $h) or (#d + #e) > #shebang
}

rule detect_base64_exec {
    meta:
        severity = "high"
        attack = "T1140,T1027"
        description = "Decodes or decompresses a hidden payload and executes it directly (decode call nested in, or on the line before, an exec/eval)"
    strings:
        // Python: exec(base64.b64decode(...)), eval(zlib.decompress(...)), exec(marshal.loads(...))
        $py_nested = /\b(exec|eval)\s*\(\s*(base64\.(b64|b32|b16|a85|b85|urlsafe_b64)decode|codecs\.decode|zlib\.decompress|bz2\.decompress|lzma\.decompress|gzip\.decompress|marshal\.loads|bytes\.fromhex|binascii\.(unhexlify|a2b_base64)|__import__\s*\(\s*['"](base64|zlib|marshal|codecs|binascii)['"]\s*\))/ ascii wide
        // Python, two steps: payload = base64.b64decode(...) then exec(payload) on the next line(s)
        $py_two_step = /(b64decode|b32decode|zlib\.decompress|marshal\.loads|unhexlify|bytes\.fromhex)\s*\([^\n]{0,400}(\n[^\n]{0,300}){0,2}\n[^\n]{0,40}\b(exec|eval)\s*\(/ ascii wide
        // JavaScript: eval(atob(...)), new Function(atob(...)), eval(Buffer.from(x,'base64').toString())
        $js_atob = /\b(eval|Function)\s*\(\s*(window\.)?atob\s*\(/ ascii wide
        $js_buffer = /\b(eval|Function)\s*\(\s*Buffer\.from\s*\([^)\n]{0,4000},\s*['"](base64|hex)['"]\s*\)\s*\.toString\s*\(/ ascii wide
        // PHP webshell classic: eval(gzinflate(base64_decode(...)))
        $php = /\b(eval|assert)\s*\(\s*(gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode|hex2bin)\s*\(/ nocase ascii wide
        // Shell: echo ... | base64 -d | sh
        $sh = /base64\s+(-d|--decode|-D)\s*\|\s*(sudo\s+)?(ba|z|da)?sh\b/ ascii wide
        // PowerShell: -EncodedCommand <long base64>, or iex of a FromBase64String result
        $ps_enc = /powershell(\.exe)?[^\n]{0,60}\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+\/]{40,}={0,2}/ nocase ascii wide
        $ps_iex = /(iex|invoke-expression)[^\n]{0,120}frombase64string/ nocase ascii wide
    condition:
        any of them
}

rule detect_credential_harvester {
    meta:
        severity = "high"
        attack = "T1552.001,T1555.003"
        description = "Reads stored credential files (SSH keys, cloud credentials, browser password stores) and also sends data out, or pairs secrets with a webhook/bot exfiltration channel"
    strings:
        $file1 = ".aws/credentials" ascii wide
        $file2 = ".ssh/id_rsa" ascii wide
        $file3 = ".ssh/id_ed25519" ascii wide
        $file4 = "Login Data" ascii wide
        $file5 = /Local State['"][^\n]{0,200}os_crypt|os_crypt[^\n]{0,200}encrypted_key/ ascii wide
        $file6 = ".git-credentials" ascii wide
        $file7 = ".docker/config.json" ascii wide
        $file8 = /wallet\.dat|Exodus[\\\/]exodus\.wallet/ nocase ascii wide
        $secret1 = /os\.environ[^\n]{0,15}(AWS_SECRET|SECRET|TOKEN|API_KEY|PASSWORD)/ nocase ascii wide
        $secret2 = /process\.env\.[A-Z_]*(SECRET|TOKEN|KEY|PASSWORD)/ ascii wide
        $net1 = "requests.post" ascii wide
        $net2 = "socket.send" ascii wide
        $net3 = "urllib.request.urlopen" ascii wide
        $net4 = "smtplib" ascii wide
        $net5 = /fetch\s*\([^\n]{0,200}method\s*:\s*['"]POST/ ascii wide
        $exfil1 = "discord.com/api/webhooks/" ascii wide
        $exfil2 = "discordapp.com/api/webhooks/" ascii wide
        $exfil3 = "api.telegram.org/bot" ascii wide
        $exfil4 = "hooks.slack.com/services/" ascii wide
    condition:
        ((1 of ($file*)) and (1 of ($net*, $exfil*)))
        or ((1 of ($secret*)) and (1 of ($exfil*)))
}

rule detect_downloader {
    meta:
        severity = "low"
        attack = "T1105"
        description = "Downloads an executable or script file (.exe, .dll, .sh, .ps1, .jar...) - low signal alone; see detect_download_and_execute"
    strings:
        // The keyword must be used like a command or a call. Without this,
        // an emoji stylesheet listing "curl,.cmd" and "curly_loop,.cmd" counted.
        $a = /\b(urlretrieve|requests\.get|urlopen|wget|curl|DownloadFile|Invoke-WebRequest|iwr|fetch)(\.exe)?[ \t("'][^\n]{0,250}\.(exe|dll|scr|bat|cmd|ps1|vbs|hta|msi|jar|apk|elf|bin|so|sh)['"\s)]/ nocase ascii wide
    condition:
        $a
}

rule detect_download_and_execute {
    meta:
        severity = "high"
        attack = "T1105,T1059"
        description = "Downloads a remote resource and runs it straight away (download nested in, or within a few lines of, an exec/eval/system call)"
    strings:
        // Python: exec(urlopen(...).read()), exec(requests.get(...).text)
        $py_nested = /\b(exec|eval)\s*\(\s*(urllib\.request\.|urllib2\.)?(urlopen\s*\(|requests\.get\s*\()/ ascii wide
        // Python: download, then within 3 lines run it
        $py_steps = /(urlretrieve|urlopen|requests\.get)\s*\([^\n]{0,300}(\n[^\n]{0,300}){0,3}\b(os\.system|os\.startfile|os\.popen|subprocess\.(call|run|Popen|check_call|check_output)|exec|eval)\s*\(/ ascii wide
        // PowerShell cradle: IEX (New-Object Net.WebClient).DownloadString(...)
        $ps1 = /(iex|invoke-expression)[^\n]{0,80}(downloadstring|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b)/ nocase ascii wide
        $ps2 = /(downloadstring|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b)[^\n]{0,200}\|\s*(iex|invoke-expression)\b/ nocase ascii wide
        // Windows LOLBins fetching and running
        $lol1 = /certutil(\.exe)?\s[^\n]{0,40}-urlcache[^\n]{0,40}-f\s/ nocase ascii wide
        $lol2 = /mshta(\.exe)?\s+["']?https?:\/\// nocase ascii wide
        $lol3 = /regsvr32[^\n]{0,60}\/i:https?:\/\// nocase ascii wide
        // Shell: download to a file, then make it executable and run it within 3 lines
        $sh_steps = /(curl|wget)\s[^\n]{0,300}(\n[^\n]{0,300}){0,3}chmod\s+(\+x|[0-7]?[0-7]*[1357])\s[^\n]{0,120}(&&|;|\n)\s*(\.\/|\/tmp\/|nohup\s)/ ascii wide
        // Node: child_process exec of a downloaded script
        $node = /(exec|execSync|spawn)\s*\(\s*['"`](curl|wget)\s[^\n'"`]{0,300}\|\s*(ba)?sh/ ascii wide
    condition:
        any of them
}

rule detect_pipe_to_shell {
    meta:
        severity = "medium"
        attack = "T1105,T1059.004"
        description = "Pipes a downloaded script straight into a shell (curl ... | sh) - also how many legitimate installers work, so medium rather than high"
    strings:
        $a = /(curl|wget)\s[^\n|;]{0,300}\|\s*(sudo\s+)?(-E\s+)?(ba|z|da)?sh\b/ ascii wide
    condition:
        $a
}

rule detect_obfuscated_string_execution {
    meta:
        severity = "high"
        attack = "T1027"
        description = "Builds a string from character codes or hex escapes and executes it in the same expression"
    strings:
        $py_join = /\b(exec|eval)\s*\(\s*(''|"")\.join\s*\(/ ascii wide
        $py_chr = /\b(exec|eval)\s*\(\s*(chr\s*\(\s*\d+\s*\)\s*\+\s*){3,}/ ascii wide
        $py_hex = /\b(exec|eval)\s*\(\s*b?['"](\\x[0-9a-fA-F]{2}){8,}/ ascii wide
        $js_fcc = /\b(eval|Function)\s*\(\s*String\.fromCharCode\s*\(/ ascii wide
        $js_unescape = /\b(eval|document\.write)\s*\(\s*unescape\s*\(/ ascii wide
        $js_hex = /\b(eval|Function)\s*\(\s*['"](\\x[0-9a-fA-F]{2}){8,}/ ascii wide
        $js_docwrite = /document\.write\s*\(\s*(String\.fromCharCode|atob)\s*\(/ ascii wide
    condition:
        any of them
}

rule detect_known_obfuscator {
    meta:
        severity = "medium"
        attack = "T1027"
        description = "Output of a known code obfuscator or packer (javascript-obfuscator, Dean Edwards packer, PyArmor, JSFuck) - sometimes used to protect legitimate code, but hides what the code does from review"
    strings:
        $jsobf_decl = /var _0x[a-f0-9]{4,6}\s*=\s*\[/ ascii wide
        $jsobf_id = /\b_0x[a-f0-9]{4,6}\b/ ascii wide
        $packer = "eval(function(p,a,c,k,e," ascii wide
        $pyarmor1 = "__pyarmor__" ascii wide
        $pyarmor2 = "from pytransform import pyarmor_runtime" ascii wide
        $pyarmor3 = "pyarmor_runtime_0" ascii wide
        $jsfuck = /(\(!\[\]\+\[\]\)\[|\[\]\[\(!\[\]\+\[\]\)\[\+\[\]\]|\(\+\[\]\+\[\]\))/ ascii wide
    condition:
        $jsobf_decl or #jsobf_id > 25 or $packer or any of ($pyarmor*) or #jsfuck > 5
}

rule detect_persistence_mechanism {
    meta:
        severity = "high"
        attack = "T1053.003,T1547.001,T1543.001,T1053.005"
        description = "Installs itself to run automatically: adds a cron job, writes a Windows Run registry key, or loads a macOS LaunchAgent"
    strings:
        $cron1 = /crontab\s+-l[^\n]{0,300}\|\s*crontab\s+-/ ascii wide
        $cron2 = /(>>|\btee\s+-a)\s*\/etc\/cron(tab|\.d\/)/ ascii wide
        $cron3 = /open\s*\(\s*['"]\/etc\/cron(tab|\.d\/[^'"]*)['"]\s*,\s*['"][aw]/ ascii wide
        $run1 = /(reg(\.exe)?\s+add|New-ItemProperty|Set-ItemProperty|RegSetValueEx[AW]?|SetValueEx)[^\n]{0,250}CurrentVersion\\{1,2}Run\b/ nocase ascii wide
        $run2 = /CurrentVersion\\{1,2}Run\b[^\n]{0,250}(\n[^\n]{0,300}){0,4}(SetValueEx|RegSetValueEx|New-ItemProperty|Set-ItemProperty)/ nocase ascii wide
        $launch1 = /LaunchAgents[^\n]{0,300}(\n[^\n]{0,300}){0,6}launchctl\s+(load|bootstrap)/ ascii wide
        $launch2 = /launchctl\s+(load|bootstrap)[^\n]{0,200}LaunchAgents/ ascii wide
        $schtask = /schtasks(\.exe)?\s+\/create[^\n]{0,200}\/sc\s+(onlogon|onstart|minute)/ nocase ascii wide
    condition:
        any of them
}

rule detect_shell_profile_modification {
    meta:
        severity = "medium"
        attack = "T1546.004"
        description = "Appends to a shell startup file (~/.bashrc, ~/.zshrc, ~/.profile) - a persistence technique, but also what toolchain installers do to set PATH"
    strings:
        $redirect = /(>>|\btee\s+-a)\s*["']?(~|\$HOME|\$\{HOME\})\/\.(bashrc|bash_profile|zshrc|profile)\b/ ascii wide
        $py_open = /open\s*\([^\n]{0,120}\.(bashrc|bash_profile|zshrc|profile)['"][^\n]{0,40},\s*['"]a/ ascii wide
    condition:
        any of them
}

rule detect_anti_analysis {
    meta:
        severity = "high"
        attack = "T1497,T1622"
        description = "Checks for a debugger together with a VM or sandbox before continuing - a malware evasion technique; one check alone is common in legitimate crash handlers and games"
    strings:
        $dbg1 = "IsDebuggerPresent" ascii wide
        $dbg2 = "CheckRemoteDebuggerPresent" ascii wide
        $dbg3 = "ptrace(PTRACE_TRACEME" ascii wide
        $dbg4 = "NtQueryInformationProcess" ascii wide
        $vm1 = "VBoxService" nocase ascii wide
        $vm2 = "VBoxGuest" nocase ascii wide
        $vm3 = "vmtoolsd" nocase ascii wide
        $vm4 = "SbieDll.dll" nocase ascii wide
        $vm5 = "sandboxie" nocase ascii wide
        $vm6 = "wine_get_unix_file_name" ascii wide
        $vm7 = /\b(vmware|virtualbox|qemu)\b[^\n]{0,80}(exit|quit|sys\.exit|ExitProcess|return)/ nocase ascii wide
    condition:
        (1 of ($dbg*) and 1 of ($vm*)) or 2 of ($vm*)
}

rule detect_crypto_miner {
    meta:
        severity = "high"
        attack = "T1496"
        description = "Connects to a cryptocurrency mining pool or carries an XMRig miner configuration"
    strings:
        $a = "stratum+tcp://" ascii wide
        $b = "stratum+ssl://" ascii wide
        $c = "stratum+tls://" ascii wide
        $d = "--donate-level" ascii wide
        $e = "\"donate-level\"" ascii wide
        $f = /xmrig[^\n]{0,200}\s(-o|--url)\s/ nocase ascii wide
        $g = /(pool\.minergate\.com|xmrpool\.eu|supportxmr\.com|nanopool\.org|moneroocean\.stream)/ nocase ascii wide
    condition:
        any of them
}

rule detect_process_injection {
    meta:
        severity = "high"
        attack = "T1055"
        description = "Windows remote process injection: allocate memory in another process, write to it, and start a thread there"
    strings:
        $alloc = "VirtualAllocEx" ascii wide
        $write = "WriteProcessMemory" ascii wide
        $thread1 = "CreateRemoteThread" ascii wide
        $thread2 = "NtCreateThreadEx" ascii wide
        $thread3 = "QueueUserAPC" ascii wide
        $thread4 = "RtlCreateUserThread" ascii wide
    condition:
        $alloc and $write and 1 of ($thread*)
}

rule detect_clipboard_hijack {
    meta:
        severity = "medium"
        attack = "T1115"
        description = "Reads the clipboard alongside crypto-wallet-address-shaped patterns - a known 'clipper' malware technique that swaps a copied address for the attacker's own"
    strings:
        $clip1 = "win32clipboard" nocase ascii wide
        $clip2 = "pyperclip" ascii wide
        $clip3 = "navigator.clipboard" ascii wide
        $wallet1 = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/ ascii wide
        $wallet2 = /\b0x[a-fA-F0-9]{40}\b/ ascii wide
    condition:
        (1 of ($clip*)) and (1 of ($wallet*))
}
