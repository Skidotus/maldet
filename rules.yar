rule detect_reverse_shell {
    meta:
        description = "Detects reverse shell patterns"
    strings:
        $a = "bash -i >& /dev/tcp"
        $b = "nc -e /bin/bash"
        $c = "socket.connect"
        $d = "/bin/sh -i"
    condition:
        any of them
}

rule detect_base64_exec {
    meta:
        description = "Detects base64 encoded execution"
    strings:
        $a = "base64 -d"
        $b = "eval(base64"
        $c = "exec(base64"
    condition:
        any of them
}

rule detect_credential_harvester {
    meta:
        description = "Detects credential harvesting"
    strings:
        $a = "os.environ"
        $b = "AWS_SECRET"
        $c = "password" nocase
        $d = "api_key" nocase
    condition:
        2 of them
}

rule detect_downloader {
    meta:
        description = "Detects suspicious download behavior"
    strings:
        $a = "urllib.request"
        $b = "requests.get"
        $c = "wget"
        $d = "curl -o"
    condition:
        any of them
}

