/*
    Mjolnir - Default starter YARA rules.

    This is a small, honest starting set (3 rules), not a comprehensive
    malware ruleset. For real coverage, drop additional .yar files from a
    public community ruleset (e.g. https://github.com/Yara-Rules/rules or
    https://github.com/Neo23x0/signature-base) into this rules/ directory -
    core/yara_scanner.py compiles every *.yar file found here automatically.
*/

rule Suspicious_Webshell_Generic
{
    meta:
        description = "Generic PHP/ASP web shell indicators (eval/system/passthru on user input)"
        severity = "CRITICAL"
        author = "Asgard/Mjolnir"

    strings:
        $eval_b64  = "eval(base64_decode(" nocase
        $system_get = "system($_GET" nocase
        $passthru_post = "passthru($_POST" nocase
        $shell_exec = "shell_exec(" nocase

    condition:
        any of them
}

rule Ransomware_Ransom_Note_Text
{
    meta:
        description = "Common ransomware ransom-note phrasing"
        severity = "CRITICAL"
        author = "Asgard/Mjolnir"

    strings:
        $s1 = "YOUR_FILES_ARE_ENCRYPTED" nocase
        $s2 = "all your files have been encrypted" nocase
        $s3 = "HOW_TO_DECRYPT_FILES" nocase

    condition:
        any of them
}

rule Suspicious_Encoded_PowerShell
{
    meta:
        description = "Encoded PowerShell one-liner execution pattern"
        severity = "HIGH"
        author = "Asgard/Mjolnir"

    strings:
        $enc = /powershell(\.exe)?\s+(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+\/=]{20,}/ nocase
        $iex = "Invoke-Expression(New-Object Net.WebClient)" nocase ascii wide

    condition:
        any of them
}
