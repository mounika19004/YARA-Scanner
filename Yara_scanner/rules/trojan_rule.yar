rule TrojanSample
{
    meta:
        description = "Detects files containing trojan signature"
        author = "Mounika"
        date = "2025-08-14"

    strings:
        $a = "evil_payload" nocase
        $b = { 90 90 90 90 } // Example byte pattern

    condition:
        any of them
}
