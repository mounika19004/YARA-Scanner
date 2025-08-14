rule Ransomware_Generic
{
    meta:
        description = "Detects files with ransomware behavior"
        author = "Mounika"
        date = "2025-08-14"

    strings:
        $ext1 = ".locked"
        $ext2 = ".encrypted"
        $msg1 = "Your files have been encrypted" nocase
        $btc = "bitcoin" nocase

    condition:
        any of them
}
