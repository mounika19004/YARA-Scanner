rule Malware_Dropper
{
    meta:
        description = "Detects files that drop other malicious files"
        author = "Mounika"
        date = "2025-08-14"

    strings:
        $drop1 = "CreateFileA" ascii
        $drop2 = "WriteFile" ascii
        $drop3 = "LoadLibraryA" ascii

    condition:
        all of them
}
