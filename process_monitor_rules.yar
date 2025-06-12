rule ProcessMonitor_String {
    meta:
        description = "Detects by unique strings"
        author = "Your Name"
    strings:
        $str1 = "PROC_MON_K3Y-2024" fullword ascii
        $str2 = "admin@security.local" fullword ascii
        $usage = "Usage: process_monitor <pid>" ascii
    condition:
        any of them
}

rule ProcessMonitor_Hex {
    meta:
        description = "Detects by magic number and ELF signature"
    strings:
        $magic = { EF BE AD DE }
        $elf = { 7F 45 4C 46 }
    condition:
        all of them
}

rule ProcessMonitor_Size {
    meta:
        description = "Detects by exact file size"
    condition:
        filesize == 10928
}

rule ProcessMonitor_Hash {
    meta:
        description = "Detects by характерным функциям"
    strings:
        $printf = "printf" ascii
        $atoi = "atoi" ascii
    condition:
        all of them
}

rule ProcessMonitor_XOR {
    meta:
        description = "Detects by section names"
    strings:
        $text = ".text" ascii
        $rodata = ".rodata" ascii
    condition:
        all of them
}
