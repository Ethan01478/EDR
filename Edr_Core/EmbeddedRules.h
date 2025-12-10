#pragma once

const char* INTERNAL_YARA_RULES = R"(

rule CSharp_Malware_BOMBE_Memory_Scan {

    strings:
        $s1 = "https://submit.bombe.top/submitMalAns" ascii wide
        $s2 = "bhrome\\Login Data" ascii wide
        $s4 = "SOFTWARE\\BOMBE" ascii wide
        $s5 = "BOMBE_MAL_FLAG_" ascii wide
        $s6 = "SELECT origin_url, username_value, password_value FROM logins" ascii wide
        $s7 = "00000000000000000000000000000000" ascii wide 
        $w1 = "bsass" ascii wide

    condition :
        1 of ($s*) and $w1
}

)";