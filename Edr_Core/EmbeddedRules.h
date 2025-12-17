#pragma once

const char* INTERNAL_YARA_RULES = R"(

rule CSharp_Malware_BOMBE_Memory_Scan {

    strings:
        $s1 = "https://submit.bombe.top/submitMalAns" ascii wide
        $s2 = "bhrome\\Login Data" ascii wide nocase
        $s3 = "SOFTWARE\\BOMBE" ascii wide
        $s4 = "BOMBE_MAL_FLAG_" ascii wide
        $s5 = "SELECT origin_url, username_value, password_value FROM logins" ascii wide
        $s6 = "00000000000000000000000000000000" ascii wide 
        $w1 = "bsass" ascii wide nocase

    condition :
        (1 of ($s*) and $w1) or (2 of ($s*))
}

)";