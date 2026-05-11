// ============================================================
// RULECAST — YARA TEST SUITE
//
// EXPECTED RESULTS (update when adding rules):
//   Total rules  : 113
//   Valid        : 85
//   Invalid      : 28
//   Incomplete   : 5
//
// Run with: python3 main.py test → choose yara → file → 1
// ============================================================


// ============================================================
// VALID RULES — BASIC
// ============================================================

rule Valid_Minimal {
    condition:
        true
}

rule Valid_False_Condition {
    condition:
        false
}


// ============================================================
// VALID RULES — STRINGS
// ============================================================

rule Valid_String_Simple {
    strings:
        $a = "hello world"
    condition:
        $a
}

rule Valid_String_Hex {
    strings:
        $hex = { DE AD BE EF CA FE BA BE }
    condition:
        $hex
}

rule Valid_String_Regex {
    strings:
        $re = /malware[0-9]+\.exe/i
    condition:
        $re
}

rule Valid_String_Wide {
    strings:
        $wide = "malware" wide
    condition:
        $wide
}

rule Valid_String_Ascii_Wide {
    strings:
        $aw = "evil" ascii wide
    condition:
        $aw
}

rule Valid_String_Nocase {
    strings:
        $nc = "Evil" nocase
    condition:
        $nc
}

rule Valid_String_Fullword {
    strings:
        $fw = "cmd.exe" fullword
    condition:
        $fw
}

rule Valid_Multiple_Strings {
    strings:
        $a = "string_one"
        $b = "string_two"
        $c = "string_three"
    condition:
        $a or $b or $c
}

rule Valid_All_Of {
    strings:
        $a = "one"
        $b = "two"
        $c = "three"
    condition:
        all of them
}

rule Valid_Any_Of {
    strings:
        $a = "one"
        $b = "two"
    condition:
        any of them
}

rule Valid_None_Of {
    strings:
        $a = "evil"
        $b = "malware"
    condition:
        none of them
}

rule Valid_Count {
    strings:
        $a = "bad"
    condition:
        #a > 3
}

rule Valid_At_Offset {
    strings:
        $a = "MZ"
    condition:
        $a at 0
}

rule Valid_In_Range {
    strings:
        $a = "PE"
    condition:
        $a in (0..100)
}

rule Valid_Xor_String {
    strings:
        $x = "malware" xor
    condition:
        $x
}

rule Valid_Xor_Range {
    strings:
        $x = "virus" xor(1-255)
    condition:
        $x
}

rule Valid_Escaped_Quote {
    strings:
        $a = "he said \"hello\""
    condition:
        $a
}

rule Valid_Backslash {
    strings:
        $a = "C:\\Windows\\System32"
    condition:
        $a
}

rule Valid_Brace_In_String {
    strings:
        $a = "function() { return { key: 'value' }; }"
    condition:
        $a
}

rule Valid_Nocase_Fullword {
    strings:
        $a = "PowerShell" nocase fullword
    condition:
        $a
}

// ============================================================
// VALID RULES — HEX
// ============================================================

rule Valid_Hex_Wildcard {
    strings:
        $h = { 4D 5A ?? ?? ?? ?? 00 }
    condition:
        $h
}

rule Valid_Hex_Jump {
    strings:
        $h = { DE AD [2-4] BE EF }
    condition:
        $h
}

rule Valid_Hex_Alternatives {
    strings:
        $h = { (DE | AD) BE EF }
    condition:
        $h
}

rule Valid_Long_Hex {
    strings:
        $h = {
            4D 5A 90 00 03 00 00 00
            04 00 00 00 FF FF 00 00
            B8 00 00 00 00 00 00 00
            40 00 00 00 00 00 00 00
        }
    condition:
        $h at 0
}

rule Valid_Hex_All_Nibbles {
    strings:
        $h = { 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF }
    condition:
        $h
}

rule Valid_Curly_In_Regex {
    strings:
        $r = /a{3,5}b{2}/
    condition:
        $r
}


// ============================================================
// VALID RULES — METADATA (these previously triggered plyara bug)
// ============================================================

rule Valid_With_Meta {
    meta:
        author = "test"
        description = "A test rule"
        version = "1.0"
    condition:
        true
}

rule Valid_Meta_All_Types {
    meta:
        author = "Jane Doe"
        description = "Detects CVE-2021-44228 log4shell"
        reference = "https://example.com"
        date = "2024-01-01"
        version = "2.3"
        severity = "high"
        id = "550e8400-e29b-41d4-a716-446655440000"
    condition:
        true
}

rule Valid_Only_Meta {
    meta:
        author = "ghost"
        description = "no strings needed"
    condition:
        filesize > 0
}

rule Valid_With_Comments {
    meta:
        author = "tester"
    strings:
        $a = "evil"
    condition:
        $a
}

rule Valid_Meta_Duplicate_Key {
    meta:
        author = "first"
        author = "second"
    condition:
        true
}


// ============================================================
// VALID RULES — TAGS
// ============================================================

rule Valid_With_Tags : malware ransomware {
    condition:
        true
}

rule Valid_Tags_And_Meta : apt trojan {
    meta:
        author = "tester"
    condition:
        false
}

rule Valid_Many_Tags : malware trojan apt ransomware stealer dropper loader {
    condition:
        true
}


// ============================================================
// VALID RULES — MODIFIERS
// ============================================================

global rule Valid_Global {
    condition:
        true
}

private rule Valid_Private {
    condition:
        true
}

global private rule Valid_Global_Private {
    condition:
        true
}


// ============================================================
// VALID RULES — CONDITIONS
// ============================================================

rule Valid_Filesize_Less {
    condition:
        filesize < 1MB
}

rule Valid_Filesize_Greater {
    condition:
        filesize > 500KB
}

rule Valid_Filesize_Range {
    condition:
        filesize >= 100 and filesize <= 10MB
}

rule Valid_Arithmetic_Condition {
    condition:
        (filesize % 512) == 0
}

rule Valid_And_Or_Not {
    strings:
        $a = "foo"
        $b = "bar"
    condition:
        ($a and not $b) or (not $a and $b)
}

rule Valid_Complex_Condition {
    strings:
        $a = "aaa"
        $b = "bbb"
        $c = "ccc"
    condition:
        (#a > 1) and ($b or $c) and filesize < 5MB
}

rule Valid_Of_Wildcard {
    strings:
        $prefix_one = "aaa"
        $prefix_two = "bbb"
        $prefix_three = "ccc"
    condition:
        2 of ($prefix_*)
}

rule Valid_N_Of_Them {
    strings:
        $a = "a"
        $b = "b"
        $c = "c"
    condition:
        2 of them
}

rule Valid_Offset_Condition {
    strings:
        $a = "EICAR"
    condition:
        $a in (0..filesize)
}

rule Valid_Entrypoint {
    strings:
        $a = "payload"
    condition:
        $a at entrypoint
}

rule Valid_For_Loop {
    strings:
        $a = "loop_target"
    condition:
        for any i in (0..10) : ($a at i)
}


// ============================================================
// VALID RULES — PE MODULE
// ============================================================

import "pe"

rule Valid_PE_Is_PE {
    condition:
        pe.is_pe
}

rule Valid_PE_Machine_x86 {
    condition:
        pe.machine == pe.MACHINE_I386
}

rule Valid_PE_Machine_x64 {
    condition:
        pe.machine == pe.MACHINE_AMD64
}

rule Valid_PE_Number_Of_Sections {
    condition:
        pe.number_of_sections > 3
}

rule Valid_PE_Imports_CreateFile {
    condition:
        pe.imports("kernel32.dll", "CreateFileA")
}

rule Valid_PE_Imports_VirtualAlloc {
    condition:
        pe.imports("kernel32.dll", "VirtualAlloc")
}

rule Valid_PE_With_Strings_And_PE {
    strings:
        $mz = { 4D 5A }
        $sus = "VirtualAlloc"
    condition:
        $mz at 0 and $sus and pe.is_pe
}

rule Valid_PE_Complex {
    meta:
        author = "tester"
        description = "Complex PE rule combining multiple checks"
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell" nocase
    condition:
        pe.is_pe and
        pe.number_of_sections >= 2 and
        ($s1 or $s2) and
        filesize < 5MB
}


// ============================================================
// VALID RULES — EDGE CASES (tricky but valid)
// ============================================================

rule Valid_String_Contains_Rule_Keyword {
    strings:
        $a = "rule myFakeRule { condition: true }"
    condition:
        $a
}

rule Valid_Comment_Looks_Like_Rule {
    // rule FakeRule { condition: true }
    /* rule AnotherFake { condition: false } */
    condition:
        true
}

rule Valid_Name_With_123_underscores___test {
    condition:
        true
}

rule Valid_This_Is_A_Very_Long_Rule_Name_That_Goes_On_And_On_And_On_Still_Going_Yes_Really {
    condition:
        true
}

rule Valid_With_Import_Math {
    strings:
        $data = { 00 01 02 03 }
    condition:
        $data and filesize > 0
}

rule Valid_Hex_In_Condition {
    condition:
        filesize > 0x1000 and filesize < 0x100000
}

rule Valid_True_False_Combined {
    condition:
        true and false
}


// ============================================================
// VALID RULES — SEQUENCES (stress test split_rules)
// ============================================================

rule Valid_SeqA {
    condition: true
}

rule Valid_SeqB {
    condition: true
}

rule Valid_SeqC {
    condition: true
}

rule Valid_SeqD : tag1 tag2 {
    meta:
        x = "y"
    strings:
        $s = "seq"
    condition:
        $s
}

rule Valid_SeqE {
    condition: false
}

rule Valid_NoGap_A {
    condition: true
}
rule Valid_NoGap_B {
    condition: true
}
rule Valid_NoGap_C {
    condition: true
}


// ============================================================
// INVALID RULES — 35 total, expected to FAIL validation
// ============================================================

// invalid_01: missing condition block
rule Invalid_No_Condition {
    strings:
        $a = "test"
}

// invalid_02: empty body
rule Invalid_Empty_Body {
}

// invalid_03: unterminated string
rule Invalid_Unterminated_String {
    strings:
        $a = "unterminated
    condition:
        $a
}

// invalid_04: unknown string modifier
rule Invalid_Unknown_Modifier {
    strings:
        $a = "test" superfast
    condition:
        $a
}

// invalid_05: invalid hex chars
rule Invalid_Bad_Hex {
    strings:
        $h = { ZZ ZZ ZZ }
    condition:
        $h
}

// invalid_06: undefined string reference
rule Invalid_Undefined_String {
    condition:
        $undefined_var
}

// invalid_07: double AND
rule Invalid_Bad_Condition_Syntax {
    condition:
        true and and false
}

// invalid_08: bad filesize unit
rule Invalid_Bad_Unit {
    condition:
        filesize < 1GB_TYPO
}

// invalid_09: junk token at end
rule Invalid_Junk_Token {
    strings:
        $a = "test"
    condition:
        $a
    XXXXX_NOT_VALID
}

// invalid_10: unterminated regex
rule Invalid_Unterminated_Regex {
    strings:
        $r = /open_regex
    condition:
        $r
}

// invalid_11: pe.imports() with wrong arg count
rule Invalid_PE_Import_Too_Many_Args {
    condition:
        pe.imports("kernel32.dll", "CreateFile", "extra_arg")
}

// invalid_12: pe.is_pe used as string (type mismatch)
rule Invalid_PE_Wrong_Type {
    strings:
        $a = pe.is_pe
    condition:
        $a
}

// invalid_13: nonexistent pe function
rule Invalid_PE_No_Import {
    condition:
        pe.number_of_sections > 0 and nonexistent_pe_function()
}

// invalid_14: bare AND with no operands
rule Invalid_Bare_And {
    condition:
        and
}

// invalid_15: empty condition block
rule Invalid_Empty_Condition_Block {
    strings:
        $a = "test"
    condition:
}

// invalid_16: 'rule' keyword in condition
rule Invalid_Nested_Rule_Keyword {
    condition:
        rule
}

// invalid_17: empty string literal
rule Invalid_Empty_String {
    strings:
        $a = ""
    condition:
        $a
}

// invalid_18: undefined variable in condition
rule Invalid_Undefined_Variable {
    condition:
        undefined_variable > 0
}

// invalid_19: wrong type in comparison
rule Invalid_Type_Mismatch {
    condition:
        "string" > 42
}

// valid: YARA actually accepts brace on next line
rule Valid_Brace_On_Next_Line
{
    condition:
        true
}

// ============================================================
// NASTY EDGE CASES — tricky invalid rules
// ============================================================

// nasty_01: rule keyword inside a string that looks like a new rule
// The splitter must NOT split on the 'rule' inside the string
rule Nasty_Rule_Keyword_In_String {
    strings:
        $a = "rule FakeRule { condition: true }"
        $b = "another rule ReallyFake { strings: $x = \"nested\" condition: $x }"
    condition:
        $a or $b
}

// nasty_02: deeply nested braces in multiple strings
rule Nasty_Deeply_Nested_Braces {
    strings:
        $a = "{ { { {{ }} } } }"
        $b = "} { } { }"
        $c = "{{{{{{{{{"
    condition:
        $a or $b or $c
}

// nasty_03: strings that look like comments
rule Nasty_Comment_Like_Strings {
    strings:
        $a = "// this is not a comment"
        $b = "/* also not a comment */"
        $c = "# not a hash comment"
    condition:
        $a or $b or $c
}

// nasty_04: escaped backslashes and quotes nightmare
rule Nasty_Escape_Hell {
    strings:
        $a = "C:\\\\Users\\\\test\\\\file.exe"
        $b = "said \\\"hello\\\" to \\\"world\\\""
        $c = "\\\\"
    condition:
        any of them
}

// nasty_05: hex with all edge patterns together
rule Nasty_Hex_Complex {
    strings:
        $h1 = { 4D 5A [0-4] 50 45 00 00 }
        $h2 = { (4D | 5A) ?? [2] (00 | FF) }
        $h3 = { DE ?? ?? ?? BE ~EF }
    condition:
        all of them
}

// nasty_06: condition using all operators at once
rule Nasty_Complex_Condition {
    strings:
        $a = "alpha"
        $b = "beta"
        $c = "gamma"
        $d = { DE AD BE EF }
    condition:
        (not $a or ($b and $c)) and
        (#a + #b > 2) and
        ($d in (0..512)) and
        (filesize % 16 == 0) and
        (2 of ($a, $b, $c))
}

// nasty_07: multiple imports + cross-module condition
import "math"
import "hash"

rule Nasty_Multi_Import {
    condition:
        math.entropy(0, filesize) > 7.0 and
        filesize > 1024
}

// nasty_08: tags that look like keywords
rule Nasty_Tags_Like_Keywords : rule condition strings meta global private {
    condition:
        true
}

// nasty_09: very long meta block
rule Nasty_Long_Meta {
    meta:
        author = "Very Long Author Name That Goes On And On"
        description = "This is a very long description that contains lots of text including CVE-2023-12345 and CVE-2021-44228 and references to many things"
        reference = "https://very-long-url.example.com/path/to/resource?param=value&other=value"
        date = "2024-01-15"
        version = "99.99.99"
        severity = "critical"
        confidence = "high"
        tlp = "white"
        source = "internal"
        id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    condition:
        true
}

// nasty_10: rule with all string types at once
rule Nasty_All_String_Types {
    strings:
        $text    = "plaintext" nocase fullword
        $wide    = "widestr" wide ascii
        $hex     = { 4D 5A 90 00 }
        $regex   = /[a-z]{3,}\.(exe|dll|sys)/i
        $xor_str = "encoded" xor(1-254)
    condition:
        any of them
}

// nasty_11: INVALID — rule with rule in name (confuses naive parsers)
rule Invalid_Rule_In_The_Name_rule_end {
    condition:
        and
}

// nasty_12: INVALID — condition references strings section that has a syntax error
rule Invalid_Nasty_Mixed_Good_Bad_Strings {
    strings:
        $good = "valid string"
        $bad  = "unterminated
        $also_good = "another valid"
    condition:
        $good or $also_good
}

// nasty_13: INVALID — opening brace on next line (YARA doesn't support this)
rule Valid_Brace_On_Next_Line_2
{
    condition:
        true
}

// nasty_14: INVALID — using 'true' as string variable name
rule Valid_Dollar_True_String_Name {
    strings:
        $true = "test"
    condition:
        $true
}

// nasty_15: INVALID — condition with only a comment
rule Invalid_Only_Comment_In_Condition {
    condition:
        // just a comment
}


// ============================================================
// TRUNCATED / INCOMPLETE RULES — 5 total, no closing brace
// ============================================================

rule Incomplete_No_Closing_Brace {
    condition:
        true

rule Incomplete_Strings_No_Close {
    strings:
        $a = "dangling"
    condition:
        $a

rule Incomplete_Only_Meta {
    meta:
        author = "nobody"

rule Incomplete_Mid_Strings {
    strings:
        $a = "first"
        $b = "second"

rule Incomplete_Empty {