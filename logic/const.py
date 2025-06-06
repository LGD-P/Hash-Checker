from prompt_toolkit.styles import Style as St
from questionary import Style

CYBER_STYLE_QUESTIONARY = Style.from_dict({
    'qmark': 'fg:#00ff00 bold',  # token before question
    'question': 'bold',  # question prompt
    'answer': 'fg:#f44336 bold',  # display choice selected
    'pointer': 'fg:#00ff00 bold',  # pointer in select/checkbox
    'highlighted': 'fg:#00ff00 bold',  # higlight choices
    'selected': 'fg:#cc5454',  # item selected
    'separator': 'fg:#cc5454',  # separator
    'instruction': 'bg:#000000 #00ff00',  # instruction
    'text': 'bg:#000000 #ffffff',  # global text
    'disabled': 'fg:#858585 italic',  # choice desable
})

CYBER_STYLE_TOOLKIT = St.from_dict({
    'completion-menu.completion': 'bg:#000000 #00ff00',
    'completion-menu.completion.current': 'bg:#005500 #00ff00',
    'autocomplete': '#00ff00 bold',
})

HASHES_AVAILABLE = [
    'sha3_512', 'sha3_384', 'sha3_256', 'sha3_224',
    'blake2b', 'blake2s',
    'sha512', 'sha384', 'sha512_224', 'sha256', 'sha224',
    'ripemd160',
    'sm3',
    'md5-sha1',
    'md5', 'sha1'
]


ALGORITHM_STRENGTH = {
    'sha3_512': ('Very High', 'sea_green1'),
    'sha3_384': ('High', 'bright_green'),
    'sha3_256': ('High', 'bright_green'),
    'sha3_224': ('Medium', 'gold1'),
    'blake2b': ('Very High', 'sea_green1'),
    'blake2s': ('High', 'bright_green'),
    'sha512': ('Very High', 'sea_green1'),
    'sha384': ('High', 'bright_green'),
    'sha512_224': ('Medium', 'gold1'),
    'sha256': ('Medium', 'gold1'),
    'sha224': ('Medium', 'gold1'),
    'ripemd160': ('Low', 'red'),
    'sm3': ('Medium', 'gold1'),
    'md5-sha1': ('Very Low', 'red1'),
    'md5': ('Very Low', 'red1'),
    'sha1': ('Low', 'red')
}



VIRUS_TOTAL_URL = "https://www.virustotal.com/api/v3/files/"


RESPONSE_EXEMPLE = {
    "data": {
        "id": "44e83f84a5d5219e2f7c3cf1e4f02489cae81361227f46946abe4b8d8245b879",
        "type": "file",
        "links": {
            "self": "https://www.virustotal.com/api/v3/files/44e83f84a5d5219e2f7c3cf1e4f02489cae81361227f46946abe4b8d8245b879"
        },
        "attributes": {
            "names": [
                "PwnKit",
                "PwnKit.",
                "cakilroot",
                "slowend",
                "PwnKit.elf",
                "pk",
                "aab",
                "pkexec.so",
                "videoDownloader.pellet",
                "videoDownloader(1).pellet",
                "videoDownloader",
                "TF12",
                "X13-unix",
                "12.elf",
                "kt",
                "downloaded_file.bin",
                "pwnkit",
                "PK",
                "914258220.exe",
                "PWN",
                "Pwnkit",
                "extract-1707097937.099974-HTTP-FaQdCE3Q3ZqCESNni1",
                "PwnKit.1.bin",
                "pwnkit.bin",
                "PwnKit[1].elf",
                "PwnKit(1)",
                "bruh.txt",
                "60caae55-a99c-4143-bd1b-4c0ecdf27c49.tmp",
                "malware2",
                "garbage.file",
                "cakilroot.unknown",
                "pkexecso.txt",
                "1",
                "composer",
                "kit",
                "THwcXszA.exe",
                "meki",
                "fck",
                "prs1",
                "p_xx",
                "output.236089260.txt",
                "V9jPyD",
                "kit2",
                "gc",
                "pwnk",
                "pwnk_PELIGRO",
                "D7",
                "file.elf",
                "sh",
                "NOTaPwnKit"
            ],
            "last_modification_date": 1748971959,
            "last_analysis_stats": {
                "malicious": 43,
                "suspicious": 0,
                "undetected": 21,
                "harmless": 0,
                "timeout": 0,
                "confirmed-timeout": 0,
                "failure": 0,
                "type-unsupported": 12
            },
            "ssdeep": "192:RHw8At8WCQt4hIf8QB6C2af9SBXeDDcIJeEZ6l:at6QtieB6CVf9iiE3",
            "tlsh": "T1F982550B7751CD3BC5D8827554AB07749277F9B2EB62630B160462F62F4338C8E2EB56",
            "sandbox_verdicts": {
                "Zenbox Linux": {
                    "category": "harmless",
                    "sandbox_name": "Zenbox Linux",
                    "malware_classification": [
                        "CLEAN"
                    ]
                }
            },
            "tags": [
                "64bits",
                "cve-2021-4043",
                "elf",
                "exploit",
                "cve-2017-7308",
                "shared-lib",
                "cve-2021-4034"
            ],
            "elf_info": {
                "build_id": "a049295e94010dfc313c5e5a6f282a68a047522b",
                "interp": "/lib64/ld-linux-x86-64.so.2",
                "header": {
                    "hdr_version": "1 (current)",
                    "type": "DYN (Shared object file)",
                    "obj_version": "0x1",
                    "data": "2's complement, little endian",
                    "machine": "Advanced Micro Devices X86-64",
                    "num_section_headers": 36,
                    "os_abi": "UNIX - System V",
                    "abi_version": 0,
                    "entrypoint": 4865,
                    "num_prog_headers": 13,
                    "class": "ELF64"
                },
                "shared_libraries": [
                    "libc.so.6"
                ],
                "export_list": [
                    {
                        "name": "service_interp",
                        "type": "OBJECT"
                    },
                    {
                        "name": "entry",
                        "type": "FUNC"
                    },
                    {
                        "name": "gconv",
                        "type": "FUNC"
                    },
                    {
                        "name": "gconv_init",
                        "type": "FUNC"
                    },
                    {
                        "name": "rmrf",
                        "type": "FUNC"
                    },
                    {
                        "name": "unlink_cb",
                        "type": "FUNC"
                    },
                    {
                        "name": "rmrf",
                        "type": "FUNC"
                    },
                    {
                        "name": "service_interp",
                        "type": "OBJECT"
                    },
                    {
                        "name": "entry",
                        "type": "FUNC"
                    },
                    {
                        "name": "gconv",
                        "type": "FUNC"
                    },
                    {
                        "name": "unlink_cb",
                        "type": "FUNC"
                    },
                    {
                        "name": "gconv_init",
                        "type": "FUNC"
                    }
                ],
                "import_list": [
                    {
                        "name": "getenv",
                        "type": "FUNC"
                    },
                    {
                        "name": "nftw",
                        "type": "FUNC"
                    },
                    {
                        "name": "__errno_location",
                        "type": "FUNC"
                    },
                    {
                        "name": "remove",
                        "type": "FUNC"
                    },
                    {
                        "name": "_ITM_deregisterTMCloneTable",
                        "type": "NOTYPE"
                    },
                    {
                        "name": "_exit",
                        "type": "FUNC"
                    },
                    {
                        "name": "mkdir",
                        "type": "FUNC"
                    },
                    {
                        "name": "puts",
                        "type": "FUNC"
                    },
                    {
                        "name": "readlink",
                        "type": "FUNC"
                    },
                    {
                        "name": "setresuid",
                        "type": "FUNC"
                    },
                    {
                        "name": "fclose",
                        "type": "FUNC"
                    },
                    {
                        "name": "setresgid",
                        "type": "FUNC"
                    },
                    {
                        "name": "dup2",
                        "type": "FUNC"
                    },
                    {
                        "name": "execvpe",
                        "type": "FUNC"
                    },
                    {
                        "name": "symlink",
                        "type": "FUNC"
                    },
                    {
                        "name": "fputs",
                        "type": "FUNC"
                    },
                    {
                        "name": "close",
                        "type": "FUNC"
                    },
                    {
                        "name": "pipe",
                        "type": "FUNC"
                    },
                    {
                        "name": "read",
                        "type": "FUNC"
                    },
                    {
                        "name": "execve",
                        "type": "FUNC"
                    },
                    {
                        "name": "__gmon_start__",
                        "type": "NOTYPE"
                    },
                    {
                        "name": "memcpy",
                        "type": "FUNC"
                    },
                    {
                        "name": "fopen",
                        "type": "FUNC"
                    },
                    {
                        "name": "perror",
                        "type": "FUNC"
                    },
                    {
                        "name": "creat",
                        "type": "FUNC"
                    },
                    {
                        "name": "_ITM_registerTMCloneTable",
                        "type": "NOTYPE"
                    },
                    {
                        "name": "__cxa_finalize",
                        "type": "FUNC"
                    },
                    {
                        "name": "fork",
                        "type": "FUNC"
                    },
                    {
                        "name": "strstr",
                        "type": "FUNC"
                    },
                    {
                        "name": "getenv@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "nftw@GLIBC_2.3.3",
                        "type": "FUNC"
                    },
                    {
                        "name": "__errno_location@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "remove@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "_ITM_deregisterTMCloneTable",
                        "type": "NOTYPE"
                    },
                    {
                        "name": "_exit@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "mkdir@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "puts@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "readlink@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "setresuid@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "fclose@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "setresgid@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "dup2@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "execvpe@GLIBC_2.11",
                        "type": "FUNC"
                    },
                    {
                        "name": "symlink@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "fputs@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "close@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "pipe@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "read@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "execve@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "__gmon_start__",
                        "type": "NOTYPE"
                    },
                    {
                        "name": "memcpy@GLIBC_2.14",
                        "type": "FUNC"
                    },
                    {
                        "name": "fopen@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "perror@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "creat@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "_ITM_registerTMCloneTable",
                        "type": "NOTYPE"
                    },
                    {
                        "name": "__cxa_finalize@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "fork@GLIBC_2.2.5",
                        "type": "FUNC"
                    },
                    {
                        "name": "strstr@GLIBC_2.2.5",
                        "type": "FUNC"
                    }
                ],
                "section_list": [
                    {
                        "name": "",
                        "section_type": "NULL",
                        "virtual_address": 0,
                        "physical_offset": 0,
                        "size": 0,
                        "flags": ""
                    },
                    {
                        "name": ".note.gnu.property",
                        "section_type": "NOTE",
                        "virtual_address": 792,
                        "physical_offset": 792,
                        "size": 48,
                        "flags": "A"
                    },
                    {
                        "name": ".note.gnu.build-id",
                        "section_type": "NOTE",
                        "virtual_address": 840,
                        "physical_offset": 840,
                        "size": 36,
                        "flags": "A"
                    },
                    {
                        "name": ".gnu.hash",
                        "section_type": "GNU_HASH",
                        "virtual_address": 880,
                        "physical_offset": 880,
                        "size": 60,
                        "flags": "A"
                    },
                    {
                        "name": ".dynsym",
                        "section_type": "DYNSYM",
                        "virtual_address": 944,
                        "physical_offset": 944,
                        "size": 864,
                        "flags": "A"
                    },
                    {
                        "name": ".dynstr",
                        "section_type": "STRTAB",
                        "virtual_address": 1808,
                        "physical_offset": 1808,
                        "size": 360,
                        "flags": "A"
                    },
                    {
                        "name": ".gnu.version",
                        "section_type": "VERSYM",
                        "virtual_address": 2168,
                        "physical_offset": 2168,
                        "size": 72,
                        "flags": "A"
                    },
                    {
                        "name": ".gnu.version_r",
                        "section_type": "VERNEED",
                        "virtual_address": 2240,
                        "physical_offset": 2240,
                        "size": 80,
                        "flags": "A"
                    },
                    {
                        "name": ".rela.dyn",
                        "section_type": "RELA",
                        "virtual_address": 2320,
                        "physical_offset": 2320,
                        "size": 192,
                        "flags": "A"
                    },
                    {
                        "name": ".rela.plt",
                        "section_type": "RELA",
                        "virtual_address": 2512,
                        "physical_offset": 2512,
                        "size": 624,
                        "flags": "AI"
                    },
                    {
                        "name": ".init",
                        "section_type": "PROGBITS",
                        "virtual_address": 4096,
                        "physical_offset": 4096,
                        "size": 27,
                        "flags": "AX"
                    },
                    {
                        "name": ".plt",
                        "section_type": "PROGBITS",
                        "virtual_address": 4128,
                        "physical_offset": 4128,
                        "size": 432,
                        "flags": "AX"
                    },
                    {
                        "name": ".text",
                        "section_type": "PROGBITS",
                        "virtual_address": 4560,
                        "physical_offset": 4560,
                        "size": 1490,
                        "flags": "AX"
                    },
                    {
                        "name": ".fini",
                        "section_type": "PROGBITS",
                        "virtual_address": 6052,
                        "physical_offset": 6052,
                        "size": 13,
                        "flags": "AX"
                    },
                    {
                        "name": ".rodata",
                        "section_type": "PROGBITS",
                        "virtual_address": 8192,
                        "physical_offset": 8192,
                        "size": 405,
                        "flags": "A"
                    },
                    {
                        "name": ".interp",
                        "section_type": "PROGBITS",
                        "virtual_address": 8608,
                        "physical_offset": 8608,
                        "size": 28,
                        "flags": "A"
                    },
                    {
                        "name": ".eh_frame_hdr",
                        "section_type": "PROGBITS",
                        "virtual_address": 8636,
                        "physical_offset": 8636,
                        "size": 60,
                        "flags": "A"
                    },
                    {
                        "name": ".eh_frame",
                        "section_type": "PROGBITS",
                        "virtual_address": 8696,
                        "physical_offset": 8696,
                        "size": 220,
                        "flags": "A"
                    },
                    {
                        "name": ".init_array",
                        "section_type": "INIT_ARRAY",
                        "virtual_address": 15880,
                        "physical_offset": 11784,
                        "size": 8,
                        "flags": "WA"
                    },
                    {
                        "name": ".fini_array",
                        "section_type": "FINI_ARRAY",
                        "virtual_address": 15888,
                        "physical_offset": 11792,
                        "size": 8,
                        "flags": "WA"
                    },
                    {
                        "name": ".dynamic",
                        "section_type": "DYNAMIC",
                        "virtual_address": 15896,
                        "physical_offset": 11800,
                        "size": 448,
                        "flags": "WA"
                    },
                    {
                        "name": ".got",
                        "section_type": "PROGBITS",
                        "virtual_address": 16344,
                        "physical_offset": 12248,
                        "size": 40,
                        "flags": "WA"
                    },
                    {
                        "name": ".got.plt",
                        "section_type": "PROGBITS",
                        "virtual_address": 16384,
                        "physical_offset": 12288,
                        "size": 232,
                        "flags": "WA"
                    },
                    {
                        "name": ".data",
                        "section_type": "PROGBITS",
                        "virtual_address": 16616,
                        "physical_offset": 12520,
                        "size": 8,
                        "flags": "WA"
                    },
                    {
                        "name": ".bss",
                        "section_type": "NOBITS",
                        "virtual_address": 16624,
                        "physical_offset": 12528,
                        "size": 8,
                        "flags": "WA"
                    },
                    {
                        "name": ".comment",
                        "section_type": "PROGBITS",
                        "virtual_address": 0,
                        "physical_offset": 12528,
                        "size": 18,
                        "flags": "MS"
                    },
                    {
                        "name": ".debug_aranges",
                        "section_type": "PROGBITS",
                        "virtual_address": 0,
                        "physical_offset": 12560,
                        "size": 128,
                        "flags": ""
                    },
                    {
                        "name": ".debug_info",
                        "section_type": "PROGBITS",
                        "virtual_address": 0,
                        "physical_offset": 12688,
                        "size": 70,
                        "flags": ""
                    },
                    {
                        "name": ".debug_abbrev",
                        "section_type": "PROGBITS",
                        "virtual_address": 0,
                        "physical_offset": 12758,
                        "size": 36,
                        "flags": ""
                    },
                    {
                        "name": ".debug_line",
                        "section_type": "PROGBITS",
                        "virtual_address": 0,
                        "physical_offset": 12794,
                        "size": 201,
                        "flags": ""
                    },
                    {
                        "name": ".debug_str",
                        "section_type": "PROGBITS",
                        "virtual_address": 0,
                        "physical_offset": 12995,
                        "size": 89,
                        "flags": "MS"
                    },
                    {
                        "name": ".debug_line_str",
                        "section_type": "PROGBITS",
                        "virtual_address": 0,
                        "physical_offset": 13084,
                        "size": 59,
                        "flags": "MS"
                    },
                    {
                        "name": ".debug_rnglists",
                        "section_type": "PROGBITS",
                        "virtual_address": 0,
                        "physical_offset": 13143,
                        "size": 66,
                        "flags": ""
                    },
                    {
                        "name": ".symtab",
                        "section_type": "SYMTAB",
                        "virtual_address": 0,
                        "physical_offset": 13216,
                        "size": 1320,
                        "flags": ""
                    },
                    {
                        "name": ".strtab",
                        "section_type": "STRTAB",
                        "virtual_address": 0,
                        "physical_offset": 14536,
                        "size": 836,
                        "flags": ""
                    },
                    {
                        "name": ".shstrtab",
                        "section_type": "STRTAB",
                        "virtual_address": 0,
                        "physical_offset": 15372,
                        "size": 360,
                        "flags": ""
                    }
                ],
                "segment_list": [
                    {
                        "segment_type": "PHDR",
                        "resources": []
                    },
                    {
                        "segment_type": "INTERP",
                        "resources": [
                            ".interp"
                        ]
                    },
                    {
                        "segment_type": "LOAD",
                        "resources": [
                            ".note.gnu.property",
                            ".note.gnu.build-id",
                            ".gnu.hash",
                            ".dynsym",
                            ".dynstr",
                            ".gnu.version",
                            ".gnu.version_r",
                            ".rela.dyn",
                            ".rela.plt"
                        ]
                    },
                    {
                        "segment_type": "LOAD",
                        "resources": [
                            ".init",
                            ".plt",
                            ".text",
                            ".fini"
                        ]
                    },
                    {
                        "segment_type": "LOAD",
                        "resources": [
                            ".rodata",
                            ".interp",
                            ".eh_frame_hdr",
                            ".eh_frame"
                        ]
                    },
                    {
                        "segment_type": "LOAD",
                        "resources": [
                            ".init_array",
                            ".fini_array",
                            ".dynamic",
                            ".got",
                            ".got.plt",
                            ".data",
                            ".bss"
                        ]
                    },
                    {
                        "segment_type": "DYNAMIC",
                        "resources": [
                            ".dynamic"
                        ]
                    },
                    {
                        "segment_type": "NOTE",
                        "resources": [
                            ".note.gnu.property"
                        ]
                    },
                    {
                        "segment_type": "NOTE",
                        "resources": [
                            ".note.gnu.build-id"
                        ]
                    },
                    {
                        "segment_type": "GNU_PROPERTY",
                        "resources": [
                            ".note.gnu.property"
                        ]
                    },
                    {
                        "segment_type": "GNU_EH_FRAME",
                        "resources": [
                            ".eh_frame_hdr"
                        ]
                    },
                    {
                        "segment_type": "GNU_STACK",
                        "resources": []
                    },
                    {
                        "segment_type": "GNU_RELRO",
                        "resources": [
                            ".init_array",
                            ".fini_array",
                            ".dynamic",
                            ".got"
                        ]
                    }
                ]
            },
            "last_submission_date": 1748971959,
            "last_analysis_date": 1746564006,
            "magika": "ELF",
            "total_votes": {
                "harmless": 0,
                "malicious": 0
            },
            "popular_threat_classification": {
                "popular_threat_name": [
                    {
                        "value": "cve20214043",
                        "count": 2
                    },
                    {
                        "value": "expl",
                        "count": 2
                    },
                    {
                        "value": "fhbwb",
                        "count": 2
                    }
                ],
                "suggested_threat_label": "trojan.cve20214043/expl",
                "popular_threat_category": [
                    {
                        "value": "trojan",
                        "count": 11
                    }
                ]
            },
            "detectiteasy": {
                "filetype": "ELF64",
                "values": [
                    {
                        "info": "DYN AMD64-64",
                        "type": "Operation system",
                        "name": "Unix"
                    },
                    {
                        "info": "DYN AMD64-64",
                        "version": "2.3.3",
                        "type": "Library",
                        "name": "GLIBC"
                    },
                    {
                        "info": "DYN AMD64-64",
                        "version": "(GNU) 12.1.0",
                        "type": "Compiler",
                        "name": "gcc"
                    }
                ]
            },
            "vhash": "c661306a5175b500ae5da603f1cb9070",
            "first_submission_date": 1655993954,
            "type_extension": "so",
            "unique_sources": 161,
            "type_tags": [
                "executable",
                "linux",
                "elf"
            ],
            "type_tag": "elf",
            "magic": "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a049295e94010dfc313c5e5a6f282a68a047522b, with debug_info, not stripped",
            "sha1": "869e68253bb602144b3750c277eda1ed0b08534a",
            "crowdsourced_yara_results": [
                {
                    "ruleset_id": "015d29e092",
                    "rule_name": "Linux_Exploit_CVE_2021_4034_1c8f235d",
                    "ruleset_name": "Linux_Exploit_CVE_2021_4034",
                    "author": "Elastic Security",
                    "match_date": 1746564007,
                    "ruleset_version": "015d29e092|195c9611ddb90db599d7ffc1a9b0e8c45688007d",
                    "source": "https://github.com/elastic/protections-artifacts"
                },
                {
                    "ruleset_id": "0002a7a510",
                    "ruleset_name": "mal_perfctl_oct24",
                    "rule_name": "MAL_EXPL_Perfctl_Oct24",
                    "match_date": 1746564007,
                    "description": "Detects exploits used in relation with Perfctl malware campaigns",
                    "author": "Florian Roth",
                    "ruleset_version": "0002a7a510|1d926845269a3ac8de0431da133950390b5cced3",
                    "source": "https://github.com/Neo23x0/signature-base"
                }
            ],
            "trid": [
                {
                    "file_type": "ELF Executable and Linkable format (Linux)",
                    "probability": 50.1
                },
                {
                    "file_type": "ELF Executable and Linkable format (generic)",
                    "probability": 49.8
                }
            ],
            "reputation": 0,
            "filecondis": {
                "dhash": "f8f0b0b891000000",
                "raw_md5": "a5a4db3c068954538089ac99cf29515c"
            },
            "type_description": "ELF",
            "sha256": "44e83f84a5d5219e2f7c3cf1e4f02489cae81361227f46946abe4b8d8245b879",
            "meaningful_name": "PwnKit",
            "telfhash": "t122c022c1cd224e22b7d29181a477003a80038722e23909789e828091b4050832440268",
            "md5": "a63eb43c6c694570f4aca391b8111439",
            "size": 18040,
            "last_analysis_results": {
                "Bkav": {
                    "method": "blacklist",
                    "engine_name": "Bkav",
                    "engine_version": "2.0.0.1",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "Lionic": {
                    "method": "blacklist",
                    "engine_name": "Lionic",
                    "engine_version": "8.16",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Trojan.Linux.CVE-2021-4034.3!c"
                },
                "Elastic": {
                    "method": "blacklist",
                    "engine_name": "Elastic",
                    "engine_version": "4.0.203",
                    "engine_update": "20250505",
                    "category": "malicious",
                    "result": "Linux.Exploit.CVE.2021.4034"
                },
                "MicroWorld-eScan": {
                    "method": "blacklist",
                    "engine_name": "MicroWorld-eScan",
                    "engine_version": "14.0.409.0",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Trojan.Generic.37924306"
                },
                "CTX": {
                    "method": "blacklist",
                    "engine_name": "CTX",
                    "engine_version": "2024.8.29.1",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "elf.exploit-kit.generic"
                },
                "CAT-QuickHeal": {
                    "method": "blacklist",
                    "engine_name": "CAT-QuickHeal",
                    "engine_version": "22.00",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "Skyhigh": {
                    "method": "blacklist",
                    "engine_name": "Skyhigh",
                    "engine_version": "v2021.2.0+4045",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "GenericRXRQ-KJ!A63EB43C6C69"
                },
                "McAfee": {
                    "method": "blacklist",
                    "engine_name": "McAfee",
                    "engine_version": "6.0.6.653",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "GenericRXRQ-KJ!A63EB43C6C69"
                },
                "Malwarebytes": {
                    "method": "blacklist",
                    "engine_name": "Malwarebytes",
                    "engine_version": "4.5.5.54",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "Zillya": {
                    "method": "blacklist",
                    "engine_name": "Zillya",
                    "engine_version": "2.0.0.5354",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "Sangfor": {
                    "method": "blacklist",
                    "engine_name": "Sangfor",
                    "engine_version": "2.22.3.0",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Suspicious.Linux.Save.a"
                },
                "K7AntiVirus": {
                    "method": "blacklist",
                    "engine_name": "K7AntiVirus",
                    "engine_version": "12.234.55669",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "Varist": {
                    "method": "blacklist",
                    "engine_name": "Varist",
                    "engine_version": "6.6.1.3",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "E64/DCCVE214034"
                },
                "K7GW": {
                    "method": "blacklist",
                    "engine_name": "K7GW",
                    "engine_version": "12.234.55669",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "CrowdStrike": {
                    "method": "blacklist",
                    "engine_name": "CrowdStrike",
                    "engine_version": "1.0",
                    "engine_update": "20230417",
                    "category": "undetected",
                    "result": "null"
                },
                "Baidu": {
                    "method": "blacklist",
                    "engine_name": "Baidu",
                    "engine_version": "1.0.0.2",
                    "engine_update": "20190318",
                    "category": "undetected",
                    "result": "null"
                },
                "VirIT": {
                    "method": "blacklist",
                    "engine_name": "VirIT",
                    "engine_version": "9.5.948",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "Symantec": {
                    "method": "blacklist",
                    "engine_name": "Symantec",
                    "engine_version": "1.22.0.0",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Trojan Horse"
                },
                "ESET-NOD32": {
                    "method": "blacklist",
                    "engine_name": "ESET-NOD32",
                    "engine_version": "31155",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "a variant of Linux/Exploit.CVE-2021-4034.G"
                },
                "TrendMicro-HouseCall": {
                    "method": "blacklist",
                    "engine_name": "TrendMicro-HouseCall",
                    "engine_version": "24.550.0.1002",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Trojan.Linux.CVE20214043.A"
                },
                "Avast": {
                    "method": "blacklist",
                    "engine_name": "Avast",
                    "engine_version": "23.9.8494.0",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "ELF:Agent-DBG [Expl]"
                },
                "ClamAV": {
                    "method": "blacklist",
                    "engine_name": "ClamAV",
                    "engine_version": "1.4.2.0",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Unix.Exploit.Pkexecexploit-10034078-0"
                },
                "Kaspersky": {
                    "method": "blacklist",
                    "engine_name": "Kaspersky",
                    "engine_version": "22.0.1.28",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "HEUR:Exploit.Linux.CVE-2021-4034.f"
                },
                "BitDefender": {
                    "method": "blacklist",
                    "engine_name": "BitDefender",
                    "engine_version": "7.2",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Trojan.Generic.37924306"
                },
                "NANO-Antivirus": {
                    "method": "blacklist",
                    "engine_name": "NANO-Antivirus",
                    "engine_version": "1.0.170.26531",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Exploit.Elf64.CVE20214034.jtpxvc"
                },
                "SUPERAntiSpyware": {
                    "method": "blacklist",
                    "engine_name": "SUPERAntiSpyware",
                    "engine_version": "5.6.0.1032",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "Tencent": {
                    "method": "blacklist",
                    "engine_name": "Tencent",
                    "engine_version": "1.0.0.1",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Exp.Elf.CVE-2021-4043.a"
                },
                "Emsisoft": {
                    "method": "blacklist",
                    "engine_name": "Emsisoft",
                    "engine_version": "2024.8.0.61147",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Trojan.Generic.37924306 (B)"
                },
                "F-Secure": {
                    "method": "blacklist",
                    "engine_name": "F-Secure",
                    "engine_version": "18.10.1547.307",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Exploit.EXP/CVE-2017-7308.fhbwb"
                },
                "DrWeb": {
                    "method": "blacklist",
                    "engine_name": "DrWeb",
                    "engine_version": "7.0.67.2170",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Linux.Exploit.324"
                },
                "VIPRE": {
                    "method": "blacklist",
                    "engine_name": "VIPRE",
                    "engine_version": "6.0.0.35",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Trojan.Generic.37924306"
                },
                "TrendMicro": {
                    "method": "blacklist",
                    "engine_name": "TrendMicro",
                    "engine_version": "24.550.0.1002",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Trojan.Linux.CVE20214043.A"
                },
                "SentinelOne": {
                    "method": "blacklist",
                    "engine_name": "SentinelOne",
                    "engine_version": "25.1.1.1",
                    "engine_update": "20250114",
                    "category": "malicious",
                    "result": "Static AI - Suspicious ELF"
                },
                "CMC": {
                    "method": "blacklist",
                    "engine_name": "CMC",
                    "engine_version": "2.4.2022.1",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "Sophos": {
                    "method": "blacklist",
                    "engine_name": "Sophos",
                    "engine_version": "3.0.3.0",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Exp/20214034-B"
                },
                "Ikarus": {
                    "method": "blacklist",
                    "engine_name": "Ikarus",
                    "engine_version": "6.3.30.0",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Exploit.CVE-2021-4034"
                },
                "Avast-Mobile": {
                    "method": "blacklist",
                    "engine_name": "Avast-Mobile",
                    "engine_version": "250506-00",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "Jiangmin": {
                    "method": "blacklist",
                    "engine_name": "Jiangmin",
                    "engine_version": "16.0.100",
                    "engine_update": "20250505",
                    "category": "malicious",
                    "result": "Exploit.Linux.eax"
                },
                "Google": {
                    "method": "blacklist",
                    "engine_name": "Google",
                    "engine_version": "1746556237",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Detected"
                },
                "Avira": {
                    "method": "blacklist",
                    "engine_name": "Avira",
                    "engine_version": "8.3.3.20",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "EXP/CVE-2017-7308.fhbwb"
                },
                "Antiy-AVL": {
                    "method": "blacklist",
                    "engine_name": "Antiy-AVL",
                    "engine_version": "3.0",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Trojan[Exploit]/Linux.CVE-2021-4034.g"
                },
                "Kingsoft": {
                    "method": "blacklist",
                    "engine_name": "Kingsoft",
                    "engine_version": "None",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Linux.Exploit.CVE-2021-403.f"
                },
                "Microsoft": {
                    "method": "blacklist",
                    "engine_name": "Microsoft",
                    "engine_version": "1.1.25030.1",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Exploit:Linux/CVE-2021-4034"
                },
                "Gridinsoft": {
                    "method": "blacklist",
                    "engine_name": "Gridinsoft",
                    "engine_version": "1.0.216.174",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "Xcitium": {
                    "method": "blacklist",
                    "engine_name": "Xcitium",
                    "engine_version": "37707",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Malware@#604bwe7sfhoa"
                },
                "Arcabit": {
                    "method": "blacklist",
                    "engine_name": "Arcabit",
                    "engine_version": "2022.0.0.18",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Trojan.Generic.D242ADD2"
                },
                "ViRobot": {
                    "method": "blacklist",
                    "engine_name": "ViRobot",
                    "engine_version": "2014.3.20.0",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "ELF.S.Agent.18040"
                },
                "ZoneAlarm": {
                    "method": "blacklist",
                    "engine_name": "ZoneAlarm",
                    "engine_version": "6.15-102623205",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Exp/20214034-B"
                },
                "GData": {
                    "method": "blacklist",
                    "engine_name": "GData",
                    "engine_version": "GD:27.40230AVA:64.29149",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Trojan.Generic.37924306"
                },
                "Cynet": {
                    "method": "blacklist",
                    "engine_name": "Cynet",
                    "engine_version": "4.0.3.4",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Malicious (score: 99)"
                },
                "AhnLab-V3": {
                    "method": "blacklist",
                    "engine_name": "AhnLab-V3",
                    "engine_version": "3.27.2.10550",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Exploit/Linux.Agent"
                },
                "Acronis": {
                    "method": "blacklist",
                    "engine_name": "Acronis",
                    "engine_version": "1.2.0.121",
                    "engine_update": "20240328",
                    "category": "undetected",
                    "result": "null"
                },
                "VBA32": {
                    "method": "blacklist",
                    "engine_name": "VBA32",
                    "engine_version": "5.3.2",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "ALYac": {
                    "method": "blacklist",
                    "engine_name": "ALYac",
                    "engine_version": "2.0.0.10",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Exploit.Linux.CVE-2021-4034"
                },
                "TACHYON": {
                    "method": "blacklist",
                    "engine_name": "TACHYON",
                    "engine_version": "2025-05-06.02",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "Zoner": {
                    "method": "blacklist",
                    "engine_name": "Zoner",
                    "engine_version": "2.2.2.0",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "Rising": {
                    "method": "blacklist",
                    "engine_name": "Rising",
                    "engine_version": "25.0.0.28",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Exploit.CVE-2021-4034!8.131F2 (TFE:19:dyM04kUoiaC)"
                },
                "Yandex": {
                    "method": "blacklist",
                    "engine_name": "Yandex",
                    "engine_version": "5.5.2.24",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "huorong": {
                    "method": "blacklist",
                    "engine_name": "huorong",
                    "engine_version": "b8bcb5c:b8bcb5c:0248311:0248311",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "Exploit/Linux.CVE-2021-4034.b"
                },
                "MaxSecure": {
                    "method": "blacklist",
                    "engine_name": "MaxSecure",
                    "engine_version": "1.0.0.1",
                    "engine_update": "20250505",
                    "category": "undetected",
                    "result": "null"
                },
                "Fortinet": {
                    "method": "blacklist",
                    "engine_name": "Fortinet",
                    "engine_version": "7.0.30.0",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "AVG": {
                    "method": "blacklist",
                    "engine_name": "AVG",
                    "engine_version": "23.9.8494.0",
                    "engine_update": "20250506",
                    "category": "malicious",
                    "result": "ELF:Agent-DBG [Expl]"
                },
                "Panda": {
                    "method": "blacklist",
                    "engine_name": "Panda",
                    "engine_version": "4.6.4.2",
                    "engine_update": "20250506",
                    "category": "undetected",
                    "result": "null"
                },
                "alibabacloud": {
                    "method": "blacklist",
                    "engine_name": "alibabacloud",
                    "engine_version": "2.2.0",
                    "engine_update": "20250321",
                    "category": "malicious",
                    "result": "Exp:Linux/CVE.2021.4034"
                },
                "SymantecMobileInsight": {
                    "method": "blacklist",
                    "engine_name": "SymantecMobileInsight",
                    "engine_version": "2.0",
                    "engine_update": "20250124",
                    "category": "type-unsupported",
                    "result": "null"
                },
                "BitDefenderFalx": {
                    "method": "blacklist",
                    "engine_name": "BitDefenderFalx",
                    "engine_version": "2.0.936",
                    "engine_update": "20250416",
                    "category": "type-unsupported",
                    "result": "null"
                },
                "McAfeeD": {
                    "method": "blacklist",
                    "engine_name": "McAfeeD",
                    "engine_version": "1.2.0.7977",
                    "engine_update": "20250506",
                    "category": "type-unsupported",
                    "result": "null"
                },
                "DeepInstinct": {
                    "method": "blacklist",
                    "engine_name": "DeepInstinct",
                    "engine_version": "5.0.0.8",
                    "engine_update": "20250506",
                    "category": "type-unsupported",
                    "result": "null"
                },
                "APEX": {
                    "method": "blacklist",
                    "engine_name": "APEX",
                    "engine_version": "6.651",
                    "engine_update": "20250504",
                    "category": "type-unsupported",
                    "result": "null"
                },
                "Paloalto": {
                    "method": "blacklist",
                    "engine_name": "Paloalto",
                    "engine_version": "0.9.0.1003",
                    "engine_update": "20250506",
                    "category": "type-unsupported",
                    "result": "null"
                },
                "Trapmine": {
                    "method": "blacklist",
                    "engine_name": "Trapmine",
                    "engine_version": "4.0.4.0",
                    "engine_update": "20250417",
                    "category": "type-unsupported",
                    "result": "null"
                },
                "Alibaba": {
                    "method": "blacklist",
                    "engine_name": "Alibaba",
                    "engine_version": "0.3.0.5",
                    "engine_update": "20190527",
                    "category": "type-unsupported",
                    "result": "null"
                },
                "Webroot": {
                    "method": "blacklist",
                    "engine_name": "Webroot",
                    "engine_version": "1.9.0.8",
                    "engine_update": "20250227",
                    "category": "type-unsupported",
                    "result": "null"
                },
                "Cylance": {
                    "method": "blacklist",
                    "engine_name": "Cylance",
                    "engine_version": "3.0.0.0",
                    "engine_update": "20250424",
                    "category": "type-unsupported",
                    "result": "null"
                },
                "tehtris": {
                    "method": "blacklist",
                    "engine_name": "tehtris",
                    "engine_version": "null",
                    "engine_update": "20250506",
                    "category": "type-unsupported",
                    "result": "null"
                },
                "Trustlook": {
                    "method": "blacklist",
                    "engine_name": "Trustlook",
                    "engine_version": "1.0",
                    "engine_update": "20250506",
                    "category": "type-unsupported",
                    "result": "null"
                }
            },
            "times_submitted": 240,
            "first_seen_itw_date": 1656059960
        }
    }
}
