#ifndef __PRX_LDR_H__
#define __PRX_LDR_H__

typedef unsigned int   u32;
typedef unsigned short u16;
typedef unsigned char  u8;
typedef int   s32;
typedef short s16;
typedef char  s8;

#define PSP_MODULE_INFO_NAME ".rodata.sceModuleInfo"
#define PSP_MODULE_MAX_NAME 28

#define ET_PRX  				0xffa0		/* PSP PRX header type*/
#define PT_PRXRELOC             	0x700000A0
#define PT_PRXRELOC2            	0x700000A1

#define E_MIPS_MACH_ALLEGREX	0x00A20000
#define EF_MIPS_MACH			0x00FF0000
#define EBOOT_BASE_ADDR 		(0x08800000 + 0x4000)
#define ELF_SECT_MAX_NAME 		128
#define PSP_ENTRY_MAX_NAME 	128
#define PSP_LIB_MAX_NAME 		128
/* Define the maximum number of permitted entries per lib */
#define PSP_MAX_V_ENTRIES 		255
#define PSP_MAX_F_ENTRIES 		65535
#ifndef PATH_MAX
#define PATH_MAX 256
#endif

/* Define a name for the unnamed first export */
#define PSP_SYSTEM_EXPORT "syslib"

/* Base size of an import structure */
#define PSP_IMPORT_BASE_SIZE (5*4)

// MIPS Reloc Entry Types
#define R_MIPS_NONE    	0
#define R_MIPS_16       	1
#define R_MIPS_32       	2
#define R_MIPS_26       	4
#define R_MIPS_HI16     	5
#define R_MIPS_LO16     	6

/* Unsupported for PRXes (loadcore.prx ignores them) */
#define R_MIPS_REL32    	3
#define R_MIPS_GPREL16  7
#define R_MIPS_LITERAL  	8
#define R_MIPS_GOT16    	9
#define R_MIPS_PC16     	10
#define R_MIPS_CALL16   	11
#define R_MIPS_GPREL32  12

/* For the new relocation type */
#define R_MIPS_X_HI16   	13
#define R_MIPS_X_J26    	14
#define R_MIPS_X_JAL26  	15

/* ELF Header */
#define EI_NIDENT 		16            // sizeof
#define ELF_MAGIC 		0x464c457f
#define EI_CLASS    		4
#define   ELFCLASS32    	1   // 32bit object
#define EI_DATA     		5
#define   ELFDATA2LSB    	1   // low byte first
#define EM_MIPS			8 // Mips 3000 (officialy, big-endian only)

#define SHT_PRXRELOC 	(SHT_LOPROC | 0xA0)
#define ELF32_R_SYM(i)    	((i)>>8)
#define ELF32_R_TYPE(i)   ((unsigned char)(i))
#define ELF32_R_INFO(s,t) (((s)<<8)+(unsigned char)(t))

#define PF_X				1
#define PT_LOAD			1

enum elf_SHF
{
  SHF_WRITE     = (1 << 0),     // writable data
  SHF_ALLOC     = (1 << 1),     // occupies memory
  SHF_EXECINSTR = (1 << 2),     // machine instruction

  SHF_MERGE     = (1 << 4),     // can be merged
  SHF_STRINGS   = (1 << 5),     // contains nul-terminated strings
  SHF_INFO_LINK = (1 << 6),     // sh_info contains SHT index
  SHF_LINK_ORDER= (1 << 7),     // preserve order after combining
  SHF_OS_NONCONFORMING = (1 << 8), // non-standard os specific handling required
  SHF_GROUP     = (1 << 9),     // section is memory of a group
  SHF_TLS       = (1 << 10),    // section holds thread-local data

  SHF_MASKOS    = 0x0ff00000,   // os specific
  SHF_MASKPROC  = 0xf0000000,   // processor specific
};

enum elf_SHT {
  SHT_NULL      = 0,    // inactive - no assoc. section
  SHT_PROGBITS  = 1,    // internal program information
  SHT_SYMTAB    = 2,    // symbol table (static)
  SHT_STRTAB    = 3,    // string table
  SHT_RELA      = 4,    // relocation entries
  SHT_HASH      = 5,    // symbol hash table
  SHT_DYNAMIC   = 6,    // inf. for dynamic linking
  SHT_NOTE      = 7,    // additional info
  SHT_NOBITS    = 8,    // no placed in file
  SHT_REL       = 9,    // relocation entries without explicit address
  SHT_SHLIB     = 10,   // RESERVED
  SHT_DYNSYM    = 11,   // Dynamic Symbol Table
  // abi 3
  SHT_INIT_ARRAY    = 14, // Array of ptrs to init functions
  SHT_FINI_ARRAY    = 15, // Array of ptrs to finish functions
  SHT_PREINIT_ARRAY = 16, // Array of ptrs to pre-init funcs
  SHT_GROUP         = 17, // Section contains a section group
  SHT_SYMTAB_SHNDX  = 18, // Indicies for SHN_XINDEX entries
  //  SHT_NUM       = 12,
#ifndef __DOS16__
  SHT_LOOS      = 0x60000000ul,
  SHT_HIOS      = 0x6ffffffful,
  SHT_LOPROC    = 0x70000000ul,
  SHT_HIPROC    = 0x7ffffffful,
  SHT_LOUSER    = 0x80000000ul,
  SHT_HIUSER    = 0xfffffffful,
  //
  // The remaining values are not in the standard.
  // Incremental build data.
  SHT_GNU_INCREMENTAL_INPUTS = 0x6fff4700,
  // Object attributes.
  SHT_GNU_ATTRIBUTES = 0x6ffffff5,
  // GNU style dynamic hash table.
  SHT_GNU_HASH = 0x6ffffff6,
  // List of prelink dependencies.
  SHT_GNU_LIBLIST = 0x6ffffff7,

  // The next three section types are defined by Solaris, and are named SHT_SUNW*.  We use them in GNU code, so we also define SHT_GNU*
  SHT_SUNW_verdef   = 0x6ffffffd, // Versions defined by file
  SHT_SUNW_verneed  = 0x6ffffffe, // Versions needed by file
  SHT_SUNW_versym   = 0x6fffffff  // Symbol versions
#endif
};

enum PspEntryType
{
	PSP_ENTRY_FUNC = 0,
	PSP_ENTRY_VAR = 1
};

#pragma pack(push, 4)
struct Elf32_Ehdr
{
  u8   e_ident[EI_NIDENT];   // see above
  u16  e_type;               // enum ET
  u16  e_machine;            // enum EM
  u32  e_version;            // enum EV
  u32  e_entry;              // virtual start address
  u32  e_phoff;              // off to program header table's (pht)
  u32  e_shoff;              // off to section header table's (sht)
  u32  e_flags;              // EF_machine_flag
  u16  e_ehsize;             // header's size
  u16  e_phentsize;          // size of pht element
  u16  e_phnum;              // entry counter in pht
  u16  e_shentsize;          // size of sht element
  u16  e_shnum;              // entry count in sht
  u16  e_shstrndx;           // sht index in name table
};

typedef struct
{
  u32    sh_name;      // index in string table
  u32    sh_type;      // enum SHT
  u32    sh_flags;     // enum SHF
  u32    sh_addr;      // address in memmory (or 0)
  u32    sh_offset;    // offset in file
  u32    sh_size;      // section size in bytes
  u32    sh_link;      // index in symbol table
  u32    sh_info;      // extra information
  u32    sh_addralign; // 0 & 1 => no alignment
  u32    sh_entsize;   // size symbol table or eq.
} Elf32_Shdr;

typedef struct
{
  u32    p_type;         //Segment type. see below
  u32    p_offset;       //from beginning of file at 1 byte of segment resides
  u32    p_vaddr;        //virtual addr of 1 byte
  u32    p_paddr;        //reserved for system
  u32    p_filesz;       //may be 0
  u32    p_memsz;        //my be 0
  u32    p_flags;        // for PT_LOAD access mask (PF_
#define PF_R 4
#define PF_W 2
#define PF_X 1
  u32    p_align;        //0/1-no,
}Elf32_Phdr;

typedef struct
{
  u32    r_offset;       //virtual address
  u32    r_info;         //type of relocation
}Elf32_Rel;

struct ElfReloc
{
	/* Pointer to the section name */
	const char* secname;
	/* Base address */
	u32 base;
	/* Type */
	u32 type;
	/* Symbol (if known) */
	u32 symbol;
	/* Offset into the file */
	u32 offset;
	/* New Address for the relocation (to do with what you will) */
	u32 info;
	u32 addr;
};

/* Structure to hold the module info */
struct PspModuleInfo
{
	u32 flags;
	char name[PSP_MODULE_MAX_NAME];
	u32 gp;
	u32 exports;
	u32 exp_end;
	u32 imports;
	u32 imp_end;
};

/* Structure to hold the module export information */
struct PspModuleExport
{
	u32 name;
	u32 flags;
	u32 counts;
	u32 exports;
};

/* Define the loaded prx types */
struct PspEntry
{
	/* Name of the entry */
	char name[PSP_ENTRY_MAX_NAME];
	/* Nid of the entry */
	u32 nid;
	/* Type of the entry */
	PspEntryType type;
	/* Virtual address of the entry in the loaded elf */
	u32 addr;
	/* Virtual address of the nid dword */
	u32 nid_addr;
};

/* Holds a linking entry for an export library */
struct PspLibExport
{
	/** Previous export in the chain */
	PspLibExport *prev;
	/** Next export in the chain */
	PspLibExport *next;
	/** Name of the library */
	char name[PSP_LIB_MAX_NAME];
	/** Virtual address of the lib import stub */
	u32 addr;
	/** Copy of the import stub (in native byte order) */
	PspModuleExport stub;
	/** List of function entries */
	PspEntry funcs[PSP_MAX_F_ENTRIES];
	/** Number of function entries */
	int f_count;
	/** List of variable entried */
	PspEntry vars[PSP_MAX_V_ENTRIES];
	/** Number of variable entires */
	int v_count;
};

/* Structure to hold the module import information */
struct PspModuleImport
{
	u32 name;
	u32 flags;
	u32 counts;
	u32 nids;
	u32 funcs;
	u32 vars;
};

/* Holds a linking entry for an import library */
struct PspLibImport
{
	/** Previous import */
	PspLibImport *prev;
	/** Next import */
	PspLibImport *next;
	/** Name of the library */
	char name[PSP_LIB_MAX_NAME];
	/** Virtual address of the lib import stub */
	u32 addr;
	/** Copy of the import stub (in native byte order) */
	PspModuleImport stub;
	/** List of function entries */
	PspEntry funcs[PSP_MAX_F_ENTRIES];
	/** Number of function entries */
	int f_count;
	/** List of variable entried */
	PspEntry vars[PSP_MAX_V_ENTRIES];
	/** Number of variable entries */
	int v_count;
	/** File containing the export */
	char file[PATH_MAX];
};

struct NidEntry
{
	u32 nid;
	char name[64];
};

struct LibNidEntry
{
	NidEntry *pNid;
	char name[64];
	u32 cnt;
};

struct SyslibEntry
{
	unsigned int nid;
	const char *name;
};

struct Prx_info
{
	int prx_size;

	Elf32_Ehdr *ehdr32;
	Elf32_Shdr *shdr32;
	Elf32_Phdr *phdr32;

	char **secname;

	int relocs_cnt;
	ElfReloc *elfreloc;

	PspModuleInfo *pModInfo;
	PspLibExport *plibexp;
	PspLibImport *plibimp;
	LibNidEntry *plibnid;
	int lib_cnt;
};

#pragma pack(pop)
#endif /* __PRX_LDR_H__ */

