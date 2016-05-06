/*
 *       LOADER for PSP Prx files
 *       Tested on IDA Pro 6.1
 */

//#define  _CRT_SECURE_NO_WARNINGS

#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS

#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#include "../idaldr.h"
#include "prxldr.h"
#include "sceLibNids.c"

//----------------------------------------------------------------------
ea_t base_addr = EBOOT_BASE_ADDR;


//----------------------------------------------------------------------
int find_section(Prx_info *prx, const char *name)
{
	int i, ret=-1;

	if(NULL == name)
		return ret;
	
	for(i=0; i<prx->ehdr32->e_shnum; i++){
		if(strcmp(prx->secname[i], name) == 0){
			ret = i;
			break;
		}		
	}

	return ret;
}

static bool is_prx(linput_t *li)
{
	Elf32_Ehdr ehdr32;

	qlseek(li, 0);
	qlread(li, &ehdr32, sizeof(ehdr32));

	// check ELF magic
	if(ELF_MAGIC != *(u32*)ehdr32.e_ident)
		return false;

	// check MIPSL 32bit
	if((ELFDATA2LSB != ehdr32.e_ident[EI_DATA]) || (ELFCLASS32 != ehdr32.e_ident[EI_CLASS]) || (EM_MIPS != ehdr32.e_machine))
		return false;

	// check PSP PRX
	if(ET_PRX == ehdr32.e_type)
		return true;

	// check ALLEGREX
	if(E_MIPS_MACH_ALLEGREX == (ehdr32.e_flags&EF_MIPS_MACH))
		return true;

	return false;
}

int load_section_headers(u8 *buf, Prx_info *prx)
{
	int i, sht_size;
	Elf32_Shdr *sh;
	Elf32_Shdr *shstrtab = NULL;
	Elf32_Ehdr *ehdr = prx->ehdr32;
	u8 *start = buf;

	sht_size = ehdr->e_shnum*ehdr->e_shentsize;
	if((int)(ehdr->e_shoff+sht_size)>prx->prx_size){
		msg("Invalid section table! ignore it.\n");
		ehdr->e_shnum = 0;
		ehdr->e_shoff = 0;
		ehdr->e_shstrndx = 0;
		return -1;
	}

	prx->shdr32 = (Elf32_Shdr *)qalloc(ehdr->e_shnum*sizeof(Elf32_Shdr));
	if (NULL == prx->shdr32)
		return -1;

	start += ehdr->e_shoff;
	for(i=0, sh=prx->shdr32; i<ehdr->e_shnum; i++,sh++){
		*sh = *(Elf32_Shdr *)start;
		start += sizeof(Elf32_Shdr);
	}

	if((ehdr->e_shstrndx >0) && (ehdr->e_shstrndx < ehdr->e_shnum)){
		shstrtab = &prx->shdr32[ehdr->e_shstrndx];
		prx->secname = (char **)qalloc(ehdr->e_shnum*4);
		for(i=0, sh=prx->shdr32; i<ehdr->e_shnum; i++,sh++){
			prx->secname[i] = (char *)(buf+shstrtab->sh_offset+prx->shdr32[i].sh_name);
		}
	}

	return i;
}

int load_program_headers(u8 *buf, Prx_info *prx)
{
	int i;
	Elf32_Phdr *ph;

	prx->phdr32 = (Elf32_Phdr *)qalloc(prx->ehdr32->e_phnum * sizeof(Elf32_Phdr));
	if ( NULL == prx->phdr32 )
		return -1;

	buf += prx->ehdr32->e_phoff;
	for(i=0, ph=prx->phdr32; i<prx->ehdr32->e_phnum; i++,ph++){
		*ph = *(Elf32_Phdr *)buf;
		buf += sizeof(Elf32_Phdr);
	}

	return i;
}

int load_symbols(u8 *buf, Elf32_Ehdr *ehdr32)
{
	return 0;
}

static void create32(sel_t sel, ea_t startEA, ea_t endEA, const char *name, const char *classname)
{
	if(!add_segm(sel, startEA, endEA, name, classname))
		loader_failure();
}

int load_sections(u8 *buf, Prx_info *prx)
{
	int i;
	Elf32_Shdr *sh = prx->shdr32;
	segment_t *s;

 	for(i = 1, sh++; i < prx->ehdr32->e_shnum; i++, sh++){
		if(sh->sh_type != SHT_PROGBITS) 
			continue;
		if ( sh->sh_size == 0 ) 
			continue;

		if(sh->sh_flags & SHF_ALLOC){
			mem2base(buf+sh->sh_offset, sh->sh_addr+base_addr, sh->sh_addr+sh->sh_size+base_addr, -1);
			if(sh->sh_flags & SHF_EXECINSTR)
				create32(0, sh->sh_addr+base_addr, sh->sh_addr+sh->sh_size+base_addr, prx->secname[i], CLASS_CODE);
			else
				create32(0, sh->sh_addr+base_addr, sh->sh_addr+sh->sh_size+base_addr, prx->secname[i], CLASS_DATA);
			s = getseg(sh->sh_addr+base_addr);
			set_segm_addressing(s, 1);
		}
	}

	return i;
}

int load_programs(u8 *buf, Prx_info *prx)
{
	int i;
	Elf32_Phdr *ph = prx->phdr32;
	segment_t *s;

 	for(i=0; i<prx->ehdr32->e_phnum; i++, ph++){
		if(ph->p_type != PT_LOAD) 
			continue;
		if(ph->p_filesz == 0) 
			continue;

		mem2base(buf+ph->p_offset, ph->p_vaddr+base_addr, ph->p_vaddr+ph->p_filesz+base_addr, -1);
		if(ph->p_flags & PF_X)
			create32(0, ph->p_vaddr+base_addr, ph->p_vaddr+ph->p_filesz+base_addr, ".text", CLASS_CODE);
		else
			create32(0, ph->p_vaddr+base_addr, ph->p_vaddr+ph->p_filesz+base_addr, ".data", CLASS_DATA);
		s = getseg(ph->p_vaddr+base_addr);
		set_segm_addressing(s, 1);
	}

	return i;
}

int create_bss(Prx_info *prx)
{
	Elf32_Phdr *ph;
	u32 bss_size, bss_addr;
	int i;

	bss_size = 0;
	bss_addr = 0;

	// get bss info from programs header
	ph = prx->phdr32;

	for(i=0; i<prx->ehdr32->e_phnum; i++){
		if(ph[i].p_type==PT_LOAD){
			// bss_size are caculated from last ph.
			bss_size = ph[i].p_memsz-ph[i].p_filesz;
			bss_addr = ph[i].p_vaddr+ph[i].p_filesz;
		}
	}

	create32(0, bss_addr+base_addr, bss_addr+base_addr+bss_size, ".bss", CLASS_BSS);

	return 0;
}

int count_relocs(u8 *buf, Prx_info *prx)
{
	int  relocs_cnt = 0, i, typea_from_section = 0;
	Elf32_Shdr *sh = prx->shdr32;
	Elf32_Phdr *ph = prx->phdr32;
	
 	for(i = 1, sh++; i < prx->ehdr32->e_shnum; i++, sh++){
		if((sh->sh_type == SHT_PRXRELOC) || (sh->sh_type == SHT_REL)){
			if(sh->sh_size % sizeof(Elf32_Rel)){
				msg("[ERRO] Relocation section size invalid\n");
			}
			relocs_cnt += sh->sh_size/sizeof(Elf32_Rel);
			if(relocs_cnt)
				typea_from_section = 1;
		}
	}
	msg("Relocation entries in sections cnt [%d]\n", relocs_cnt);
	
	for(i = 1, ph++; i < prx->ehdr32->e_phnum; i++, ph++){
		if(ph->p_type == PT_PRXRELOC) {
			if(typea_from_section)
				continue;
			if(ph->p_filesz % sizeof(Elf32_Rel)){
				msg("[ERRO] Relocation section size invalid\n");
			}
			relocs_cnt += ph->p_filesz/sizeof(Elf32_Rel);
		}else if(ph->p_type == PT_PRXRELOC2) {
			u8 *block1, block1s, part1s;
			u8 *block2, block2s, part2s;
			u8 *pos, *end;
			
			if (*(u16*)(ph->p_offset+buf) != 0) {
				msg("[ERRO] PT_PRXRELOC2 programs should start with 0x00 0x00\n");
				return -1;
			}
			
			part1s = *(u8*)(ph->p_offset+buf+2);
			part2s = *(u8*)(ph->p_offset+buf+3);
			block1s = *(u8*)(ph->p_offset+buf+4);
			block1 = ph->p_offset+buf+4;
			block2 = block1 + block1s;
			block2s = block2[0];
			pos = block2 + block2s;
			end = ph->p_offset + ph->p_filesz + buf;
			while (pos < end) {
				u32 cmd, part1, temp;
				cmd = pos[0] | (pos[1] << 16);
				pos += 2;
				temp = (cmd << (16 - part1s)) & 0xFFFF;
				temp = (temp >> (16 - part1s)) & 0xFFFF;
				if (temp >= block1s) {
					msg("[ERRO] Invalid cmd1 index\n");
					return -1;
				}
				part1 = block1[temp];
				pos += (part1 & 0x06);
				if ((part1 & 0x01) != 0) {
					if (part1 & 0x38 == 0x10) {
						pos += 2;
					} else if (part1 & 0x38 == 0x18) {
						pos += 4;
					}
				}
				relocs_cnt++;
			}
		}
	}
	msg("Relocation entries in programs cnt [%d]\n", relocs_cnt);

	return relocs_cnt;
}

int load_relocs(u8 *buf, Prx_info *prx)
{
	int i, j, count, typea_from_section = 0;
	Elf32_Rel *reloc;
	int  iCurrRel = 0;


	u8 *block1, *block2, *pos, *end;
	u32 block1s, block2s, part1s, part2s;
	u32 cmd, part1, part2, lastpart2;
	u32 addend = 0, offset = 0;
	u32 ofsbase = 0xFFFFFFFF, addrbase;
	u32 temp1, temp2;
	u32 nbits;
	u32 iLoop;
	Elf32_Phdr *ph;
	
	/* Load from sections */
	for(i = 0; i < prx->ehdr32->e_shnum; i++){
		if((prx->shdr32[i].sh_type == SHT_PRXRELOC) || (prx->shdr32[i].sh_type == SHT_REL)){
			count = prx->shdr32[i].sh_size / sizeof(Elf32_Rel);
			if(count)
				typea_from_section = 1;
			reloc = (Elf32_Rel *) (buf+prx->shdr32[i].sh_offset);
			for(j = 0; j < count; j++) {    
				prx->elfreloc[iCurrRel].secname = prx->secname[i];
				prx->elfreloc[iCurrRel].base = 0;
				prx->elfreloc[iCurrRel].type = ELF32_R_TYPE(reloc->r_info);
				prx->elfreloc[iCurrRel].symbol = ELF32_R_SYM(reloc->r_info);
				prx->elfreloc[iCurrRel].info = reloc->r_info;
				prx->elfreloc[iCurrRel].offset = reloc->r_offset;
				reloc++;
				iCurrRel++;
			}
		}
	}
	
	/* Load from programs */	
	for(iLoop = 0; iLoop < prx->ehdr32->e_phnum; iLoop++){
		ph = &prx->phdr32[iLoop];
		if(ph->p_type == PT_PRXRELOC) {
			if(typea_from_section)
				continue;
			count = ph->p_filesz / sizeof(Elf32_Rel);
			reloc = (Elf32_Rel *) (buf+ph->p_offset);
			for(j = 0; j < count; j++) {
				prx->elfreloc[iCurrRel].secname = NULL;
				prx->elfreloc[iCurrRel].base = 0;
				prx->elfreloc[iCurrRel].type = ELF32_R_TYPE(reloc->r_info);
				prx->elfreloc[iCurrRel].symbol = ELF32_R_SYM(reloc->r_info);
				prx->elfreloc[iCurrRel].info = reloc->r_info;
				prx->elfreloc[iCurrRel].offset = reloc->r_offset;
				reloc++;
				iCurrRel++;
			}
		}else if(ph->p_type == PT_PRXRELOC2){
			part1s = *(u8*)(ph->p_offset+buf+2);//m_pElfPrograms[iLoop].pData[2];
			part2s = *(u8*)(ph->p_offset+buf+3);//m_pElfPrograms[iLoop].pData[3];
			block1s = *(u8*)(ph->p_offset+buf+4);//m_pElfPrograms[iLoop].pData[4];
			block1 = ph->p_offset+buf+4;//&m_pElfPrograms[iLoop].pData[4];
			block2 = block1 + block1s;
			block2s = block2[0];
			pos = block2 + block2s;
			end = ph->p_offset+ph->p_filesz+buf;//&m_pElfPrograms[iLoop].pData[m_pElfPrograms[iLoop].iFilesz];
			
			for (nbits = 1; (1 << nbits) < (int)iLoop; nbits++) {
				if (nbits >= 33) {
					msg("[ERRO] Invalid nbits\n");
					return -1;
				}
			}
	
			lastpart2 = block2s;
			while (pos < end) {
				cmd = pos[0] | (pos[1] << 8);
				pos += 2;
				temp1 = (cmd << (16 - part1s)) & 0xFFFF;
				temp1 = (temp1 >> (16 - part1s)) & 0xFFFF;
				if (temp1 >= block1s) {
					msg("[ERRO] Invalid part1 index\n");
					return -1;
				}
				part1 = block1[temp1];
				if ((part1 & 0x01) == 0) {
					ofsbase = (cmd << (16 - part1s - nbits)) & 0xFFFF;
					ofsbase = (ofsbase >> (16 - nbits)) & 0xFFFF;
					if (!(ofsbase < iLoop)) {
						msg("[ERRO] Invalid offset base\n");
						return -1;
					}

					if ((part1 & 0x06) == 0) {
						offset = cmd >> (part1s + nbits);
					} else if ((part1 & 0x06) == 4) {
						offset = pos[0] | (pos[1] << 8) | (pos[2] << 16) | (pos[3] << 24);
						pos += 4;
					} else {
						msg("[ERRO] Invalid size\n");
						return -1;
					}
				} else {
					temp2 = (cmd << (16 - (part1s + nbits + part2s))) & 0xFFFF;
					temp2 = (temp2 >> (16 - part2s)) & 0xFFFF;
					if (temp2 >= block2s) {
						msg("[ERRO] Invalid part2 index\n");
						return -1;
					}

					addrbase = (cmd << (16 - part1s - nbits)) & 0xFFFF;
					addrbase = (addrbase >> (16 - nbits)) & 0xFFFF;
					if (!(addrbase < iLoop)) {
						msg("[ERRO] Invalid address base\n");
						return -1;
					}
					part2 = block2[temp2];
					
					switch (part1 & 0x06) {
					case 0:
						temp1 = cmd;
						if (temp1 & 0x8000) {
							temp1 |= ~0xFFFF;
							temp1 >>= part1s + part2s + nbits;
							temp1 |= ~0xFFFF;
						} else {
							temp1 >>= part1s + part2s + nbits;
						}
						offset += temp1;
						break;
					case 2:
						temp1 = cmd;
						if (temp1 & 0x8000) temp1 |= ~0xFFFF;
						temp1 = (temp1 >> (part1s + part2s + nbits)) << 16;
						temp1 |= pos[0] | (pos[1] << 8);
						offset += temp1;
						pos += 2;
						break;
					case 4:
						offset = pos[0] | (pos[1] << 8) | (pos[2] << 16) | (pos[3] << 24);
						pos += 4;
						break;
					default:
						msg("[ERRO] invalid part1 size\n");
						return -1;
					}
					
					if (!(offset < prx->phdr32[ofsbase].p_filesz)) {
						msg("[ERRO] invalid relocation offset\n");
						msg(" reloc %4d: offset=%08x filesz=%08x\n", iCurrRel, offset, prx->phdr32[ofsbase].p_filesz);
						return -1;
					}
					
					switch (part1 & 0x38) {
					case 0x00:
						addend = 0;
						break;
					case 0x08:
						if ((lastpart2 ^ 0x04) != 0) {
							addend = 0;
						}
						break;
					case 0x10:
						addend = pos[0] | (pos[1] << 8);
						pos += 2;
						break;
					case 0x18:
						addend = pos[0] | (pos[1] << 8) | (pos[2] << 16) | (pos[3] << 24);
						pos += 4;
						msg("[ERRO] invalid addendum size\n");
						return -1;
					default:
						msg("[ERRO] invalid addendum size\n");
						return -1;
					}

					lastpart2 = part2;
					prx->elfreloc[iCurrRel].secname = NULL;
					prx->elfreloc[iCurrRel].base = 0;
					prx->elfreloc[iCurrRel].symbol = ofsbase | (addrbase << 8);
					prx->elfreloc[iCurrRel].info = (ofsbase << 8) | (addrbase << 8);
					prx->elfreloc[iCurrRel].offset = offset;

					switch (part2) {
					case 2:
						prx->elfreloc[iCurrRel].type = R_MIPS_32;
						break;
					case 0:
						continue;
					case 3:
						prx->elfreloc[iCurrRel].type = R_MIPS_26;
						break;
					case 6:
						prx->elfreloc[iCurrRel].type = R_MIPS_X_J26;
						break;
					case 7:
						prx->elfreloc[iCurrRel].type = R_MIPS_X_JAL26;
						break;
					case 4:
						prx->elfreloc[iCurrRel].type = R_MIPS_X_HI16;
						prx->elfreloc[iCurrRel].base = (s16) addend;
						break;
					case 1:
					case 5:
						prx->elfreloc[iCurrRel].type = R_MIPS_LO16;
						break;
					default:
						msg("[ERRO] invalid relocation type\n");
						return -1;
					}
					temp1 = (cmd << (16 - part1s)) & 0xFFFF;
					temp1 = (temp1 >> (16 - part1s)) & 0xFFFF;
					temp2 = (cmd << (16 - (part1s + nbits + part2s))) & 0xFFFF;
					temp2 = (temp2 >> (16 - part2s)) & 0xFFFF;					
					//msg("[DEBUG] CMD=0x%04X I1=0x%02X I2=0x%02X PART1=0x%02X PART2=0x%02X\n", cmd, temp1, temp2, part1, part2);
					prx->elfreloc[iCurrRel].info |= prx->elfreloc[iCurrRel].type;
					iCurrRel++;
				}
			}
		}
	}

	return iCurrRel;
}

int fix_relocs(u8 *buf, Prx_info *prx)
{
	int i;
	u32 dwRealOfs;
	u32 dwCurrBase;
	int iOfsPH;
	int iValPH;
	ElfReloc *rel;
	
	for(i = 0; i < prx->relocs_cnt; i++){
		rel = &prx->elfreloc[i];
		iOfsPH = rel->symbol & 0xFF;
		iValPH = (rel->symbol >> 8) & 0xFF;
		dwRealOfs = base_addr + rel->offset + prx->phdr32[iOfsPH].p_vaddr;
		dwCurrBase = base_addr + prx->phdr32[iValPH].p_vaddr;
		switch(prx->elfreloc[i].type){
			case R_MIPS_HI16: {
				u32 inst;
				int base = i;
				int lowaddr, hiaddr, addr;
			  	int loinst;
			  	int ofsph = prx->phdr32[iOfsPH].p_vaddr;
			  	
				inst = get_long(dwRealOfs);
				addr = ((inst & 0xFFFF) << 16) + dwCurrBase;
				//msg("Hi at (%08X) %d\n", dwRealOfs, i);
			  	while (++i < prx->relocs_cnt) {
			  		if (prx->elfreloc[i].type != R_MIPS_HI16) break;
			  	}
				//msg("Matching low at %d\n", i);
			  	if (i < prx->relocs_cnt) {
					//loinst = LW(*((u32*) m_vMem.GetPtr(m_pElfRelocs[iLoop].offset+ofsph)));
					loinst = get_long(prx->elfreloc[i].offset+ofsph+base_addr);
				} else {
					loinst = 0;
				}

				addr = (s32) addr + (s16) (loinst & 0xFFFF);
				lowaddr = addr & 0xFFFF;
				hiaddr = (((addr >> 15) + 1) >> 1) & 0xFFFF;
				while (base < i) {
					inst = get_long(prx->elfreloc[base].offset+ofsph+base_addr);
					//msg("REL R_MIPS_HI16 Patching VAddr[0x%0.8x] [0x%0.8x] -> ", prx->elfreloc[base].offset+ofsph+base_addr, inst);
					inst = (inst & ~0xFFFF) | hiaddr;
					put_long(prx->elfreloc[base].offset+ofsph+base_addr, inst);
					//msg(" [0x%0.8x]\n", inst);
					base++;
				}
			  	while (i < prx->relocs_cnt) {
					inst = get_long(prx->elfreloc[i].offset+ofsph+base_addr);
					//msg("REL R_MIPS_HI16 Patching VAddr[0x%0.8x] [0x%0.8x] -> ", prx->elfreloc[i].offset+ofsph+base_addr, inst);
					if ((inst & 0xFFFF) != (loinst & 0xFFFF)) break;
					inst = (inst & ~0xFFFF) | lowaddr;
					put_long(prx->elfreloc[i].offset+ofsph+base_addr, inst);
					//msg(" [0x%0.8x]\n", inst);
					

			  		if (prx->elfreloc[++i].type != R_MIPS_LO16) break;
				}
				i--;
				//msg("Finished at %d\n", i);
			}
			break;
			case R_MIPS_16:
			case R_MIPS_LO16: {
				u32 loinst;
				u32 addr;
				//loinst = LW(*pData);
				loinst = get_long(dwRealOfs);
				//msg("REL R_MIPS_16 Patching VAddr[0x%0.8x] [0x%0.8x] -> ", dwRealOfs, loinst);
				addr = ((s16) (loinst & 0xFFFF)) + dwCurrBase;
				//msg("Low at (%08X)\n", dwRealOfs);
				loinst &= ~0xFFFF;
				loinst |= (addr & 0xFFFF);
				//SW(*pData, loinst);
				put_long(dwRealOfs, loinst);
				//msg(" [0x%0.8x]\n", loinst);
			}
			break;
			case R_MIPS_X_HI16: {
				u32 hiinst;
				u32 addr, hiaddr;
				//ImmEntry *imm;

				//hiinst = LW(*pData);

				hiinst = get_long(dwRealOfs);
				//msg("REL R_MIPS_X_HI16 Patching VAddr[0x%0.8x] [0x%0.8x] -> ", dwRealOfs, hiinst);
				addr = (hiinst & 0xFFFF) << 16;
				addr += rel->base + dwCurrBase;
				hiaddr = (((addr >> 15) + 1) >> 1) & 0xFFFF;
				//msg("Extended hi at (%08X)\n", dwRealOfs);


				hiinst &= ~0xFFFF;
				hiinst |= (hiaddr & 0xFFFF);
				//SW(*pData, hiinst);
				put_long(dwRealOfs, hiinst);
				//msg(" [0x%0.8x]\n", hiinst);
			}
			break;
			case R_MIPS_X_J26:
			case R_MIPS_X_JAL26:
			case R_MIPS_26: {
				u32 dwAddr;
				u32 dwInst;

				//dwInst = LW(*pData);
				dwInst = get_long(dwRealOfs);
				//msg("REL R_MIPS_X_J26 Patching VAddr[0x%0.8x] [0x%0.8x] -> ", dwRealOfs, dwInst);
				dwAddr = (dwInst & 0x03FFFFFF) << 2;
				dwAddr += dwCurrBase;
				dwInst &= ~0x03FFFFFF;
				dwAddr = (dwAddr >> 2) & 0x03FFFFFF;
				dwInst |= dwAddr;
				//SW(*pData, dwInst);
				put_long(dwRealOfs, dwInst);
				//msg(" [0x%0.8x]\n", dwInst);
			}
			break;
			case R_MIPS_32:   {
				u32 dwData;

				//dwData = LW(*pData);
				dwData = get_long(dwRealOfs);
				//msg("REL R_MIPS_32 Patching VAddr[0x%0.8x] [0x%0.8x] -> ", dwRealOfs, dwData);
				dwData += dwCurrBase;
				//SW(*pData, dwData);
				put_long(dwRealOfs, dwData);
				//msg(" [0x%0.8x]\n", dwData);
				
			}
			break;
			default: /* Do nothing */
			break;
		};
	}
	return 0;
}

int do_relocs(u8 *buf, Prx_info *prx)
{
	prx->relocs_cnt = count_relocs(buf, prx);
	if(prx->relocs_cnt < 0)
		return -1;

	prx->elfreloc = (ElfReloc *)qalloc(sizeof(ElfReloc)*prx->relocs_cnt);
	prx->relocs_cnt = load_relocs(buf, prx);
	fix_relocs(buf, prx);

	return 0;
}

char * find_nid_name(Prx_info *prx, char *libname, u32 nid)
{
	int i, idx = -1;
	for(i=0; i<prx->lib_cnt; i++){
		if(0 == strcmp(prx->plibnid[i].name, libname)){
			idx = i;
			break;
		}
	}
	if(idx < 0)
		return NULL;
	
	for(i=0; i<(int)prx->plibnid[idx].cnt; i++){
		if(nid == prx->plibnid[idx].pNid[i].nid)
			return prx->plibnid[idx].pNid[i].name;
	}
	return NULL;
}

int load_single_export(u8 *buf, Prx_info *prx, PspModuleExport *pExport, u32 addr, int idx)
{
	bool blError = true;
	int count = 0;
	int iLoop;
	PspLibExport* pLib = NULL;
	u32 expAddr;
	char sym_name[128];
	char *nid_name;
	
	if(NULL == pExport)
		return -1;
	
	pLib = (PspLibExport *)qalloc(sizeof(PspLibExport));
	if(pLib != NULL){
		do{
			memset(pLib, 0, sizeof(PspLibExport));
			pLib->addr = addr;
			pLib->stub.name = pExport->name;
			pLib->stub.flags = pExport->flags;
			pLib->stub.counts = pExport->counts;
			pLib->stub.exports = pExport->exports;
			
			if(pLib->stub.name == 0){
				/* If 0 then this is the system, this should be the only one */
				strcpy(pLib->name, PSP_SYSTEM_EXPORT);
			}
			else{
				get_many_bytes(pLib->stub.name, pLib->name, PSP_LIB_MAX_NAME);
				doASCI(pLib->stub.name, -1);
				sprintf(sym_name, "export_%d%s", idx, "_name");
				set_name(pLib->stub.name, sym_name);
			}

			//msg("[DEBUG] Found export library '%s'\n", pLib->name);
			//msg("[DEBUG] Flags %08X, counts %08X, exports %08X\n", 
			//		pLib->stub.flags, pLib->stub.counts, pLib->stub.exports);

			pLib->v_count = (pLib->stub.counts >> 8) & 0xFF;
			pLib->f_count = (pLib->stub.counts >> 16) & 0xFFFF;
			count = pLib->stub.counts & 0xFF;
			expAddr = pLib->stub.exports;

			for(iLoop = 0; iLoop < pLib->f_count; iLoop++){
				pLib->funcs[iLoop].nid = get_long(expAddr);
				nid_name = find_nid_name(prx, pLib->name, pLib->funcs[iLoop].nid);
				if(NULL == nid_name)
					sprintf(pLib->funcs[iLoop].name, "%s_%08x", pLib->name, pLib->funcs[iLoop].nid);
				else
					strcpy(pLib->funcs[iLoop].name, nid_name);
				pLib->funcs[iLoop].type = PSP_ENTRY_FUNC;
				pLib->funcs[iLoop].addr = get_long(expAddr + (sizeof(u32) * (pLib->v_count + pLib->f_count)));
				pLib->funcs[iLoop].nid_addr = expAddr; 
				//msg("[DEBUG] Found export nid:0x%08X func:0x%08X name:%s\n", 
				//							pLib->funcs[iLoop].nid, pLib->funcs[iLoop].addr, pLib->funcs[iLoop].name);
				set_name(pLib->funcs[iLoop].addr, pLib->funcs[iLoop].name);//, SN_PUBLIC);
				doDwrd(expAddr + (sizeof(u32) * (pLib->v_count + pLib->f_count)), 4);
				sprintf(sym_name, "export_%d_%s_nid", idx, pLib->funcs[iLoop].name);
				doDwrd(expAddr, 4);
				set_name(expAddr, sym_name);
				expAddr += 4;
			}

			for(iLoop = 0; iLoop < pLib->v_count; iLoop++){
				pLib->vars[iLoop].nid = get_long(expAddr);
				nid_name = find_nid_name(prx, pLib->name, pLib->vars[iLoop].nid);
				if(NULL == nid_name)
					sprintf(pLib->vars[iLoop].name, "%s_%08x", pLib->name, pLib->vars[iLoop].nid);
				else
					strcpy(pLib->vars[iLoop].name, nid_name);
				pLib->vars[iLoop].type = PSP_ENTRY_FUNC;
				pLib->vars[iLoop].addr = get_long(expAddr + (sizeof(u32) * (pLib->v_count + pLib->f_count)));
				pLib->vars[iLoop].nid_addr = expAddr; 
				//msg("[DEBUG] Found export nid:0x%08X var:0x%08X name:%s\n", 
				//							pLib->vars[iLoop].nid, pLib->vars[iLoop].addr, pLib->vars[iLoop].name);
				//set_name(pLib->vars[iLoop].addr, pLib->vars[iLoop].name);
				doDwrd(expAddr + (sizeof(u32) * (pLib->v_count + pLib->f_count)), 4);
				sprintf(sym_name, "export_%d_%s_nid", idx, pLib->vars[iLoop].name);
				doDwrd(expAddr, 4);
				set_name(expAddr, sym_name);
				expAddr += 4;
			}

			if(prx->plibexp == NULL){
				pLib->next = NULL;
				pLib->prev = NULL;
				prx->plibexp = pLib;
			}
			else{
				// Search for the end of the list
				PspLibExport* pExport;
				pExport = prx->plibexp = pLib;
				while(pExport->next != NULL){
					pExport = pExport->next;
				}

				pExport->next = pLib;
				pLib->prev = pExport;
				pLib->next = NULL;
			}

			blError = false;

		}
		while(false);
	}
	else	{
		msg("[ERRO] Couldn't allocate memory for export\n");
	}
	if(blError){
		count = 0;
		if(pLib != NULL){
			qfree(pLib);
			pLib = NULL;
		}
	}
	return count;
}


bool load_exports(u8 *buf, Prx_info *prx)
{
	bool blRet = true;
	u32 exp_base;
	u32 exp_end;
	u32 count;
	PspModuleExport exports;
	PspModuleExport *pExports;
	int idx = 0;
	char sym_name[128];
	
	exp_base = prx->pModInfo->exports;
	exp_end =  prx->pModInfo->exp_end;
	if(exp_base != 0){
		while((exp_end - exp_base) >= sizeof(PspModuleExport)){
			pExports = (PspModuleExport*) (exp_base + base_addr);
			if(get_many_bytes(exp_base+base_addr, &exports, sizeof(PspModuleExport))){
				doDwrd((ea_t)(&pExports->counts), 4);
				sprintf(sym_name, "export_%d%s", idx, "_counts");
				set_name((ea_t)(&pExports->counts), sym_name);
				doDwrd((ea_t)(&pExports->exports), 4);
				sprintf(sym_name, "export_%d%s", idx, "_exports");
				set_name((ea_t)(&pExports->exports), sym_name);
				doDwrd((ea_t)(&pExports->flags), 4);
				sprintf(sym_name, "export_%d%s", idx, "_flags");
				set_name((ea_t)(&pExports->flags), sym_name);
				doDwrd((ea_t)(&pExports->name), 4);
				sprintf(sym_name, "export_%d%s", idx, "");
				set_name((ea_t)(&pExports->name), sym_name);
				count = load_single_export(buf, prx, &exports, exp_base, idx);
				if(count > 0){
					exp_base += (count * sizeof(u32));
				}
				else{
					blRet = false;
					break;
				}
			}
			else{
				blRet = false;
				break;
			}
			idx++;
		}
	}
	return blRet;
}

int load_single_import(u8 *buf, Prx_info *prx, PspModuleImport *pImport, u32 addr, int idx)
{
	bool blError = true;
	int count = 0;
	int iLoop;
	u32 nidAddr;
	u32 funcAddr;
	u32 varAddr;
	PspLibImport *pLib = NULL;
	char sym_name[128];
	char *nid_name;
	
	pLib = (PspLibImport *)qalloc(sizeof(PspLibImport));
	
	if(pLib != NULL){
		do{
			memset(pLib, 0, sizeof(PspModuleImport));
			pLib->addr = addr;
			pLib->stub.name = pImport->name; /*SYM:addr of pImport->name set to DWORD, named with importX*/
			pLib->stub.flags = pImport->flags; /* SYM:addr of pImport->flags set to DWORD, named with importX_flags */
			pLib->stub.counts = pImport->counts; /* SYM:DWORD , importX_counts */
			pLib->stub.nids = pImport->nids; /* SYM:DWORD, importX_nids */
			pLib->stub.funcs = pImport->funcs; /* SYM:DWORD, importX_funcs */
			pLib->stub.vars = pImport->vars; /* ?? overflow to next import */

			if(pLib->stub.name == 0){
				/* Shouldn't be zero, although technically it could be */
				msg("[DEBUG] Import libraries must have a name");
				break;
			}
			else{
				get_many_bytes(pLib->stub.name, pLib->name, PSP_LIB_MAX_NAME);
				doASCI(pLib->stub.name, -1);
				sprintf(sym_name, "import_%d%s", idx, "_name");
				set_name(pLib->stub.name, sym_name);
			}

			//msg("[DEBUG] Found import library '%s'\n", pLib->name);
			//msg("[DEBUG] Flags %08X, counts %08X, nids %08X, funcs %08X\n", 
			//		pLib->stub.flags, pLib->stub.counts, pLib->stub.nids, pLib->stub.funcs);

			pLib->v_count = (pLib->stub.counts >> 8) & 0xFF;
			pLib->f_count = (pLib->stub.counts >> 16) & 0xFFFF;
			count = pLib->stub.counts & 0xFF;
			nidAddr = pLib->stub.nids;
			funcAddr = pLib->stub.funcs;
			varAddr = pLib->stub.vars;
			
			for(iLoop = 0; iLoop < pLib->f_count; iLoop++){
				pLib->funcs[iLoop].nid = get_long(nidAddr);
				nid_name = find_nid_name(prx, pLib->name, pLib->funcs[iLoop].nid);
				if(NULL == nid_name)
					sprintf(pLib->funcs[iLoop].name, "%s_%08x", pLib->name, pLib->funcs[iLoop].nid);
				else
					strcpy(pLib->funcs[iLoop].name, nid_name);
				//sprintf(pLib->funcs[iLoop].name, "%s_%08x", pLib->name, pLib->funcs[iLoop].nid);
				pLib->funcs[iLoop].type = PSP_ENTRY_FUNC;
				pLib->funcs[iLoop].addr = funcAddr;
				pLib->funcs[iLoop].nid_addr = nidAddr;
				//msg("[DEBUG] Found import nid:0x%08X func:0x%08X name:%s\n", 
				//				pLib->funcs[iLoop].nid, pLib->funcs[iLoop].addr, pLib->funcs[iLoop].name);
				set_name(pLib->funcs[iLoop].addr, pLib->funcs[iLoop].name);
				doDwrd(nidAddr, 4);
				sprintf(sym_name, "import_%d_%s_nid", idx, pLib->funcs[iLoop].name);
				set_name(nidAddr, sym_name);				
				nidAddr += 4;
				funcAddr += 8;
			}

			for(iLoop = 0; iLoop < pLib->v_count; iLoop++){
				u32 varFixup;
				u32 varData;

				pLib->vars[iLoop].addr = get_long(varAddr);
				pLib->vars[iLoop].nid = get_long(varAddr+4);
				pLib->vars[iLoop].type = PSP_ENTRY_VAR;
				pLib->vars[iLoop].nid_addr = varAddr+4;
				//strcpy(pLib->vars[iLoop].name, m_pCurrNidMgr->FindLibName(pLib->name, pLib->vars[iLoop].nid));
				//sprintf(pLib->vars[iLoop].name, "%s_%08x", pLib->name, pLib->vars[iLoop].nid);
				nid_name = find_nid_name(prx, pLib->name, pLib->vars[iLoop].nid);
				if(NULL == nid_name)
					sprintf(pLib->vars[iLoop].name, "%s_%08x", pLib->name, pLib->vars[iLoop].nid);
				else
					strcpy(pLib->vars[iLoop].name, nid_name);
				//msg("[DEBUG] Found variable nid:0x%08X addr:0x%08X name:%s\n",
				//		pLib->vars[iLoop].nid, pLib->vars[iLoop].addr, pLib->vars[iLoop].name);
				set_name(pLib->vars[iLoop].addr, pLib->vars[iLoop].name);
				varFixup = pLib->vars[iLoop].addr;
				while((varData = get_long(varFixup))){
					//msg("[DEBUG] Variable Fixup: addr:%08X type:%08X\n", 
					//		(varData & 0x3FFFFFF) << 2, varData >> 26);
					varFixup += 4;
				}
				varAddr += 8;
			}

			if(prx->plibimp == NULL){
				pLib->next = NULL;
				pLib->prev = NULL;
				prx->plibimp = pLib;
			}
			else{
				// Search for the end of the list
				PspLibImport* pImport;

				pImport = prx->plibimp;
				while(pImport->next != NULL){
					pImport = pImport->next;
				}

				pImport->next = pLib;
				pLib->prev = pImport;
				pLib->next = NULL;
			}

			blError = false;
		}
		while(false);
	}
	else{
		msg("[ERRO] Could not allocate memory for import library");
	}

	if(blError == true){
		count = 0;
		if(pLib != NULL){
			qfree(pLib);
			pLib = NULL;
		}
	}

	return count;
}
 
bool load_imports(u8 *buf, Prx_info *prx)
{
	bool blRet = true;
	u32 imp_base;
	u32 imp_end;
	u32 count;
	PspModuleImport imports;
	PspModuleImport* pImports;
	int idx = 0;
	char sym_name[128];
	
	imp_base = prx->pModInfo->imports;
	imp_end =  prx->pModInfo->imp_end;
	int stubBottom = 0;

	if(imp_base != 0){
		while((imp_end - imp_base) >= PSP_IMPORT_BASE_SIZE){
			pImports = (PspModuleImport*)(imp_base+base_addr);
			if(get_many_bytes(imp_base+base_addr, &imports, sizeof(PspModuleImport))){
				doDwrd((ea_t)(&pImports->counts), 4);
				sprintf(sym_name, "import_%d%s", idx, "_counts");
				set_name((ea_t)(&pImports->counts), sym_name);
				doDwrd((ea_t)(&pImports->flags), 4);
				sprintf(sym_name, "import_%d%s", idx, "_flags");
				set_name((ea_t)(&pImports->flags), sym_name);
				doDwrd((ea_t)(&pImports->name), 4);
				sprintf(sym_name, "import_%d%s", idx, "");
				set_name((ea_t)(&pImports->name), sym_name);	
				doDwrd((ea_t)(&pImports->nids), 4);
				sprintf(sym_name, "import_%d%s", idx, "_nids");
				set_name((ea_t)(&pImports->nids), sym_name);
				doDwrd((ea_t)(&pImports->funcs), 4);
				sprintf(sym_name, "import_%d%s", idx, "_funcs");
				set_name((ea_t)(&pImports->funcs), sym_name);
				count = load_single_import(buf, prx, &imports, imp_base, idx);
				if(count > 0){
					imp_base += (count * sizeof(u32));
				}
				else{
					blRet = false;
					break;
				}
				idx++;
			}
			else{
				blRet = false;
				break;
			}
		}
	}
	stubBottom += 4;

	return blRet;
}

int load_module_info(u8 *buf, Prx_info *prx)
{
	int modinfo_idx;
	PspModuleInfo *pModInfo = NULL;

	modinfo_idx = find_section(prx, PSP_MODULE_INFO_NAME);
	
	if(modinfo_idx > 0){
		prx->pModInfo = (PspModuleInfo*)(buf+prx->shdr32[modinfo_idx].sh_offset);
		pModInfo = (PspModuleInfo*)(prx->shdr32[modinfo_idx].sh_addr + base_addr);
	}else{
		if(prx->ehdr32->e_phnum>0){
			u32 vaddr, paddr;
			// if no section table found, 
			// ph[0].p_paddr is the offset of .rodata.sceModuleInfo
			paddr = prx->phdr32[0].p_paddr;
			paddr &= 0x0fffffff;
			prx->pModInfo = (PspModuleInfo*)(buf+paddr);

			vaddr = prx->phdr32[0].p_vaddr+base_addr;
			vaddr += paddr-prx->phdr32[0].p_offset;

			pModInfo = (PspModuleInfo*)(vaddr);
		}
	}

	if(NULL != prx->pModInfo){
		describe(base_addr, true, "\nPrx Module Info:\n");
		describe(base_addr, true, "Name: %s", prx->pModInfo->name);
		describe(base_addr, true, "Flags: 0x%08X", prx->pModInfo->flags);
		describe(base_addr, true, "GP: 0x%08X", prx->pModInfo->gp);
		describe(base_addr, true, "Exports: 0x%08X, Exp_end: 0x%08X", prx->pModInfo->exports+base_addr, prx->pModInfo->exp_end+base_addr);
		describe(base_addr, true, "Imports: 0x%08X, Imp_end: 0x%08X", prx->pModInfo->imports+base_addr, prx->pModInfo->imp_end+base_addr);

		doASCI((ea_t)(pModInfo->name), PSP_MODULE_MAX_NAME);
		set_name((ea_t)(pModInfo->name), "_module_name");
		doDwrd((ea_t)(&pModInfo->flags), 4);
		set_name((ea_t)(&pModInfo->flags), "_module_flags");
		doDwrd((ea_t)(&pModInfo->gp), 4);
		set_name((ea_t)(&pModInfo->gp), "_module_gp");
		doDwrd((ea_t)(&pModInfo->exports), 4);
		set_name((ea_t)(&pModInfo->exports), "_module_exports");
		doDwrd((ea_t)(&pModInfo->exp_end), 4);
		set_name((ea_t)(&pModInfo->exp_end), "_module_exp_end");
		doDwrd(prx->pModInfo->exp_end+base_addr, 4);
		set_name(prx->pModInfo->exp_end+base_addr, "_exp_end");
		doDwrd((ea_t)(&pModInfo->imports), 4);
		set_name((ea_t)(&pModInfo->imports), "_module_imports");
		doDwrd((ea_t)(&pModInfo->imp_end), 4);
		set_name((ea_t)(&pModInfo->imp_end), "_module_imp_end");
		doDwrd(prx->pModInfo->imp_end+base_addr, 4);
		set_name(prx->pModInfo->imp_end+base_addr, "_imp_end");
	}

	return 0;
}

int load_single_lib_nids(Prx_info *prx, u8 *start, u8 *end, int idx)
{
	int nid_cnt=0, i;
	u8 *p, *q, *s;
	p = start;
	while(p<end){
		q = (u8 *)strstr((char *)p, "<NID>");
		if((NULL == q) ||q>end)
			break;
		nid_cnt++;
		p = q+1;
	}

	//msg("[debug] here is %d nid entrys\n", nid_cnt);
	prx->plibnid[idx].pNid = (NidEntry *)qalloc(nid_cnt * sizeof(NidEntry));
	memset(prx->plibnid[idx].pNid, 0, nid_cnt * sizeof(NidEntry));
	p = start;
	prx->plibnid[idx].cnt = nid_cnt;
	for(i=0 ;i<nid_cnt; i++){
		q = (u8 *)strstr((char *)p, "<NID>");
		s = (u8 *)strstr((char *)p, "</NID>");
		strncpy(prx->plibnid[idx].pNid[i].name, (const char*)q+5, s-q-5);
		prx->plibnid[idx].pNid[i].nid = strtoul(prx->plibnid[idx].pNid[i].name,NULL,16);
		p = s;
		q = (u8 *)strstr((char *)p, "<NAME>");
		s = (u8 *)strstr((char *)p, "</NAME>");
		memset(prx->plibnid[idx].pNid[i].name, 0, 64);
		strncpy(prx->plibnid[idx].pNid[i].name, (const char*)q+6, s-q-6);
		p = s;
	}
	return 0;
}

int load_lib_nids(Prx_info *prx, u8 *start, u8 *end)
{
	int lib_cnt = 0, i, j;
	u8 *p, *q, *s, *t;
	
	p = start;
	while(p<end){
		q = (u8 *)strstr((char *)p, "<LIBRARY>");
		if(NULL == q || q>end)
			break;
		lib_cnt++;
		p = q+1;
	}
	msg("[debug] here is %d library entrys\n", lib_cnt);
	lib_cnt = lib_cnt + 3; /* for syslib ; sceLibc and sceLibm */
	prx->plibnid = (LibNidEntry *)qalloc(lib_cnt * sizeof(LibNidEntry));
	memset(prx->plibnid, 0, lib_cnt * sizeof(LibNidEntry));
	p = (u8 *)strstr((char *)start, "<LIBRARY>");
	for(i=0; i<lib_cnt-3; i++){
		q = (u8 *)strstr((char *)p+1, "<LIBRARY>");
		if(q == NULL)
			q = end;
		load_single_lib_nids(prx, p, q, i);
		s = (u8 *)strstr((char *)p, "<NAME>");
		t = (u8 *)strstr((char *)p, "</NAME>");
		strncpy(prx->plibnid[i].name, (const char*)s+6, t-s-6);
		p = q+1;
		
	}
	
	/* load syslib */
	prx->plibnid[i].cnt = sizeof(g_syslib) / sizeof(g_syslib[0]);
	prx->plibnid[i].pNid = (NidEntry *)qalloc(prx->plibnid[i].cnt * sizeof(NidEntry));
	memset(prx->plibnid[i].pNid, 0, prx->plibnid[i].cnt * sizeof(NidEntry));
	for(j=0; j<(int)prx->plibnid[i].cnt; j++) {
		strcpy(prx->plibnid[i].pNid[j].name, g_syslib[j].name);
		prx->plibnid[i].pNid[j].nid = g_syslib[j].nid;
	}
	strcpy(prx->plibnid[i].name, "syslib");

	/* load sceLibc */
	i++;
	prx->plibnid[i].cnt = sizeof(g_sceLibc) / sizeof(g_sceLibc[0]);
	prx->plibnid[i].pNid = (NidEntry *)qalloc(prx->plibnid[i].cnt * sizeof(NidEntry));
	memset(prx->plibnid[i].pNid, 0, prx->plibnid[i].cnt * sizeof(NidEntry));
	for(j=0; j<(int)prx->plibnid[i].cnt; j++) {
		strcpy(prx->plibnid[i].pNid[j].name, g_sceLibc[j].name);
		prx->plibnid[i].pNid[j].nid = g_sceLibc[j].nid;
	}
	strcpy(prx->plibnid[i].name, "sceLibc");
	
	/* load sceLibm */
	i++;
	prx->plibnid[i].cnt = sizeof(g_sceLibm) / sizeof(g_sceLibm[0]);
	prx->plibnid[i].pNid = (NidEntry *)qalloc(prx->plibnid[i].cnt * sizeof(NidEntry));
	memset(prx->plibnid[i].pNid, 0, prx->plibnid[i].cnt * sizeof(NidEntry));
	for(j=0; j<(int)prx->plibnid[i].cnt; j++) {
		strcpy(prx->plibnid[i].pNid[j].name, g_sceLibm[j].name);
		prx->plibnid[i].pNid[j].nid = g_sceLibm[j].nid;
	}
	strcpy(prx->plibnid[i].name, "sceLibm");
	
	return lib_cnt;
}

int load_nid_tbl(Prx_info *prx)
{
	char xml_path[256];
	FILE *fp = NULL;
	u8 *buf;
	int filesize;
	char * fname = NULL;
	
	/* const char * get_plugins_path(void); failed to link, not in lib ida.a ida.lib */
	/*path = get_plugins_path();*/
	sprintf(xml_path, "%s\\%s", idadir(LDR_SUBDIR), "psplibdoc.xml");
	fp = fopen(xml_path, "rb");
	if(NULL == fp){
		fname = askfile_c(0, "*.xml", "select psplibdoc.xml file\n");
		if(NULL == fname)
			return -1;
		fp = fopen(fname, "rb");
		if(NULL == fp)
			return -1;
	}
	fseek(fp, 0, SEEK_END);
	filesize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	buf = (u8*)qalloc(filesize);
	fread(buf, filesize, 1, fp);
	fclose(fp);
	prx->lib_cnt = load_lib_nids(prx, buf, buf+filesize);
	qfree(buf);
	return 0;
}

//----------------------------------------------------------------------
static int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
	if ( n != 0 ) 
		return false;
	if(!is_prx(li))
		return false;
	qsnprintf(fileformatname, MAX_FILE_FORMAT_NAME, "PSP Prx Loader");
	return 1;
}

/* fname is used to indcate which ldr is used, like "PSP Prx Loader" */
static void idaapi load_file(linput_t *li, ushort neflag, const char * /*fname*/) 
{
	u8 *buf;
	int filesize;
	Prx_info prx;
	memset(&prx, 0, sizeof(Prx_info));
	
	if(ph.id != PLFM_MIPS){
		/* IDA 6.1 have PSP cpu module, use 'mipsl' for lower version */
		char *proc_module;
		proc_module = set_processor_type("psp", SETPROC_ALL);
		if(proc_module==NULL)
			proc_module = set_processor_type("mipsl", SETPROC_ALL|SETPROC_FATAL);
	}


	load_nid_tbl(&prx);

	qlseek(li, 0, SEEK_END);
	prx.prx_size = qltell(li);
	qlseek(li, 0, SEEK_SET);

	buf = (u8*)qalloc(prx.prx_size);
	qlread(li, buf, prx.prx_size);
	
	prx.ehdr32 = (Elf32_Ehdr *)buf;

	if(prx.ehdr32->e_entry<0x08800000)
		askaddr(&base_addr, "Set base address for relocation:");
	else
		base_addr = 0;

	load_section_headers(buf, &prx);

	if(load_program_headers(buf, &prx)<0){
		goto EXIT;
	}

	//load_symbols(buf, ehdr32);
	if(prx.ehdr32->e_shnum > 0){
		load_sections(buf, &prx);
	}else{
		load_programs(buf, &prx);
	}

	create_bss(&prx);

	do_relocs(buf, &prx);

	load_module_info(buf, &prx);
	load_exports(buf, &prx);
	load_imports(buf, &prx);

EXIT:
	qfree(buf);

	if(NULL != prx.secname)
		qfree(prx.secname);

	if(NULL != prx.shdr32)
		qfree(prx.shdr32);

	if(NULL != prx.phdr32)
		qfree(prx.phdr32);

	if(NULL != prx.elfreloc)
		qfree(prx.elfreloc);

	return;
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
loader_t LDSC =
{
	IDP_INTERFACE_VERSION,
 	0,
	accept_file,
	load_file,
	NULL,
	NULL,
	NULL,
};

