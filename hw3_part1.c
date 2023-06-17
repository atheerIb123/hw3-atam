#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) 
{
	bool symbol_flag = false; //indicates whether the symbol is found
	FILE* exe_file = fopen(exe_file_name, "rb"); //open the file in binary mode for read only
	
	if (exe_file == NULL)
	{
		*error_val = -3; //Couldn't open the file in this case or the file is not an executable
		return 0;
	}

	Elf64_Ehdr elf_header;

	size_t elf_header_size = sizeof(Elf64_Ehdr);
	fread(&elf_header, elf_header_size, 1, exe_file); //read one instance of size = eHdr_size from the file

	
	if (elf_header.e_type != ET_EXEC)
	{
		*error_val = -3;
		fclose(exe_file);
		return 0;
	}

	//All set to start finding the symbol_table

	Elf64_Shdr section_header;
	
	size_t Shdr_size = sizeof(section_header);
	long offset_of_Shdr = elf_header.e_shoff + elf_header.e_shentsize * elf_header.e_shstrndx; //calc the offest to section header names/section header string table

	fseek(exe_file, offset_of_Shdr, SEEK_SET);
	fread(&section_header, Shdr_size, 1, exe_file); //update "Elf64_Shdr section_header"

	fseek(exe_file, elf_header.e_shoff, SEEK_SET);

	


	return 0;
}

int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], "./verySecretProgram.axf", &err);


	if (err >= 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}
