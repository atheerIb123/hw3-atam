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
#define STB_LOCAL 0
#define SHN_UNDEF 0
#define SHT_SYMTAB 2

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
    bool symbol_flag = false; // Indicates whether the symbol is found
    FILE* exe_file = fopen(exe_file_name, "rb"); // Open the file in binary mode for read only

    if (exe_file == NULL)
    {
        *error_val = -3; // Couldn't open the file in this case or the file is not an executable
        return 0;
    }

    Elf64_Ehdr elf_header;

    size_t elf_header_size = sizeof(Elf64_Ehdr);
    fread(&elf_header, elf_header_size, 1, exe_file); // Read one instance of size = eHdr_size from the file

    if (elf_header.e_type != ET_EXEC)
    {
        *error_val = -3;
        fclose(exe_file);
        return 0;
    }

    // All set to start finding the symbol table

    Elf64_Shdr section_header;

    size_t Shdr_size = sizeof(section_header);
    long offset_of_Shdr = elf_header.e_shoff + elf_header.e_shentsize * elf_header.e_shstrndx; // Calculate the offset to section header names/section header string table

    fseek(exe_file, offset_of_Shdr, SEEK_SET);
    fread(&section_header, Shdr_size, 1, exe_file); // Update "Elf64_Shdr section_header"

    fseek(exe_file, elf_header.e_shoff, SEEK_SET);

    // Find the section header string table

    char *section_names = malloc(section_header.sh_size);
    fseek(exe_file, section_header.sh_offset, SEEK_SET);
    fread(section_names, section_header.sh_size, 1, exe_file);

    // Find the symbol table section

    Elf64_Shdr symbol_table_header;

    for (int i = 0; i < elf_header.e_shnum; i++)
    {
        printf("\n%d\n", i);
        fread(&symbol_table_header, Shdr_size, 1, exe_file);

        if (symbol_table_header.sh_type == 2)
            break;

        fseek(exe_file, elf_header.e_shentsize - Shdr_size, SEEK_CUR);
    }

    if (symbol_table_header.sh_type != SHT_SYMTAB)
    {
        *error_val = -1; // Symbol table not found
        printf("\nwassup\n");
        fclose(exe_file);
        free(section_names);
        return 0;
    }

    // Read the symbol table entries

    Elf64_Sym symbol;
    size_t symbol_size = sizeof(symbol);

    fseek(exe_file, symbol_table_header.sh_offset, SEEK_SET);

    while (fread(&symbol, symbol_size, 1, exe_file))
    {
        char *symbol_name_str = section_names + symbol_table_header.sh_link + symbol.st_name;

        if (strcmp(symbol_name_str, symbol_name) == 0)
        {
            symbol_flag = true;
            break;
        }
    }

    fclose(exe_file);
    free(section_names);

    if (!symbol_flag)
    {
        *error_val = -1; // Symbol not found
        return 0;
    }

    if (ELF64_ST_BIND(symbol.st_info) == STB_LOCAL)
    {
        *error_val = -2; // Symbol is not global
        return 0;
    }

    if (symbol.st_shndx == SHN_UNDEF)
    {
        *error_val = -4; // Symbol is global but will come from a shared library
        return 0;
    }

    *error_val = 1; // Symbol is found and is global
    return symbol.st_value;
}

int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);


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
