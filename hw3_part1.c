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

    // Find the symbol table section

    Elf64_Shdr symbol_table_header;
    Elf64_Shdr string_table;
    Elf64_Shdr current;

    size_t sht_size = elf_header.e_shnum * elf_header.e_shentsize;
    fseek(exe_file, elf_header.e_shoff, SEEK_SET);

    uint8_t sht[sht_size];
    fread(sht, elf_header.e_shentsize, elf_header.e_shnum, exe_file);
    size_t Shdr_size = sizeof(current);
    Elf64_Shdr* strtab_sh = NULL;
    Elf64_Shdr* shstrtab_sh = (void *) sht + elf_header.e_shstrndx * elf_header.e_shentsize;

    uint8_t shstrtab[shstrtab_sh->sh_size];
    fseek(exe_file, shstrtab_sh->sh_offset, SEEK_SET);
    fread(shstrtab, 1, sizeof(shstrtab), exe_file);

    for(size_t i = 0; i < elf_header.e_shnum; ++i)
    {
        Elf64_Shdr *sh = (void *) sht + i * elf_header.e_shentsize;

        char* str = shstrtab + sh->sh_name;

        if(strcmp(".strtab", shstrtab + sh->sh_name))
        {
            continue;
        }

        // We found the string table.
        strtab_sh = sh;
        break;
    }

    for (int i = 0; i < elf_header.e_shnum; i++)
    {
        fseek(exe_file, elf_header.e_shoff + i * elf_header.e_shentsize, SEEK_SET);
        fread(&current, Shdr_size, 1, exe_file);

        if (ELF64_R_TYPE(current.sh_type) == SHT_SYMTAB)
        {
            symbol_table_header = current;
        }
        else if(ELF64_R_TYPE(current.sh_type) == 3)
        {
            string_table = current;
        }
    }

    int symbolCount = symbol_table_header.sh_size / sizeof(Elf64_Sym);
    Elf64_Sym sym;
    uint8_t symtab[symbol_table_header.sh_size];
    fseek(exe_file, symbol_table_header.sh_offset, SEEK_SET);
    fread(symtab, symbol_table_header.sh_entsize, symbolCount, exe_file);

    uint8_t strtab[strtab_sh->sh_size];
    fseek(exe_file, strtab_sh->sh_offset, SEEK_SET);
    fread(strtab, 1, sizeof(strtab), exe_file);

    Elf64_Sym* symbol;// = (void *) symtab + i * symbol_table_header.sh_entsize;
    size_t sym_index = 0;

    for(sym_index; sym_index < symbolCount; sym_index++)
    {
        symbol = (void *) symtab + sym_index * symbol_table_header.sh_entsize;
        char* name = strtab + symbol->st_name;

        // If the name is empty skip this symbol.
        if(name == NULL)
            continue;

        if(strcmp(name, symbol_name) == 0)
        {
            symbol_flag = true;
            break;
        }
        else
        {
            symbol_flag = false;
        }
    }

    fclose(exe_file);

    if (!symbol_flag)
    {
        *error_val = -1; // Symbol not found
        return 0;
    }

    if (ELF64_ST_BIND(symbol->st_info) == STB_LOCAL)
    {
        bool flag = false;
        for(size_t i = sym_index + 1; i < symbolCount; i++) {
            symbol = (void *) symtab + i * symbol_table_header.sh_entsize;
            char *name = strtab + symbol->st_name;
            if(strcmp(name, symbol_name) == 0)
            {
                flag = true;
                break;
            }
        }
        if(!flag)
        {
            *error_val = -2; // Symbol is not global
            return 0;
        }
    }

    if (symbol->st_shndx == SHN_UNDEF)
    {
        *error_val = -4; // Symbol is global but will come from a shared library
        return 0;
    }

    *error_val = 1; // Symbol is found and is global
    return symbol->st_value;
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
