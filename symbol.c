#include "symbol.h"

int lookup_symbols(char *fname, SymbolEntry **ses, int sesc) {
    FILE *tfile = fopen(fname, "r");
    if (tfile == 0) {
        return 0;
    }
    if (fseek(tfile, 0, SEEK_END)) {
        fclose(tfile);
        return 0;
    }
    long tfile_size = ftell(tfile);

    void *tbytes = mmap(0, (size_t)tfile_size, PROT_READ, MAP_PRIVATE, fileno(tfile), 0);

    if (tbytes == 0) {
        fclose(tfile);
        perror("mmap()");
        return 0;
    }

    fclose(tfile);

    const unsigned char expected_magic[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
    Elf64_Ehdr elf_hdr;
    memmove(&elf_hdr, tbytes, sizeof(elf_hdr));
    if (memcmp(elf_hdr.e_ident, expected_magic, sizeof(expected_magic)) != 0) {
        printf("Target is not an ELF executable\n");
        return 0;
    }
    if (elf_hdr.e_ident[EI_CLASS] != ELFCLASS64) {
        printf("Sorry, only ELF-64 is supported.\n");
        return 0;
    }
    if (elf_hdr.e_machine != EM_X86_64) {
        printf("Sorry, only x86-64 is supported.\n");
        return 0;
    }

    /*printf("file size: %zd\n", tfile_size);
    printf("program header offset: %zd\n", elf_hdr.e_phoff);
    printf("program header num: %d\n", elf_hdr.e_phnum);
    printf("section header offset: %zd\n", elf_hdr.e_shoff);
    printf("section header num: %d\n", elf_hdr.e_shnum);
    printf("section header string table: %d\n", elf_hdr.e_shstrndx);*/

    size_t string_offset = elf_hdr.e_shstrndx;
    uint64_t load_addr;
    char *cbytes = (char *)tbytes;
    for (uint16_t i = 0; i < elf_hdr.e_phnum; i++) {
        size_t offset = elf_hdr.e_phoff + i * elf_hdr.e_phentsize;
        Elf64_Phdr phdr;
        memmove(&phdr, tbytes + offset, sizeof(phdr));
        if (!i) {
            //printf("ELF load address is %p\n", phdr.p_vaddr);
            load_addr = phdr.p_vaddr;
        }
    }

    size_t dynstr_off = 0;
    size_t dynsym_off = 0;
    size_t dynsym_sz = 0;

    for (uint16_t i = 0; i < elf_hdr.e_shnum; i++) {
        size_t offset = elf_hdr.e_shoff + i * elf_hdr.e_shentsize;
        Elf64_Shdr shdr;
        memmove(&shdr, tbytes + offset, sizeof(shdr));
        //printf("LOAD ADDR: %p\n", shdr.sh_addr);
        switch (shdr.sh_type) {
          //case SHT_DYNSTR:
          case SHT_STRTAB:
            if (!dynstr_off && dynsym_off) { // XXX: this assumes .strtab is always after .symtab. readelf -S ./bin
                //printf("found string table at 0x%zx\n", shdr.sh_offset);
                dynstr_off = shdr.sh_offset;
            }
            break;
          //case SHT_DYNSYM:
          case SHT_SYMTAB:
            if (!dynsym_off) {
                dynsym_off = shdr.sh_offset;
                dynsym_sz = shdr.sh_size;
                //printf("found dynsym table at 0x%zx, size 0x%zx\n", shdr.sh_offset, shdr.sh_size);
            }
            break;
          default:
            break;
        }
    }
    assert(dynstr_off);
    assert(dynsym_off);


    for (size_t j = 0; j * sizeof(Elf64_Sym) < dynsym_sz; j++) {
        Elf64_Sym sym;
        size_t absoffset = dynsym_off + j * sizeof(Elf64_Sym);
        memmove(&sym, cbytes + absoffset, sizeof(sym));
        if (sym.st_name != 0) {
            char *name = cbytes + dynstr_off + sym.st_name;
            size_t n = strlen(name);
            char *pos = strstr(name, "@GLIBC_"); // XXX: slightly hacky
            if (pos) {
                //n = pos - name;
                // TODO: figure out how to do dynamically linked binaries with this
            }

            for (int i = 0; i < sesc; i++) {
                SymbolEntry *cse = ses[i];
                if (strncmp(cse->name, name, n) == 0) {
                    cse->offset = (uint64_t)(sym.st_value) - load_addr;
                    cse->section = sym.st_shndx;
                    /*printf("---\nSYMBOL TABLE ENTRY %zd\n", j);
                    printf("st_value = 0x%x\n", sym.st_value);
                    printf("st_shndx = %d\n", sym.st_shndx);
                    printf("st_name = %d", sym.st_name);
                    printf(" (%s)\n---\n", name);*/
                }
            }
        }
    }

    return 1;
}
