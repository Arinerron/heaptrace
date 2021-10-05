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

    size_t string_index = elf_hdr.e_shstrndx;
    uint64_t string_offset;
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

    size_t strtab_off = 0;
    size_t symtab_off = 0;
    size_t symtab_sz = 0;
    size_t dynstr_off = 0;
    size_t dynsym_off = 0;
    size_t dynsym_sz = 0;
    size_t rela_dyn_off = 0;
    size_t rela_dyn_sz = 0;
    size_t rela_plt_off = 0;
    size_t rela_plt_sz = 0;

    // find sh_offset of string_index
    for (uint16_t i = 0; i < elf_hdr.e_shnum; i++) {
        size_t offset = elf_hdr.e_shoff + i * elf_hdr.e_shentsize;
        Elf64_Shdr shdr;
        memmove(&shdr, tbytes + offset, sizeof(shdr));
        if (string_index == i) {
            string_offset = shdr.sh_offset;
            break;
        }
    }

    // find .plt, symtab, .strtab offsets
    for (uint16_t i = 0; i < elf_hdr.e_shnum; i++) {
        size_t offset = elf_hdr.e_shoff + i * elf_hdr.e_shentsize;
        Elf64_Shdr shdr;
        memmove(&shdr, tbytes + offset, sizeof(shdr));
        char *section_name = cbytes + string_offset + shdr.sh_name;
        //printf("section: %s\n", section_name);

        if (!strcmp(section_name, ".symtab")) {
            symtab_off = shdr.sh_offset;
            symtab_sz = shdr.sh_size;
        } else if (!strcmp(section_name, ".strtab")) {
            strtab_off = shdr.sh_offset;
        } else if (!strcmp(section_name, ".dynsym")) {
            dynsym_off = shdr.sh_offset;
            dynsym_sz = shdr.sh_size;
        } else if (!strcmp(section_name, ".dynstr")) {
            dynstr_off = shdr.sh_offset;
        } else if (!strcmp(section_name, ".rela.dyn")) {
            rela_dyn_off = shdr.sh_offset;
            rela_dyn_sz = shdr.sh_size;
        } else if (!strcmp(section_name, ".rela.plt")) {
            rela_plt_off = shdr.sh_offset;
            rela_plt_sz = shdr.sh_size;
        }
    }

    // reset symbol entries
    for (int i = 0; i < sesc; i++) {
        SymbolEntry *cse = ses[i];
        cse->type = SE_TYPE_UNRESOLVED;
    }

    // resolve dynamic (libc) symbols
    if (rela_dyn_off && dynstr_off && dynsym_off) {
        size_t rela_offsets[(dynsym_sz / sizeof(Elf64_Sym)) + 1];
        for (int k = 0; k < (dynsym_sz / sizeof(Elf64_Sym)) + 1; k++) rela_offsets[k] = 0;

        for (size_t j = 0; j * sizeof(Elf64_Rela) < rela_dyn_sz; j++) {
            Elf64_Rela rela;
            size_t absoffset = rela_dyn_off + j * sizeof(Elf64_Rela);
            memmove(&rela, cbytes + absoffset, sizeof(rela));
            //printf("rela libc: 0x%x (%d)\n", rela.r_offset, ELF64_R_SYM(rela.r_info));
            if (ELF64_R_TYPE(rela.r_info) == R_X86_64_GLOB_DAT) {
                int sym_i = ELF64_R_SYM(rela.r_info);
                rela_offsets[sym_i] = rela.r_offset;
            }
        }

        int ji = 0;
        for (size_t j = 0; j * sizeof(Elf64_Sym) < dynsym_sz; j++) {
            Elf64_Sym sym;
            size_t absoffset = dynsym_off + j * sizeof(Elf64_Sym);
            memmove(&sym, cbytes + absoffset, sizeof(sym));
            
            if (sym.st_name != 0) {
                char *name = cbytes + dynstr_off + sym.st_name;
                size_t n = strlen(name);
                char *pos = strstr(name, "@GLIBC_"); // XXX: slightly hacky
                if (pos) {
                    n = pos - name;
                }

                for (int i = 0; i < sesc; i++) {
                    SymbolEntry *cse = ses[i];
                    if (((!cse->offset && rela_offsets[ji]) || cse->type == SE_TYPE_UNRESOLVED) && strncmp(cse->name, name, n) == 0) {
                        //printf("rela dyn plt: st_name: %s @ 0x%x (%d) rela idx %d\n", name, rela_offsets[ji], sym.st_shndx, ji);
                        cse->type = SE_TYPE_DYNAMIC;
                        cse->offset = (uint64_t)rela_offsets[ji];
                        cse->section = sym.st_shndx;
                    }
                }
            }
            ji++;
        }
    }

    // resolve dynamic (plt) symbols
    // XXX/TODO: refactor to merge with the code block above
    if (rela_plt_off && dynstr_off && dynsym_off) {
        size_t rela_offsets[(dynsym_sz / sizeof(Elf64_Sym)) + 1];
        for (int k = 0; k < (dynsym_sz / sizeof(Elf64_Sym)) + 1; k++) rela_offsets[k] = 0;

        for (size_t j = 0; j * sizeof(Elf64_Rela) < rela_plt_sz; j++) {
            Elf64_Rela rela;
            size_t absoffset = rela_plt_off + j * sizeof(Elf64_Rela);
            memmove(&rela, cbytes + absoffset, sizeof(rela));
            //printf("rela plt: 0x%x (sym=%d, type=%d)\n", rela.r_offset, ELF64_R_SYM(rela.r_info), ELF64_R_TYPE(rela.r_info));
            if (ELF64_R_TYPE(rela.r_info) == R_X86_64_JUMP_SLOT) {
                int sym_i = ELF64_R_SYM(rela.r_info);
                rela_offsets[sym_i] = rela.r_offset;
                //printf("@6: %p\n", rela_offsets[6]);
            }
        }


        int ji = 0;
        for (size_t j = 0; j * sizeof(Elf64_Sym) < dynsym_sz; j++) {
            Elf64_Sym sym;
            size_t absoffset = dynsym_off + j * sizeof(Elf64_Sym);
            memmove(&sym, cbytes + absoffset, sizeof(sym));
            
            if (sym.st_name != 0) {
                char *name = cbytes + dynstr_off + sym.st_name;
                size_t n = strlen(name);
                char *pos = strstr(name, "@GLIBC_"); // XXX: slightly hacky
                if (pos) {
                    n = pos - name;
                }

                for (int i = 0; i < sesc; i++) {
                    SymbolEntry *cse = ses[i];
                    if (((!cse->offset && rela_offsets[ji]) || cse->type == SE_TYPE_UNRESOLVED) && strncmp(cse->name, name, n) == 0) {
                        //printf("dyn plt: st_name: %s @ 0x%x (%d) rela idx %d\n", name, rela_offsets[ji], sym.st_shndx, ji);
                        cse->type = SE_TYPE_DYNAMIC;
                        cse->offset = (uint64_t)rela_offsets[ji];
                        cse->section = sym.st_shndx;
                    }
                }
            }
            ji++;
        }
    }

    // resolve static symbols
    if (strtab_off && symtab_off) {
        for (size_t j = 0; j * sizeof(Elf64_Sym) < symtab_sz; j++) {
            Elf64_Sym sym;
            size_t absoffset = symtab_off + j * sizeof(Elf64_Sym);
            memmove(&sym, cbytes + absoffset, sizeof(sym));
            if (sym.st_name != 0) {
                char *name = cbytes + strtab_off + sym.st_name;
                size_t n = strlen(name);
                for (int i = 0; i < sesc; i++) {
                    SymbolEntry *cse = ses[i];
                    if (((!cse->offset && sym.st_value) || cse->type == SE_TYPE_UNRESOLVED) && strncmp(cse->name, name, n) == 0) {
                        //printf("tab: st_name: %s @ 0x%x\n", name, sym.st_value);
                        cse->type = SE_TYPE_STATIC;
                        cse->offset = (uint64_t)(sym.st_value) - load_addr;
                        cse->section = sym.st_shndx;
                    }
                }
            }
        }
    }

    return 1;
}
