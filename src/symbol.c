#include "symbol.h"
#include "proc.h"
#include "logging.h"


#define _CHECK_BOUNDS(ptr, msg) { ASSERT((void *)(ptr) >= (void *)tbytes && (void *)(ptr) < (void *)tbytes + tfile_size, "invalid ELF; bounds check failed for " msg); }

SymbolEntry *lookup_symbols(HeaptraceContext *ctx, char *names[]) {
    // init list of symbolentries
    SymbolEntry *se_head = 0;
    SymbolEntry *cur_se = 0;
    int names_i = 0;
    while (names[names_i]) {
        SymbolEntry *se = (SymbolEntry *)calloc(1, sizeof(SymbolEntry));
        se->name = strdup(names[names_i]);
        se->type = SE_TYPE_UNRESOLVED;
        if (!se_head) {
            se_head = se;
        } else {
            cur_se->_next = se;
        }
        cur_se = se;
        names_i++;
    }
    if (!se_head) return 0;

    char **interp_name = &ctx->target_interp_name;
    char *fname = ctx->target_path;
    
    FILE *tfile = fopen(fname, "r");
    if (tfile == 0) {
        fatal("failed to open target.\n");
        exit(1);
        return 0;
    }
    if (fseek(tfile, 0, SEEK_END)) {
        fclose(tfile);
        fatal("failed to seek target.\n");
        exit(1);
        return 0;
    }
    long tfile_size = ftell(tfile);

    void *tbytes = mmap(0, (size_t)tfile_size, PROT_READ, MAP_PRIVATE, fileno(tfile), 0);

    if (tbytes == 0) {
        fclose(tfile);
        ASSERT(tbytes != 0, "mmap() failed in lookup_symbols");
        return 0;
    }

    fclose(tfile);

    const unsigned char expected_magic[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
    Elf64_Ehdr elf_hdr;
    memmove(&elf_hdr, tbytes, sizeof(elf_hdr));
    if (memcmp(elf_hdr.e_ident, expected_magic, sizeof(expected_magic)) != 0) {
        fatal("target is not an ELF executable.\n");
        exit(1);
        return 0;
    }
    if (elf_hdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fatal("target is not an ELF64 executable.\n");
        exit(1);
        return 0;
    }
    if (elf_hdr.e_machine != EM_X86_64) {
        fatal("target is not x86-64.\n");
        exit(1);
        return 0;
    }

    size_t string_index = elf_hdr.e_shstrndx;
    uint64_t string_offset;
    uint64_t load_addr = 0;
    uint64_t interp_addr = 0;
    char *cbytes = (char *)tbytes;
    for (uint16_t i = 0; i < elf_hdr.e_phnum; i++) {
        size_t offset = elf_hdr.e_phoff + i * elf_hdr.e_phentsize;
        Elf64_Phdr phdr;
        _CHECK_BOUNDS(tbytes + offset, "phdr: tbytes + offset");
        memmove(&phdr, tbytes + offset, sizeof(phdr));
        //if (phdr.p_type == PT_LOAD) { // XXX: not working TODO
        if (!i) {
            //printf("ELF load address is %p\n", phdr.p_vaddr);
            load_addr = phdr.p_vaddr;
        }

        if (phdr.p_type == PT_INTERP) {
            interp_addr = phdr.p_vaddr;
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
        _CHECK_BOUNDS(tbytes + offset, "string_offset: tbytes + offset");
        memmove(&shdr, tbytes + offset, sizeof(shdr));
        if (string_index == i) {
            string_offset = shdr.sh_offset;
            break;
        }
    }

    //if (interp_addr) _CHECK_BOUNDS(cbytes + interp_addr, "_interp_name: cbytes + interp_addr");
    char *_iptr = cbytes + interp_addr;
    if (!((void *)(_iptr) >= (void *)tbytes && (void *)(_iptr) < (void *)tbytes + tfile_size)) { _iptr = 0; interp_addr = 0; }; // XXX: strange bug. see ret2win bin in ~/ctf
    char *_interp_name = (interp_addr ? strdup(_iptr) : 0);
    *interp_name = _interp_name;

    // find .plt, symtab, .strtab offsets
    for (uint16_t i = 0; i < elf_hdr.e_shnum; i++) {
        size_t offset = elf_hdr.e_shoff + i * elf_hdr.e_shentsize;
        Elf64_Shdr shdr;
        _CHECK_BOUNDS(tbytes + offset, "shdr: tbytes + offset");
        memmove(&shdr, tbytes + offset, sizeof(shdr));
        _CHECK_BOUNDS(cbytes + string_offset + shdr.sh_name, "section_name: cbytes + string_offset + shdr.sh_name");
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

    // resolve dynamic (libc) symbols
    if (rela_dyn_off && dynstr_off && dynsym_off) {
        int rela_offsets_sz = (dynsym_sz / sizeof(Elf64_Sym)) + 1;
        size_t rela_offsets[rela_offsets_sz];
        for (int k = 0; k < rela_offsets_sz; k++) rela_offsets[k] = 0;

        for (size_t j = 0; j * sizeof(Elf64_Rela) < rela_dyn_sz; j++) {
            Elf64_Rela rela;
            size_t absoffset = rela_dyn_off + j * sizeof(Elf64_Rela);
            _CHECK_BOUNDS(cbytes + absoffset, "rela: cbytes + absoffset");
            memmove(&rela, cbytes + absoffset, sizeof(rela));
            //printf("rela libc: 0x%x (%d)\n", rela.r_offset, ELF64_R_SYM(rela.r_info));
            if (ELF64_R_TYPE(rela.r_info) == R_X86_64_GLOB_DAT) {
                unsigned int sym_i = ELF64_R_SYM(rela.r_info);
                ASSERT(sym_i < rela_offsets_sz, "rela: sym_i < rela_offsets_sz");
                rela_offsets[sym_i] = rela.r_offset;
            }
        }

        int ji = 0;
        for (size_t j = 0; j * sizeof(Elf64_Sym) < dynsym_sz; j++) {
            Elf64_Sym sym;
            size_t absoffset = dynsym_off + j * sizeof(Elf64_Sym);
            _CHECK_BOUNDS(cbytes + absoffset, "rela 2: cbytes + absoffset");
            memmove(&sym, cbytes + absoffset, sizeof(sym));
            
            if (sym.st_name != 0) {
                char *name = cbytes + dynstr_off + sym.st_name;
                _CHECK_BOUNDS(name, "rela: name"); // XXX: technically doesn't check if null-terminated. could read into memory if name wasn't null terminated
                size_t n = strlen(name);
                char *pos = strstr(name, "@GLIBC_"); // XXX: slightly hacky
                if (pos) {
                    n = pos - name;
                }

                SymbolEntry *cse = se_head;
                while (1) {
                    if (!cse) break;
                    if (((!cse->offset && rela_offsets[ji]) || cse->type == SE_TYPE_UNRESOLVED) && strcmp(cse->name, name) == 0) {
                        debug("rela dyn plt: st_name: %s @ 0x%x (%d) rela idx %d\n", name, rela_offsets[ji], sym.st_shndx, ji);
                        cse->type = SE_TYPE_DYNAMIC;
                        cse->offset = (uint64_t)rela_offsets[ji];
                        cse->section = sym.st_shndx;
                    }
                    cse = cse->_next;
                }
            }
            ji++;
        }
    }

    // resolve dynamic (plt) symbols
    // XXX/TODO: refactor to merge with the code block above
    if (rela_plt_off && dynstr_off && dynsym_off) {
        int rela_offsets_sz = (dynsym_sz / sizeof(Elf64_Sym)) + 1;
        size_t rela_offsets[rela_offsets_sz];
        for (int k = 0; k < rela_offsets_sz; k++) rela_offsets[k] = 0;

        for (size_t j = 0; j * sizeof(Elf64_Rela) < rela_plt_sz; j++) {
            Elf64_Rela rela;
            size_t absoffset = rela_plt_off + j * sizeof(Elf64_Rela);
            _CHECK_BOUNDS(cbytes + absoffset, ".plt: cbytes + absoffset");
            memmove(&rela, cbytes + absoffset, sizeof(rela));
            //printf("rela plt: 0x%x (sym=%d, type=%d)\n", rela.r_offset, ELF64_R_SYM(rela.r_info), ELF64_R_TYPE(rela.r_info));
            if (ELF64_R_TYPE(rela.r_info) == R_X86_64_JUMP_SLOT) {
                int sym_i = ELF64_R_SYM(rela.r_info);
                ASSERT(sym_i < rela_offsets_sz, ".plt: sym_i < rela_offsets_sz");
                rela_offsets[sym_i] = rela.r_offset;
            }
        }


        int ji = 0;
        for (size_t j = 0; j * sizeof(Elf64_Sym) < dynsym_sz; j++) {
            Elf64_Sym sym;
            size_t absoffset = dynsym_off + j * sizeof(Elf64_Sym);
            _CHECK_BOUNDS(cbytes + absoffset, ".plt 2: cbytes + absoffset");
            memmove(&sym, cbytes + absoffset, sizeof(sym));
            
            if (sym.st_name != 0) {
                char *name = cbytes + dynstr_off + sym.st_name;
                _CHECK_BOUNDS(name, ".plt: name");
                size_t n = strlen(name);
                char *pos = strstr(name, "@GLIBC_"); // XXX: slightly hacky
                if (pos) {
                    n = pos - name;
                }

                SymbolEntry *cse = se_head;
                while (1) {
                    if (!cse) break;
                    if (((!cse->offset && rela_offsets[ji]) || cse->type == SE_TYPE_UNRESOLVED) && strcmp(cse->name, name) == 0) {
                        debug("dyn plt: st_name: %s @ 0x%x (%d) rela idx %d\n", name, rela_offsets[ji], sym.st_shndx, ji);
                        cse->type = SE_TYPE_DYNAMIC_PLT;
                        cse->offset = (uint64_t)rela_offsets[ji];
                        cse->section = sym.st_shndx;
                    }
                    cse = cse->_next;
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
            _CHECK_BOUNDS(cbytes + absoffset, "static: cbytes + absoffset");
            memmove(&sym, cbytes + absoffset, sizeof(sym));
            if (sym.st_name != 0) {
                char *name = cbytes + strtab_off + sym.st_name;
                _CHECK_BOUNDS(name, "static: name");
                size_t n = strlen(name);

                SymbolEntry *cse = se_head;
                while (1) {
                    if (!cse) break;
                    if (((!cse->offset && sym.st_value) || cse->type == SE_TYPE_UNRESOLVED) && strcmp(cse->name, name) == 0) {
                        debug("tab: st_name: %s @ 0x%x\n", name, sym.st_value);
                        cse->type = SE_TYPE_STATIC;
                        cse->offset = (uint64_t)(sym.st_value) - load_addr;
                        cse->section = sym.st_shndx;
                    }
                    cse = cse->_next;
                }
            }
        }
    }

    return se_head;
}


SymbolEntry *any_se_type(SymbolEntry *se_head, int type) {
    SymbolEntry *cse = se_head;
    while (cse) {
        if (cse->type == type) {
            return cse;
        }
        cse = cse->_next;
    }
    return 0;
}


int all_se_type(SymbolEntry *se_head, int type) {
    SymbolEntry *cse = se_head;
    while (cse) {
        if (cse->type != type) {
            return 0;
        }
        cse = cse->_next;
    }
    return 1;
}


SymbolEntry *find_se_name(SymbolEntry *se_head, char *name) {
    SymbolEntry *cse = se_head;
    while (cse) {
        if (!strcmp(cse->name, name)) {
            return cse;
        }
        cse = cse->_next;
    }
}


void free_se(SymbolEntry *se_head) {
    SymbolEntry *cse = se_head;
    while (1) {
        if (!cse) break;
        SymbolEntry *next_cse = cse->_next;
        free(cse->name);
        free(cse);
        cse = next_cse;
    }
}
