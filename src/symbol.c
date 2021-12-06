#include "symbol.h"
#include "proc.h"
#include "logging.h"


#define _CHECK_BOUNDS(ptr, msg) { ASSERT((void *)(ptr) >= (void *)tbytes && (void *)(ptr) < (void *)tbytes + tfile_size, "invalid ELF; bounds check failed for " msg); }

uint lookup_symbols(HeaptraceFile *hf, char *names[]) {
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
    if (!se_head) {
        free(hf->se_head);
        hf->se_head = 0;
        return 0;
    }

    FILE *tfile = fopen(hf->path, "r");
    if (tfile == 0) {
        fatal("failed to open target.\n");
        free(hf->se_head);
        hf->se_head = 0;
        return 0;
    }
    if (fseek(tfile, 0, SEEK_END)) {
        fclose(tfile);
        fatal("failed to seek target.\n");
        free(hf->se_head);
        hf->se_head = 0;
        return 0;
    }
    long tfile_size = ftell(tfile);

    void *tbytes = mmap(0, (size_t)tfile_size, PROT_READ, MAP_PRIVATE, fileno(tfile), 0);

    if (tbytes == 0) {
        fclose(tfile);
        ASSERT(tbytes != 0, "mmap() failed in lookup_symbols");
        free(hf->se_head);
        hf->se_head = 0;
        return 0;
    }

    fclose(tfile);

    const unsigned char expected_magic[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
    Elf64_Ehdr elf_hdr;
    memmove(&elf_hdr, tbytes, sizeof(elf_hdr));
    if (memcmp(elf_hdr.e_ident, expected_magic, sizeof(expected_magic)) != 0) {
        fatal("target is not an ELF executable.\n");
        free(hf->se_head);
        hf->se_head = 0;
        return 0;
    }
    if (elf_hdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fatal("target is not an ELF64 executable.\n");
        free(hf->se_head);
        hf->se_head = 0;
        return 0;
    }
    if (elf_hdr.e_machine != EM_X86_64) {
        fatal("target is not x86-64.\n");
        free(hf->se_head);
        hf->se_head = 0;
        return 0;
    }

    size_t string_index = elf_hdr.e_shstrndx;
    uint64_t string_offset;
    uint64_t load_addr = 0;
    char *cbytes = (char *)tbytes;
    uint is_dynamic = 0;
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

        // if this section is present, this binary is dynamically-linked.
        if (phdr.p_type == PT_INTERP) {
            is_dynamic = 1;
        }
    }

    uint is_stripped = 1;
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
                ASSERT(sym_i < rela_offsets_sz, "rela");
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
                        debug("rela dyn plt: st_name: %s @ " U64T " (%d) rela idx %d\n", name, (uint64_t)rela_offsets[ji], sym.st_shndx, ji);
                        cse->type = SE_TYPE_DYNAMIC;
                        cse->offset = (uint64_t)rela_offsets[ji];
                        cse->section = sym.st_shndx;
                        if (cse->offset) is_stripped = 0;
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
                ASSERT(sym_i < rela_offsets_sz, ".plt");
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
                        debug("dyn plt: st_name: %s @ " U64T " (shndx=%d) rela idx %d\n", name, (uint64_t)rela_offsets[ji], sym.st_shndx, ji);
                        cse->type = SE_TYPE_DYNAMIC_PLT;
                        cse->offset = (uint64_t)rela_offsets[ji];
                        cse->section = sym.st_shndx;
                        if (cse->offset) is_stripped = 0;
                    }
                    cse = cse->_next;
                }
            }
            ji++;
        }
    }

    // resolve static symbols
    SymbolEntry *all_static_se_head = 0;
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

                uint64_t offset = (uint64_t)(sym.st_value);
                // XXX: for some reason libc has a load addr of 0x40 that's throwing stuff off. This is a stopgap solution for that.
                if (!is_dynamic) offset -= load_addr;

                SymbolEntry *cse = se_head;
                while (1) {
                    if (!cse) break;
                    if (((!cse->offset && sym.st_value) || cse->type == SE_TYPE_UNRESOLVED) && strcmp(cse->name, name) == 0) {
                        debug("tab: st_name: %s @ " U64T "\n", name, (uint64_t)sym.st_value);
                        cse->type = SE_TYPE_STATIC;
                        cse->offset = offset;
                        cse->_sub_offset = 0;
                        cse->size = sym.st_size;
                        cse->section = sym.st_shndx;
                        if (sym.st_value) is_stripped = 0;
                    }
                    cse = cse->_next;
                }

                // now add to all_static_se_head
                SymbolEntry *_cur_static_se = (SymbolEntry *)calloc(1, sizeof(SymbolEntry));
                _cur_static_se->_next = all_static_se_head;
                all_static_se_head = _cur_static_se;

                _cur_static_se->name = strdup(name);
                _cur_static_se->offset = offset;
                _cur_static_se->size = sym.st_size;
                _cur_static_se->_sub_offset = 0;
                _cur_static_se->type = SE_TYPE_STATIC;
                _cur_static_se->section = sym.st_shndx;

                //printf("%s\toffset=%p, size=%p\n", _cur_static_se->name, _cur_static_se->offset, _cur_static_se->size);
            }
        }
    }

    hf->all_static_se_head = all_static_se_head;
    hf->se_head = se_head;
    hf->is_stripped = is_stripped;
    hf->is_dynamic = is_dynamic;
    return 1;
}


SymbolEntry *find_symbol_by_address(HeaptraceFile *hf, uint64_t addr) {
    if (!(hf->pme) || addr < hf->pme->base || addr >= hf->pme->end) return 0; // not in bounds
    addr -= hf->pme->base;
    
    SymbolEntry *cur_se = hf->all_static_se_head;
    while(cur_se) {
        //printf("... %s\taddr=%p, offset=%p, offset+size=%p\n", cur_se->name, addr, cur_se->offset, cur_se->offset + cur_se->size);
        if (addr >= cur_se->offset && addr < cur_se->offset + cur_se->size) return cur_se;
        cur_se = cur_se->_next;
    }

    return 0;
}


HeaptraceFile *find_heaptrace_file_by_address(HeaptraceContext *ctx, uint64_t addr) {
    HeaptraceFile *hfs[] = {ctx->target, ctx->libc};
    HeaptraceFile *cur_hf;
    for (int i = 0; i < sizeof(hfs) / sizeof(hfs[0]); i++) {
        cur_hf = hfs[i];
        if (cur_hf->pme && addr >= cur_hf->pme->base && addr < cur_hf->pme->end) {
            return cur_hf;
        }
    }
    return 0;
}


char *find_symbol_name_by_address(HeaptraceContext *ctx, uint64_t addr) {
    HeaptraceFile *hf = find_heaptrace_file_by_address(ctx, addr);
    if (!hf) return 0;
    SymbolEntry *se = find_symbol_by_address(hf, addr);
    if (!se) return 0;
    return se->name;
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
    return NULL;
}


void free_se_list(SymbolEntry *se_head) {
    SymbolEntry *cse = se_head;
    while (1) {
        if (!cse) break;
        SymbolEntry *next_cse = cse->_next;
        free(cse->name);
        free(cse);
        cse = next_cse;
    }
}


char *get_source_function(HeaptraceContext *ctx) {
    char *section = "<unknown>";
    if (OPT_VERBOSE) {
        switch (ctx->h_ret_ptr_section_type) {
            case PROCELF_TYPE_LIBC:
                section = "libc";
                break;
            case PROCELF_TYPE_UNKNOWN:
                section = "<library>";
                break;
            case PROCELF_TYPE_BINARY:
                section = 0;
                break;
        }
    }

    char *symbol_name = find_symbol_name_by_address(ctx, ctx->h_ret_ptr);
    size_t buf_size = 2;
    if (symbol_name) buf_size += strlen(symbol_name);
    if (section) buf_size += 1 + strlen(section);

    char *buf = calloc(1, buf_size);
    if (symbol_name) strcat(buf, symbol_name);
    if (symbol_name && section) strcat(buf, "@");
    if (section) strcat(buf, section);

    if (!strlen(buf)) {
        free(buf);
        buf = strdup("binary"); // this is the only way `section` can be NULL
    }

    return buf;
}
