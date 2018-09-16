/*
 * Copyright (C) 2015-2017 Josh Poimboeuf <jpoimboe@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "builtin.h"
#include "check.h"
#include "coverage.h"
#include "elf.h"
#include "special.h"
#include "arch.h"
#include "warn.h"

#include <linux/hashtable.h>
#include <linux/kernel.h>

static int print_jump_instruction_dynamic(struct section *sec,
					  struct instruction *insn)
{
	bool is_ref = insn->jcc.dynamic_reg & JUMP_OP_DYNAMIC_REG_REF;
	bool is_sib = insn->jcc.dynamic_sib_mult;
	unsigned char reg = insn->jcc.dynamic_reg & ~JUMP_OP_DYNAMIC_REG_REF;

	if (insn->jcc.opcode != JUMP_OP_OPCODE_DYNAMIC) {
		WARN("dynamic jump with opcode != %x", JUMP_OP_OPCODE_DYNAMIC);
		return -1;
	}

	if (!is_ref) {
		printf("*%d", insn->jcc.dynamic_reg);
		return 0;
	}

	if (!is_sib) {
		printf("*0x%x(%d)", insn->jcc.dynamic_disp32, reg);
		return 0;
	}

	printf("*0x%x(%d, %d, %d)",
	       insn->jcc.dynamic_disp32,
	       reg,
	       insn->jcc.dynamic_sib_reg,
	       insn->jcc.dynamic_sib_mult);

	return 0;
}

static int print_jump_instruction(struct section *sec,
				  struct instruction *insn)
{
	if (insn->jump_dest == NULL &&
	    insn->type != INSN_JUMP_DYNAMIC)
		return 0;

	printf("0x%x\t0x%016lx+0x%08x\t",
	       insn->jcc.opcode,
	       sec->sh.sh_addr + insn->offset,
	       insn->len);

	if (insn->jump_dest) {
		struct instruction *dest = insn->jump_dest;

		printf("0x%016lx\t", dest->sec->sh.sh_addr + dest->offset);
	} else if (insn->type == INSN_JUMP_DYNAMIC) {
		print_jump_instruction_dynamic(sec, insn);
	} else {
		return -1;
	}

	printf("\n");
	return 0;
}

static int validate_functions(struct objtool_file *file)
{
	struct section *sec;
	struct instruction *insn;
	int ret;
	char buf[1024];
	size_t n;

	n = readlink(objname, buf, sizeof(buf));
	buf[n] = '\0';
	printf("# objname=%s\n", basename(buf));

	for_each_sec(file, sec) {
		if (!(sec->sh.sh_flags & SHF_EXECINSTR))
			continue;

		if (!no_kpatch && !strstr(sec->name, "kpatch"))
			continue;

		sec_for_each_insn(file, sec, insn) {
			switch (insn->type) {
			case INSN_JUMP_CONDITIONAL:
			case INSN_JUMP_UNCONDITIONAL:
			case INSN_JUMP_DYNAMIC:
				break;
			default:
				continue;
			}

			ret = print_jump_instruction(sec, insn);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

int coverage(const char *_objname)
{
	struct objtool_file file;
	int ret, warnings = 0;

	objname = _objname;

	file.elf = elf_open(objname, O_RDONLY);
	if (!file.elf)
		return 1;

	INIT_LIST_HEAD(&file.insn_list);
	hash_init(file.insn_hash);
	file.whitelist = find_section_by_name(file.elf, ".discard.func_stack_frame_non_standard");
	file.rodata = find_section_by_name(file.elf, ".rodata");
	file.c_file = find_section_by_name(file.elf, ".comment");
	file.ignore_unreachables = no_unreachable;
	file.hints = false;

	ret = decode_sections(&file);
	if (ret < 0)
		goto out;
	warnings += ret;

	if (list_empty(&file.insn_list))
		goto out;

	ret = validate_functions(&file);
	if (ret < 0)
		goto out;
	warnings += ret;

out:
	cleanup(&file);

	/* ignore warnings for now until we get all the code cleaned up */
	if (ret || warnings)
		return 0;
	return 0;
}
