
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

struct jump_op {
#define JUMP_OP_OPCODE_DYNAMIC	0xff
	unsigned int opcode;

	unsigned long from;
	unsigned int len;
	unsigned long to;

#define JUMP_OP_DYNAMIC_REG_REF	0x80
	unsigned int dynamic_reg;
	unsigned int dynamic_sib_mult;
	unsigned int dynamic_sib_reg;

	unsigned int dynamic_disp32;
};


/* TODO(pboldin): This code should be a part of objtool-coverage library */
static int parse_jump_op(struct jump_op *jcc,
			 const char *in)
{
	int ret, len;
	const char *p = in;

	ret = sscanf(p, "0x%x 0x%lx+0x%x %n",
		     &jcc->opcode,
		     &jcc->from,
		     &jcc->len,
		     &len);
	if (ret != 3)
		return -1;

	p += len;

	ret = sscanf(p, "0x%lx", &jcc->to);
	if (ret == 1)
		return 0;

	jcc->to = 0;
	ret = sscanf(p, "*0x%x(%d, %d, %d)",
		     &jcc->dynamic_disp32,
		     &jcc->dynamic_reg,
		     &jcc->dynamic_sib_reg,
		     &jcc->dynamic_sib_mult);
	if (ret == 4)
		goto check_dynamic_ref;

	ret = sscanf(p, "*0x%x(%d)",
		     &jcc->dynamic_disp32,
		     &jcc->dynamic_reg);
	if (ret == 2)
		goto check_dynamic_ref;

	ret = sscanf(p, "*%d",
		     &jcc->dynamic_reg);
	if (ret == 1)
		goto check_dynamic_jump;

	return -1;

check_dynamic_ref:
	jcc->dynamic_reg |= JUMP_OP_DYNAMIC_REG_REF;
check_dynamic_jump:
	if (jcc->opcode != JUMP_OP_OPCODE_DYNAMIC)
		return -1;

	return 0;
}

struct tracepoint {
	struct jump_op jcc;
	void *origcode;
};

static int read_input_file(const char *filename,
			   struct tracepoint **points,
			   size_t *npoints)
{
	FILE *fh;
	char buf[1024];
	struct tracepoint *t = NULL, tmp;
	size_t n = 0, nalloc = 0;
	int ret;

	*points = NULL;
	*npoints = 0;

	if (!strcmp(filename, "-"))
		fh = stdin;
	else
		fh = fopen(filename, "r");

	if (fh == NULL) {
		perror("fopen");
		return -1;
	}

	while (!feof(fh)) {
		fgets(buf, sizeof(buf), fh);
		ret = parse_jump_op(&tmp.jcc, buf);
		if (ret < 0) {
			fprintf(stderr, "can't parse %s\n", buf);
			goto out_err;
		}

		if (n + 1 > nalloc) {
			struct tracepoint *newt;

			nalloc = nalloc ? nalloc * 2 : 16;
			newt = realloc(t, sizeof(*t) * nalloc);
			if (newt == NULL) {
				ret = -1;
				goto out_err;
			}

			t = newt;
		}

		t[n] = tmp;
		n++;
	}

	*points = t;
	*npoints = n;

out_err:
	if (ret < 0)
		free(t);
	if (fh != stdin)
		fclose(fh);
	return ret;
}

static int install_trace_points(int pid, struct tracepoint *tpoints, size_t npoints)
{
	int memfd = -1, ret = -1;
	char path[1024];
	struct tracepoint *p;
	size_t i;

	sprintf(path, "/proc/%d/mem", pid);
	memfd = open(path, O_RDWR);
	if (memfd < 0) {
		perror("open");
		goto out;
	}

	for (i = 0, p = tpoints; i < npoints; i++, p++) {
		ret = pwrite(memfd, "\xcc", 1, p->jcc.from);
		if (ret < 0)
			perror("pwrite");
	}

	ret = 0;
out:
	if (memfd != -1)
		close(memfd);
	return ret;
}

static int attach_to_process(char * const *argv)
{
	int ret, status;
	pid_t pid, waited;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	} else if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		return execvp(argv[0], argv + 1);
	}

	ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (ret < 0) {
		perror("ptrace");
		return -1;
	}

	while (1) {
		waited = waitpid(pid, &status, 0);

		if (WIFSTOPPED(status) &&
		    WSTOPSIG(status) == SIGSTOP)
			break;

		ret = ptrace(PTRACE_CONT, pid, NULL,
			     (void *)(uintptr_t)WTERMSIG(status));
		if (ret < 0) {
			perror("ptrace");
		}
	}

	return pid;
}

static int start_process(int pid)
{
}

int main(int argc, char * const argv[])
{
	struct tracepoint *tpoints;
	size_t npoints;
	int ret;
	int pid;

	ret = read_input_file(argv[1], &tpoints, &npoints);
	if (ret < 0)
		return -1;

	pid = attach_to_process(argv + 2);
	ret = install_trace_points(pid, tpoints, npoints);
	if (ret < 0) {
		fprintf(stderr, "install_trace_points\n");
	}
	start_process(pid);
}
