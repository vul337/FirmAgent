#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/prctl.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mount.h>

bool write_file(const char* file, const char* what, ...)
{
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);

	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

pid_t clean_fork(void)
{
	pid_t pid = fork();
	if(pid) return pid;

	int ret = prctl(PR_SET_PDEATHSIG, SIGKILL);
	assert(ret == 0);
	return pid;
}

void setup_sandbox()
{
	if (unshare(CLONE_NEWPID | CLONE_NEWNS) != 0) {
		perror("[-] unshare");
		exit(EXIT_FAILURE);
	}
}

//void fix_mount()
//{
//	int ret;
//
//	// fix /proc
//	ret = mount("none", "/proc", NULL, MS_PRIVATE|MS_REC, NULL);
//	assert(ret == 0);
//	ret = mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
//	assert(ret == 0);
//}

int main(int argc, char** argv, char** env)
{
	if(argc <= 1) {
		puts("usage: unshare_pid <argv>");
		exit(-1);
	}

	setup_sandbox();

	if(!clean_fork()) {
		//fix_mount();
		execve(argv[1], &argv[1], env);
		perror("[sandbox]");
		exit(0);
	}
	wait(NULL);
}
