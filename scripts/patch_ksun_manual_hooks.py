#!/usr/bin/env python3
import sys

def replace_once(path, old, new, label):
    s=open(path).read()
    if new.strip() in s:
        print(f"{label}: already patched")
        return
    if old not in s:
        raise SystemExit(f"{label}: anchor not found in {path}")
    s=s.replace(old,new,1)
    open(path,"w").write(s)
    print(f"{label}: patched")

# fs/exec.c
p="fs/exec.c"
s=open(p).read()
if "ksu_handle_execveat" not in s:
    anchor="""static int do_execveat_common(int fd, struct filename *filename,
			      struct user_arg_ptr argv,
			      struct user_arg_ptr envp,
			      int flags)
{
	return __do_execve_file(fd, filename, argv, envp, flags, NULL);
}
"""
    new="""#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
				void *argv, void *envp, int *flags);
#endif

static int do_execveat_common(int fd, struct filename *filename,
			      struct user_arg_ptr argv,
			      struct user_arg_ptr envp,
			      int flags)
{
#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
#endif
	return __do_execve_file(fd, filename, argv, envp, flags, NULL);
}
"""
    if anchor not in s: raise SystemExit("exec hook anchor not found")
    open(p,"w").write(s.replace(anchor,new,1))

# fs/open.c
p="fs/open.c"; s=open(p).read()
if "ksu_handle_faccessat" not in s:
    marker="SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n{\n"
    repl="""#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
				int *mode, int *flags);
#endif

SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
{
"""
    if marker not in s: raise SystemExit("faccessat hook anchor not found")
    s=s.replace(marker,repl,1)
    marker2="	unsigned int lookup_flags = LOOKUP_FOLLOW;\n"
    if marker2 not in s: raise SystemExit("faccessat lookup anchor not found")
    s=s.replace(marker2, marker2+"#ifdef CONFIG_KSU_MANUAL_HOOK\n\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n#endif\n",1)
    open(p,"w").write(s)

# kernel/reboot.c
p="kernel/reboot.c"; s=open(p).read()
if "ksu_handle_sys_reboot" not in s:
    marker="SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,\n\t\tvoid __user *, arg)\n{\n"
    repl="""#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
#endif

SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
		void __user *, arg)
{
#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
#endif
"""
    if marker not in s: raise SystemExit("reboot hook anchor not found")
    open(p,"w").write(s.replace(marker,repl,1))

# fs/stat.c minimal stat hook
p="fs/stat.c"; s=open(p).read()
if "ksu_handle_stat" not in s:
    marker="SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,\n\t\tstruct stat __user *, statbuf, int, flag)\n{\n"
    repl="""#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
#endif

SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
		struct stat __user *, statbuf, int, flag)
{
#ifdef CONFIG_KSU_MANUAL_HOOK
	ksu_handle_stat(&dfd, &filename, &flag);
#endif
"""
    if marker not in s: raise SystemExit("stat hook anchor not found")
    open(p,"w").write(s.replace(marker,repl,1))

for path,sym in [("fs/stat.c","ksu_handle_stat"),("fs/exec.c","ksu_handle_execveat"),("fs/open.c","ksu_handle_faccessat"),("kernel/reboot.c","ksu_handle_sys_reboot")]:
    if sym not in open(path).read():
        raise SystemExit(f"{sym} missing in {path}")
print("manual hooks applied")
