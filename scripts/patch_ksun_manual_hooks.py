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
    marker="""static int do_execveat_common(int fd, struct filename *filename,
			      struct user_arg_ptr argv,
			      struct user_arg_ptr envp,
			      int flags)
{
"""
    repl="""#ifdef CONFIG_KSU_MANUAL_HOOK
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
"""
    if marker not in s: raise SystemExit("exec hook function anchor not found")
    open(p,"w").write(s.replace(marker,repl,1))

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


# KernelSU Next v3.4.0-legacy checks hook mode even during mrproper, before
# floral_defconfig is loaded. Teach its Kbuild to accept our verified coral
# manual hook marker directly.
p="drivers/kernelsu/Kbuild"
s=open(p).read()
needle='''ifeq ($(CONFIG_KSU_MANUAL_HOOK), y)
HAVE_KSU_HOOK := $(shell grep -q "ksu_handle_sys_reboot" $(srctree)/kernel/reboot.c && echo 0 || echo 1)
ifeq ($(HAVE_KSU_HOOK),0)
$(info -- KernelSU-Next: Hook mode: Manual)
endif
endif
'''
repl='''ifeq ($(CONFIG_KSU_MANUAL_HOOK), y)
HAVE_KSU_HOOK := $(shell grep -q "ksu_handle_sys_reboot" $(srctree)/kernel/reboot.c && echo 0 || echo 1)
ifeq ($(HAVE_KSU_HOOK),0)
$(info -- KernelSU-Next: Hook mode: Manual)
endif
endif

# Coral 4.14 build invokes mrproper before .config exists. If the manual
# reboot hook is already present, accept manual-hook mode for the clean pass.
ifeq ($(HAVE_KSU_HOOK),1)
HAVE_KSU_HOOK := $(shell grep -q "ksu_handle_sys_reboot" $(srctree)/kernel/reboot.c && echo 0 || echo 1)
ifeq ($(HAVE_KSU_HOOK),0)
$(info -- KernelSU-Next: Hook mode: Manual (coral source marker))
endif
endif
'''
if needle not in s:
    raise SystemExit("KernelSU Kbuild manual-hook block not found")
open(p,"w").write(s.replace(needle,repl,1))
print("KernelSU Kbuild clean-pass hook check patched")
