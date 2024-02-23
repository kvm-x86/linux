/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _TOOLS_LINUX_ASM_X86_KVM_HOST_H
#define _TOOLS_LINUX_ASM_X86_KVM_HOST_H

#include <stdbool.h>
#include <stdint.h>

struct kvm_vm_arch {
	uint64_t c_bit;
	uint64_t s_bit;
	int sev_fd;
	bool is_pt_protected;
};

static inline bool __vm_arch_has_protected_memory(struct kvm_vm_arch *arch)
{
	return arch->c_bit || arch->s_bit;
}

#define vm_arch_has_protected_memory(vm) \
	__vm_arch_has_protected_memory(&(vm)->arch)

#endif  // _TOOLS_LINUX_ASM_X86_KVM_HOST_H
