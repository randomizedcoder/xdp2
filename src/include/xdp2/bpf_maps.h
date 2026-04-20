/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2025 Tom Herbert
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __XDP2_BPF_MAPS_H__
#define __XDP2_BPF_MAPS_H__

/*
 * BTF-described BPF map declaration helpers.
 *
 * These macros emit the modern libbpf >= 1.0 typed-struct form
 * (SEC(".maps")) that the kernel's BTF-aware loader uses to derive key
 * and value types directly from DWARF/BTF. Prefer these for all new
 * XDP2 BPF code.
 *
 * The legacy bpf_elf_map helper in xdp2/bpf.h is retained for existing
 * samples (samples/xdp/flow_tracker_*, samples/xdp/af_xdp_parser) and
 * must not be used in new code — libbpf 1.x rejects it by default.
 *
 * Usage:
 *
 *   #include "xdp2/bpf_maps.h"
 *
 *   XDP2_MAP_PERCPU_ARRAY(ctx_map, __u32, struct my_ctx, 2);
 *   XDP2_MAP_PROG_ARRAY(jmp_table, 8);
 *   XDP2_MAP_HASH(conn_table, __u32, struct conn, 1024);
 *
 * Each expands to a typed-struct global with `SEC(".maps")`. libbpf
 * reads the BTF for these structs at load time; no .size_key /
 * .size_value fields needed.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Per-CPU array: one slot per CPU, indexed by key (typically __u32). */
#define XDP2_MAP_PERCPU_ARRAY(name, key_t, value_t, n)		\
	struct {						\
		__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);	\
		__type(key, key_t);				\
		__type(value, value_t);				\
		__uint(max_entries, n);				\
	} name SEC(".maps")

/* Plain array: shared across CPUs, indexed by __u32 key. */
#define XDP2_MAP_ARRAY(name, value_t, n)			\
	struct {						\
		__uint(type, BPF_MAP_TYPE_ARRAY);		\
		__type(key, __u32);				\
		__type(value, value_t);				\
		__uint(max_entries, n);				\
	} name SEC(".maps")

/* Program array for bpf_tail_call. Values are program file descriptors
 * (__u32); BTF types aren't used for PROG_ARRAY — use explicit sizes. */
#define XDP2_MAP_PROG_ARRAY(name, n)				\
	struct {						\
		__uint(type, BPF_MAP_TYPE_PROG_ARRAY);		\
		__uint(max_entries, n);				\
		__uint(key_size, sizeof(__u32));		\
		__uint(value_size, sizeof(__u32));		\
	} name SEC(".maps")

/* Hash map with typed key and value. */
#define XDP2_MAP_HASH(name, key_t, value_t, n)			\
	struct {						\
		__uint(type, BPF_MAP_TYPE_HASH);		\
		__type(key, key_t);				\
		__type(value, value_t);				\
		__uint(max_entries, n);				\
	} name SEC(".maps")

/* LRU hash — evicts least-recently-used entries when full. */
#define XDP2_MAP_LRU_HASH(name, key_t, value_t, n)		\
	struct {						\
		__uint(type, BPF_MAP_TYPE_LRU_HASH);		\
		__type(key, key_t);				\
		__type(value, value_t);				\
		__uint(max_entries, n);				\
	} name SEC(".maps")

/* Ring buffer — size in bytes, must be a power of two. */
#define XDP2_MAP_RINGBUF(name, size)				\
	struct {						\
		__uint(type, BPF_MAP_TYPE_RINGBUF);		\
		__uint(max_entries, size);			\
	} name SEC(".maps")

#endif /* __XDP2_BPF_MAPS_H__ */
