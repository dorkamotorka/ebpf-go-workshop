//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define NUM_LOOPS 100

SEC("xdp")
int xdp_prog_for_loop(struct xdp_md *ctx) {
  int counter = 0;

  // Add the looping logic here
  
  // The `counter` variable can then be inspected using `bpftool prog trace`
  bpf_printk("Counted %dx times", counter);

  return XDP_PASS;
}

/* -> bpf_loop helper function */

static long (*const bpf_loop)(__u32 nr_loops, void *callback_fn,
                              void *callback_ctx, __u64 flags) = (void *)181;

// Define the callback function for bpf_loop
static int increment_counter(void *ctx, int *counter) {
  (*counter)++;
  bpf_printk("Counting...");
  return 0;
}

/* -> bpf_for helper function */

extern int bpf_iter_num_new(struct bpf_iter_num *it, int start,
                            int end) __weak __ksym;
extern int *bpf_iter_num_next(struct bpf_iter_num *it) __weak __ksym;
extern void bpf_iter_num_destroy(struct bpf_iter_num *it) __weak __ksym;
#ifndef bpf_for
/* bpf_for(i, start, end) implements a for()-like looping construct that sets
 * provided integer variable *i* to values starting from *start* through,
 * but not including, *end*. It also proves to BPF verifier that *i* belongs
 * to range [start, end), so this can be used for accessing arrays without
 * extra checks.
 *
 * Note: *start* and *end* are assumed to be expressions with no side effects
 * and whose values do not change throughout bpf_for() loop execution. They do
 * not have to be statically known or constant, though.
 *
 * Note: similarly to bpf_for_each(), it relies on C99 feature of declaring
 * for() loop bound variables and cleanup attribute, supported by GCC and Clang.
 */
#define bpf_for(i, start, end)                                                                                                                                                                                          \
  for (/* initialize and define destructor */                                                                                                                                                                           \
       struct bpf_iter_num ___it __attribute__((                                                                                                                                                                        \
           aligned(8),                      /* enforce, just in case */                                                                                                                                                 \
           cleanup(bpf_iter_num_destroy))), /* ___p pointer is necessary to                                                                                                                                             \
                                               call bpf_iter_num_new() *once*                                                                                                                                           \
                                               to init ___it */                                                                                                                                                         \
       *___p                                                                                                                                                                                                            \
       __attribute__((unused)) = (bpf_iter_num_new(&___it, (start), (end)), /* this is a workaround for Clang bug: it currently doesn't emit BTF */ /* for bpf_iter_num_destroy() when used from cleanup() attribute */ \
                                  (void)bpf_iter_num_destroy, (void *)0);                                                                                                                                               \
       ({                                                                                                                                                                                                               \
         /* iteration step */                                                                                                                                                                                           \
         int *___t = bpf_iter_num_next(&___it);                                                                                                                                                                         \
         /* termination and bounds check */                                                                                                                                                                             \
         (___t && ((i) = *___t, (i) >= (start) && (i) < (end)));                                                                                                                                                        \
       });)
#endif /* bpf_for */

/* -> bpf_repeat helper function */

#ifndef bpf_repeat
/* bpf_repeat(N) performs N iterations without exposing iteration number
 *
 * Note: similarly to bpf_for_each(), it relies on C99 feature of declaring
 * for() loop bound variables and cleanup attribute, supported by GCC and Clang.
 */
#define bpf_repeat(N)                                                          \
  for (									\
	/* initialize and define destructor */							\
	struct bpf_iter_num ___it __attribute__((aligned(8), /* enforce, just in case */	\
						 cleanup(bpf_iter_num_destroy))),		\
	/* ___p pointer is necessary to call bpf_iter_num_new() *once* to init ___it */		\
			    *___p __attribute__((unused)) = (					\
				bpf_iter_num_new(&___it, 0, (N)),				\
	/* this is a workaround for Clang bug: it currently doesn't emit BTF */			\
	/* for bpf_iter_num_destroy() when used from cleanup() attribute */			\
				(void)bpf_iter_num_destroy, (void *)0);				\
	bpf_iter_num_next(&___it);								\
	/* nothing here  */									\
)
#endif /* bpf_repeat */
