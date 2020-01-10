#include "glr.h"

#include <malloc.h>
#include <stdint.h>
#include <string.h>
#include <stdalign.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sched.h>
#include <stdatomic.h>
#include <errno.h>

#ifdef GLR_VALGRIND
#    include <valgrind/valgrind.h>
#endif

#ifdef GLR_SSL
#    include <openssl/err.h>
#    include <openssl/ssl.h>
#    include <openssl/opensslv.h>
#    include <openssl/bio.h>

#    if OPENSSL_VERSION_NUMBER < 0x10100000L
#        error "Too old version of openssl"
#    endif
#endif


#define thread_local _Thread_local

#define glr_unlikely(cond) __builtin_expect(!!(cond), 0)

struct glr_exec_stack_t {
  void *original_allocation;
  void *sptr;
  size_t size;
  int valgrind_id;
};

struct glr_exec_context_t {
  void **sp;
  glr_exec_stack_t *stack;
  glr_allocator_t *saved_allocator;
};

typedef struct {
  glr_job_fn_t fn;
  void *arg;
} job_t;

typedef _Atomic job_t atomic_job_t;

typedef struct glr_runtime_t {
  glr_exec_context_t *cur_context;

  //works as ringbuffer
  glr_exec_context_t **scheduler_q;
  uint32_t scheduler_q_cap;
  uint32_t scheduler_read_idx;
  uint32_t scheduler_write_idx;
  uint32_t scheduler_currently_in_queue;

  glr_exec_context_t **free_contexts;
  uint32_t free_contexts_len;
  uint32_t free_contexts_cap;

  glr_coro_func_t new_coro_func;
  void *new_coro_arg;

  glr_exec_context_t *new_coro_context;
  glr_exec_context_t *creator_context;

  uint32_t event_loop_inited;
  uint32_t epoll_fd;
  glr_exec_context_t *event_loop_ctx;

  int64_t *timers_deadlines;
  glr_timer_t **timers;
  uint32_t timers_cap;
  uint32_t timers_len;

  glr_exec_context_t thread_context;
  glr_allocator_t *current_allocator;
  glr_allocator_t cached_default_allocator;

  atomic_job_t *async_jobs_ringbuffer;
  uint32_t async_jobs_ringbuffer_cap;
  _Atomic uint32_t async_jobs_r_idx;
  _Atomic uint32_t async_jobs_w_idx;
  _Atomic uint32_t async_woken_up;
  glr_poll_t async_eventfd_poll;

  glr_fd_t *fd_freelist;

#ifdef GLR_SSL
  BIO_METHOD *ssl_bio_method;
  SSL_CTX *ssl_client_default_ctx;
#endif

  char strerror_r_buffer[256];
} glr_runtime_t;

//static thread_local glr_exec_context_t thread_context;
static thread_local glr_runtime_t glr_runtime;

// Global malloc/free allocator
void *glr_malloc_free_adapter(void *data, int op, size_t size, size_t alignment, void *ptr) {
  (void)data;
  (void)alignment;

  switch (op) {
  case GLR_ALLOCATOR_ALLOC: {
    return malloc(size);
  }
  case GLR_ALLOCATOR_FREE: {
    free(ptr);
  } break;
  }

  return NULL;
}

glr_allocator_t glr_get_default_allocator() {
  glr_allocator_t result = {};
  result.func = glr_malloc_free_adapter;
  return result;
}

// Transient allocator: alloc many times and clean it once in the end
typedef struct {
  glr_memory_block *blocks;
  uint32_t len;
  uint32_t cap;
  uint32_t default_block_cap;
  uint32_t active_block_idx;
  uint32_t active_block_used;

  glr_allocator_t *parent;
} glr_transient_allocator;

void glr_transient_allocator_alloc_block(glr_transient_allocator *a, size_t cap) {
  printf("!!!Allocating block\n");
  if (!a->cap || a->len == a->cap) {
    uint32_t new_cap = a->cap * 2;
    if (!new_cap) {
      new_cap = 8;
    }

    uint32_t old_blocks_cap = a->cap;
    glr_memory_block *old_blocks = a->blocks;

    a->blocks = (glr_memory_block *)glr_allocator_alloc(
        a->parent, new_cap * sizeof(glr_memory_block),
        alignof(glr_memory_block));
    a->cap = new_cap;

    memcpy(a->blocks, old_blocks, old_blocks_cap * sizeof(glr_memory_block));
    glr_allocator_free(a->parent, old_blocks);
  }

  a->blocks[a->len].cap = cap;
  a->blocks[a->len].data = glr_allocator_alloc(a->parent, cap, 16);
  a->len++;
}

void glr_transient_allocator_use_next_block(
    glr_transient_allocator *a, size_t min_size) {

  if (!a->len || a->active_block_idx + 1 == a->len) {
    //no free allocated blocks
    size_t block_size = a->default_block_cap;
    if (block_size < min_size) {
      block_size = min_size;
    }
    glr_transient_allocator_alloc_block(a, block_size);
    a->active_block_idx = a->len - 1;
    a->active_block_used = 0;
    return;
  }

  size_t next_block_size = a->blocks[a->active_block_idx + 1].cap;
  if (next_block_size < min_size) {
    //next allocated block is too small
    glr_transient_allocator_alloc_block(a, min_size);
    glr_memory_block new_block = a->blocks[a->len - 1];
    a->blocks[a->len - 1] = a->blocks[a->active_block_idx + 1];
    a->blocks[a->active_block_idx + 1] = new_block;
  }

  //have free block with appropriate capacity
  a->active_block_idx++;
  a->active_block_used = 0;
}


void *glr_transient_allocator_func(
    void *data, int op, size_t size, size_t alignment, void *ptr) {
  (void)ptr;
  glr_transient_allocator *a = (glr_transient_allocator *) data;

  switch (op) {
  case GLR_ALLOCATOR_ALLOC: {
    if (!a->len) {
      glr_transient_allocator_use_next_block(a, size);
    }

    glr_memory_block *block = a->blocks + a->active_block_idx;

    char *block_begin = (char *)block->data;
    char *cur_pos = block_begin + a->active_block_used;
    char *block_end = block_begin + block->cap;

    if ((uintptr_t)cur_pos % alignment) {
      size_t shift_to_match_aligment = (alignment - (uintptr_t)cur_pos % alignment);
      cur_pos += shift_to_match_aligment;
      a->active_block_used += shift_to_match_aligment;
    }

    if (block_end - cur_pos < (long)size) {
      glr_transient_allocator_use_next_block(a, size);

      block = a->blocks + a->active_block_idx;
      block_begin = (char *)block->data;
      cur_pos = block_begin + a->active_block_used;
      block_end = block_begin + block->cap;
    }

    void *result = cur_pos;
    a->active_block_used += size;
    return result;
  } break;
  case GLR_ALLOCATOR_FREE: {
  } break;
  case GLR_ALLOCATOR_RESET: {
    a->active_block_idx = 0;
    a->active_block_used = 0;
  } break;
  case GLR_ALLOCATOR_DESTROY: {
    for (uint32_t block_idx = 0; block_idx < a->len; ++block_idx) {
      glr_allocator_free(a->parent, a->blocks[block_idx].data);
    }
    glr_allocator_free(a->parent, a->blocks);
    glr_allocator_free(a->parent, a);
  } break;
  }

  return NULL;
}

glr_allocator_t glr_get_transient_allocator(glr_allocator_t *parent) {
  if (!parent) {
    parent = glr_current_allocator();
  }
  glr_allocator_t result = {};

  glr_transient_allocator *tmp = (glr_transient_allocator *)glr_allocator_alloc(
      parent, sizeof(glr_transient_allocator),
      alignof(glr_transient_allocator));
  *tmp = (glr_transient_allocator){};

  tmp->default_block_cap = 4096;
  tmp->parent = parent;
  result.func = glr_transient_allocator_func;
  result.data = tmp;

  return result;
}

//Common for all allocators
void *glr_allocator_alloc(glr_allocator_t *a, size_t size,
                             size_t alignment) {
  return a->func(a->data, GLR_ALLOCATOR_ALLOC, size, alignment, NULL);
}

void glr_allocator_free(glr_allocator_t *a, void *ptr) {
  a->func(a->data, GLR_ALLOCATOR_FREE, 0, 0, ptr);
}

void glr_reset_allocator(glr_allocator_t *a) {
  a->func(a->data, GLR_ALLOCATOR_RESET, 0, 0, NULL);
}

void glr_destroy_allocator(glr_allocator_t *a) {
  a->func(a->data, GLR_ALLOCATOR_DESTROY, 0, 0, NULL);
}

void glr_push_allocator(glr_allocator_t *a) {
  a->next = glr_runtime.current_allocator;
  glr_runtime.current_allocator = a;
}

glr_allocator_t* glr_pop_allocator() {
  glr_allocator_t *result = glr_runtime.current_allocator;
  glr_runtime.current_allocator = glr_runtime.current_allocator->next;
  return result;
}

glr_allocator_t* glr_current_allocator() {
  if (!glr_runtime.current_allocator) {
    if (!glr_runtime.cached_default_allocator.func) {
      glr_runtime.cached_default_allocator = glr_get_default_allocator();
    }
    glr_runtime.current_allocator = &glr_runtime.cached_default_allocator;
  }

  return glr_runtime.current_allocator;
}

void *glr_malloc(size_t size, size_t alignment) {
  return glr_allocator_alloc(glr_current_allocator(), size, alignment);
}

void glr_free(void *data) {
  return glr_allocator_free(glr_current_allocator(), data);
}

str_t glr_sprintf_ex(glr_allocator_t *a, const char *format, ...) {
  va_list args;
  va_start(args, format);

  int len = vsnprintf(NULL, 0, format, args);

  str_t result = {};
  result.cap = len + 1;
  result.data = glr_allocator_alloc(a, result.cap, alignof(char));

  va_end(args);
  va_start(args, format);

  result.len = vsnprintf(result.data, result.cap, format, args);

  va_end(args);

  return result;
}

str_t glr_strdup(str_t s) {
  str_t result;
  result.cap = s.cap;
  result.len = s.len;
  result.data = GLR_ALLOCATE_ARRAY(char, s.len);
  memcpy(result.data, s.data, s.len);
  return result;
}

//stringbuilder related
stringbuilder_t glr_make_stringbuilder(size_t default_buffer_cap) {
  stringbuilder_t result = {};
  result.default_block_cap = default_buffer_cap;
  return result;
}

void glr_stringbuilder_alloc_block(stringbuilder_t *sb, size_t cap) {
  printf("!!!Allocating stringbuilder block\n");
  if (!sb->cap || sb->len == sb->cap) {
    uint32_t new_cap = sb->cap * 2;
    if (!new_cap) {
      new_cap = 8;
    }

    uint32_t old_blocks_cap = sb->cap;
    str_t *old_blocks = sb->blocks;

    sb->blocks = (str_t *) glr_malloc(new_cap * sizeof(str_t), alignof(str_t));
    sb->cap = new_cap;

    memcpy(sb->blocks, old_blocks, old_blocks_cap * sizeof(str_t));
    free(old_blocks);
  }

  sb->blocks[sb->len].cap = cap;
  sb->blocks[sb->len].data = glr_malloc(cap, 1);
  sb->blocks[sb->len].len = 0;
  sb->len++;
}

void glr_stringbuilder_use_next_block(stringbuilder_t *sb, size_t min_size) {

  if (!sb->len || sb->active_block_idx + 1 == sb->len) {
    //no free allocated blocks
    size_t block_size = sb->default_block_cap;
    if (block_size < min_size) {
      block_size = min_size;
    }
    glr_stringbuilder_alloc_block(sb, block_size);
    sb->active_block_idx = sb->len - 1;
    return;
  }

  size_t next_block_size = sb->blocks[sb->active_block_idx + 1].cap;
  if (next_block_size < min_size) {
    //next allocated block is too small
    glr_stringbuilder_alloc_block(sb, min_size);
    str_t new_block = sb->blocks[sb->len - 1];
    sb->blocks[sb->len - 1] = sb->blocks[sb->active_block_idx + 1];
    sb->blocks[sb->active_block_idx + 1] = new_block;
  }

  //have free block with appropriate capacity
  sb->active_block_idx++;
  sb->blocks[sb->active_block_idx].len = 0;
}

void glr_stringbuilder_append(stringbuilder_t *sb, const char *data, size_t len) {
  int needed_cap = len + 1;
  str_t *active_block = sb->blocks + sb->active_block_idx;
  if (!sb->len || active_block->len + needed_cap > active_block->cap) {
    glr_stringbuilder_use_next_block(sb, needed_cap);
    active_block = sb->blocks + sb->active_block_idx;
  }

  char *data_ptr = active_block->data + active_block->len;
  memcpy(data_ptr, data, len);
  active_block->len += len;
  active_block->data[active_block->len] = 0;
}


void glr_stringbuilder_append2(stringbuilder_t *sb, const str_t s) {
  glr_stringbuilder_append(sb, s.data, s.len);
}

void glr_stringbuilder_vprintf(stringbuilder_t *sb, const char *format, va_list va) {
  va_list args;
  va_copy(args, va);
  int needed_cap = vsnprintf(NULL, 0, format, args) + 1;
  va_end(args);

  str_t *active_block = sb->blocks + sb->active_block_idx;
  if (!sb->len || active_block->len + needed_cap > active_block->cap) {
    glr_stringbuilder_use_next_block(sb, needed_cap);
    active_block = sb->blocks + sb->active_block_idx;
  }

  char *data_ptr = active_block->data + active_block->len;
  int cap_left = active_block->cap - active_block->len;

  va_copy(args, va);
  int written = vsnprintf(data_ptr, cap_left, format, args);
  va_end(args);

  active_block->len += written;
}

void glr_stringbuilder_printf(stringbuilder_t *sb, const char *format, ...) {
  va_list args;
  va_start(args, format);
  glr_stringbuilder_vprintf(sb, format, args);
  va_end(args);
}

str_t glr_stringbuilder_build(stringbuilder_t *sb) {
  if (sb->len == 0) {
    return (str_t){};
  }

  if (sb->active_block_idx == 0) {
    //fast path -- giveaway that single buffer that was used

    str_t result = sb->blocks[sb->active_block_idx];
    if (sb->len) {
      sb->blocks[0] = sb->blocks[sb->len - 1];
      sb->len--;
    }
    return result;
  }

  uint32_t needed_cap = 0;
  for (uint32_t i = 0; i <= sb->active_block_idx; ++i) {
    needed_cap += sb->blocks[i].len;
  }

  str_t result = {};
  result.cap = needed_cap + 1;
  result.data = glr_malloc(result.cap, 1);

  for (uint32_t i = 0; i <= sb->active_block_idx; ++i) {
    memcpy(result.data + result.len, sb->blocks[i].data, sb->blocks[i].len);
    result.len += sb->blocks[i].len;
  }

  result.data[result.len] = 0;

  return result;
}

void glr_stringbuilder_free_buffers(stringbuilder_t *sb) {
  for (uint32_t i = 0; i < sb->len; ++i) {
    glr_free(sb->blocks[i].data);
  }
  glr_free(sb->blocks);
}

void glr_stringbuilder_reset(stringbuilder_t *sb) {
  for (uint32_t i = 0; i < sb->len; ++i) {
    sb->blocks[i].len = 0;
  }
  sb->active_block_idx = 0;
}


//coroutines

#ifdef GLR_VALGRIND
static void register_stack_in_valgrind(glr_exec_stack_t *stack) {
  stack->valgrind_id = VALGRIND_STACK_REGISTER(
      (char *)stack->sptr,
      ((char *)stack->sptr) +
          stack->size /* - default_guard_pages * GLR_PAGESIZE*/);
}

static void unregister_stack_in_valgrind(glr_exec_stack_t *stack) {
  VALGRIND_STACK_DEREGISTER(stack->valgrind_id);
}
#else
static void register_stack_in_valgrind(glr_exec_stack_t *s) {}
static void unregister_stack_in_valgrind(glr_exec_stack_t *s) {}
#endif



typedef struct {
  size_t usable;
  size_t full;
  size_t guard;
} stack_size_t;

static stack_size_t get_stack_size() {
  static stack_size_t result = {};
  if (!result.usable) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t default_stack_size = 7 * page_size;
    size_t default_guard_size = 1 * page_size;

    result = (stack_size_t){
      default_stack_size,
      default_stack_size + default_guard_size,
      default_guard_size,
    };
  }

  return result;
}

void glr_exec_context_cleanup(glr_exec_context_t *ctx, stack_size_t *ss) {
    unregister_stack_in_valgrind(ctx->stack);
    munmap(ctx->stack->original_allocation, ss->full);
    free(ctx->stack);
    free(ctx);
}

void glr_cur_thread_runtime_cleanup() {
  stack_size_t ss = get_stack_size();
  glr_runtime_t *r = &glr_runtime;

  if (r->event_loop_inited) {
    //glr_exec_context_cleanup(r->event_loop_ctx, &ss);
    close(r->epoll_fd);
    close(r->async_eventfd_poll.fd);
  }

  free(r->timers);
  free(r->timers_deadlines);
  free(r->async_jobs_ringbuffer);

  for (uint32_t i = 0; i < r->scheduler_currently_in_queue; ++i) {
    uint32_t idx = (r->scheduler_read_idx + i) % r->scheduler_q_cap;
    glr_exec_context_t *ctx = r->scheduler_q[idx];
    glr_exec_context_cleanup(ctx, &ss);
  }
  free(r->scheduler_q);

  for (uint32_t i = 0; i < r->free_contexts_len; ++i) {
    glr_exec_context_t *ctx = r->free_contexts[i];
    /*
     * FIXME: currently it does not work properly and cause tests to segfault
    glr_allocator_t *allocator_it = ctx->saved_allocator;
    while (allocator_it) {
      glr_allocator_t *tmp = allocator_it;
      allocator_it = allocator_it->next;
      glr_destroy_allocator(tmp);
    }
    */
    glr_exec_context_cleanup(ctx, &ss);
  }
  free(r->free_contexts);

  glr_fd_t *next = r->fd_freelist;
  while (next) {
    glr_fd_t *tmp = next;
    next = *(glr_fd_t **) next;
    free(tmp);
  }

#ifdef GLR_SSL
  if (r->ssl_bio_method) {
    BIO_meth_free(r->ssl_bio_method);
  }
  if (r->ssl_client_default_ctx) {
    SSL_CTX_free(r->ssl_client_default_ctx);
  }
#endif

  *r = (glr_runtime_t) {};
}


glr_exec_context_t *glr_current_context() {
  if (!glr_runtime.cur_context) {
    return &glr_runtime.thread_context;
  }
  return glr_runtime.cur_context;
}

void glr_preallocate_contexts(size_t count) {
  for (size_t i = 0; i < count; ++i) {
    glr_exec_context_t *result = NULL;
    result = malloc(sizeof(glr_exec_context_t));
    result->stack = malloc(sizeof(glr_exec_stack_t));
    stack_size_t ss = get_stack_size();
    result->stack->size = ss.usable;
    ssize_t real_size = ss.full;
    result->stack->original_allocation =
        mmap(0, real_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0);
    result->stack->sptr = result->stack->original_allocation;
    if (result->stack->sptr == (void *)-1) {
      printf("Failed to mmap coroutine stack memory\n");
      abort();
    }
    mprotect(result->stack->sptr, ss.guard, PROT_NONE);

    result->stack->sptr = ((char*)(result->stack->sptr) + ss.guard);
    register_stack_in_valgrind(result->stack);
    glr_put_context_to_freelist(result);
  }
}

glr_exec_context_t *glr_get_context_from_freelist() {
  if (!glr_runtime.free_contexts_len) {
    glr_preallocate_contexts(1);
  }
  glr_exec_context_t *result = glr_runtime.free_contexts[0];
  glr_runtime.free_contexts[0] =
      glr_runtime.free_contexts[glr_runtime.free_contexts_len - 1];
  glr_runtime.free_contexts_len--;
  result->saved_allocator = NULL;
  return result;
}


void glr_put_context_to_freelist(glr_exec_context_t *context) {
  glr_runtime_t *r = &glr_runtime;
  if (r->free_contexts_len + 1 > r->free_contexts_cap) {
    uint32_t new_cap = r->free_contexts_cap * 2;
    if (!new_cap) {
      new_cap = 512;
    }
    glr_exec_context_t **old_arr = r->free_contexts;
    glr_exec_context_t **new_arr = malloc(new_cap * sizeof(r->free_contexts[0]));
    memcpy(new_arr, r->free_contexts, r->free_contexts_len);
    free(old_arr);
    r->free_contexts_cap = new_cap;
    r->free_contexts = new_arr;
  }
  r->free_contexts[r->free_contexts_len] = context;
  r->free_contexts_len++;
}

/*
noinline -- obvious =)

regparm (number)
On x86-32 targets, the regparm attribute causes the compiler to pass arguments
number one to number if they are of integral type in registers EAX, EDX, and ECX
instead of on the stack. Functions that take a variable number of arguments
continue to be passed all of their arguments on the stack.

Beware that on some ELF systems this attribute is unsuitable for global
functions in shared libraries with lazy binding (which is the default). Lazy
binding sends the first call via resolving code in the loader, which might
assume EAX, EDX and ECX can be clobbered, as per the standard calling
conventions. Solaris 8 is affected by this. Systems with the GNU C Library
version 2.1 or higher and FreeBSD are believed to be safe since the loaders
there save EAX, EDX and ECX. (Lazy binding can be disabled with the linker or
the loader if desired, to avoid the problem.)
*/

void __attribute__((__noinline__, __regparm__(2)))
glr_coro_transfer(glr_exec_context_t *prev, glr_exec_context_t *next);

#define NUM_SAVED 6
asm("\t.text\n"
    "\t.globl glr_coro_transfer\n"
    "glr_coro_transfer:\n"
#if __amd64
    "\tpushq %rbp\n"
    "\tpushq %rbx\n"
    "\tpushq %r12\n"
    "\tpushq %r13\n"
    "\tpushq %r14\n"
    "\tpushq %r15\n"
    "\tmovq %rsp, (%rdi)\n"
    "\tmovq (%rsi), %rsp\n"
    "\tpopq %r15\n"
    "\tpopq %r14\n"
    "\tpopq %r13\n"
    "\tpopq %r12\n"
    "\tpopq %rbx\n"
    "\tpopq %rbp\n"
    "\tpopq %rcx\n"
    "\tjmpq *%rcx\n"
#else
#error unsupported architecture
#endif
);

void glr_transfer(glr_exec_context_t *prev, glr_exec_context_t *next) {
  prev->saved_allocator = glr_runtime.current_allocator;
  glr_runtime.current_allocator = next->saved_allocator;
  glr_runtime.cur_context = next;
  glr_coro_transfer(prev, next);
}

void glr_transfer_to(glr_exec_context_t *next) {
  glr_transfer(glr_current_context(), next);
}

void glr_coro_init(void) {
  glr_runtime_t *r = &glr_runtime;
  glr_coro_func_t func = r->new_coro_func;
  void *arg = r->new_coro_arg;

  glr_exec_context_t *own_context = r->new_coro_context;

  glr_transfer(r->new_coro_context,
               r->creator_context);

#if __GCC_HAVE_DWARF2_CFI_ASM && __amd64
  // From now on the previous value of register rip can’t be restored anymore
  asm(".cfi_undefined rip");
#endif

  func(arg);

  glr_put_context_to_freelist(own_context);
  glr_scheduler_yield(0);

  /* the new coro returned. bad. just abort() for now */
  abort();
}

void glr_create_coro(glr_exec_context_t *ctx, glr_coro_func_t fn, void *arg) {
  glr_runtime_t *r = &glr_runtime;
  r->new_coro_func = fn;
  r->new_coro_arg = arg;

  r->new_coro_context = ctx;
  r->creator_context = glr_current_context();

  ctx->sp = (void **)(ctx->stack->size + (char *)(ctx->stack->sptr));
  *--ctx->sp = (void *)(abort); /* needed for alignment only */
  *--ctx->sp = (void *)(glr_coro_init);

  ctx->sp -= NUM_SAVED;
  memset(ctx->sp, 0, sizeof(*ctx->sp) * NUM_SAVED);

  glr_transfer(r->creator_context, r->new_coro_context);
}

glr_exec_context_t *glr_go(glr_coro_func_t fn, void *arg) {
  glr_exec_context_t *ctx = glr_get_context_from_freelist();
  glr_create_coro(ctx, fn, arg);
  glr_scheduler_add(ctx);
  return ctx;
}

void glr_scheduler_add(glr_exec_context_t *ctx) {
  glr_runtime_t *r = &glr_runtime;
  if (r->scheduler_currently_in_queue + 1 > r->scheduler_q_cap) {
    uint32_t new_cap = r->scheduler_q_cap * 4;
    if (!new_cap) {
      new_cap = 128;
    }
    glr_exec_context_t **new_arr = malloc(new_cap * sizeof(glr_exec_context_t*));

    memcpy(new_arr, r->scheduler_q, r->scheduler_q_cap * sizeof(glr_exec_context_t*));
    memcpy(new_arr + r->scheduler_q_cap, r->scheduler_q,
           r->scheduler_read_idx * sizeof(glr_exec_context_t*));

    r->scheduler_write_idx = r->scheduler_q_cap + r->scheduler_read_idx;

    free(r->scheduler_q);
    r->scheduler_q = new_arr;
    r->scheduler_q_cap = new_cap;
  }
  r->scheduler_q[r->scheduler_write_idx] = ctx;
  r->scheduler_write_idx = (r->scheduler_write_idx + 1) % r->scheduler_q_cap;
  r->scheduler_currently_in_queue++;
}

void glr_scheduler_yield(int reschedule_current_ctx) {
  glr_runtime_t *r = &glr_runtime;
  glr_exec_context_t *cur_ctx = glr_current_context();
  if (reschedule_current_ctx) {
    glr_scheduler_add(cur_ctx);
  }

  if (!r->scheduler_currently_in_queue) {
    //TODO: logger should be here
    abort();
  }

  glr_exec_context_t *next_ctx = r->scheduler_q[r->scheduler_read_idx];
  r->scheduler_read_idx = (r->scheduler_read_idx + 1) % r->scheduler_q_cap;
  r->scheduler_currently_in_queue--;

  glr_transfer(cur_ctx, next_ctx);
}
//error handling
inline void glr_err_cleanup(err_t *err) {
  glr_stringbuilder_free_buffers(&err->msg);
  *err = (err_t) {};
}

const char *glr_posix_error = "GLR_POSIX_ERROR";

void glr_make_posix_error(err_t *err, const char *file, int line,
                          const char *func, const char *format, ...) {
  int saved_errno = errno;
  err->error = GLR_POSIX_ERROR;
  err->sub_error = saved_errno;
  err->msg = glr_make_stringbuilder(256);
  const char *error_msg = strerror_r(saved_errno, glr_runtime.strerror_r_buffer,
             sizeof(glr_runtime.strerror_r_buffer));
  glr_stringbuilder_printf(&err->msg,
                           "%s:%d:%s errno=%d '%s' ", file,
                           line, func, saved_errno, error_msg);
  va_list va;
  va_start(va, format);
  glr_stringbuilder_vprintf(&err->msg, format, va);
  va_end(va);
}

const char *glr_invalid_argument_error = "GLR_INVALID_ARGUMENT_ERROR";
const char *glr_getaddrinfo_error = "GLR_GETADDRINFO_ERROR";
const char *glr_getaddrinfo_no_result_error = "GLR_GETADDRINFO_NO_RESULT_ERROR";
const char *glr_general_error = "GLR_GENERAL_ERROR";
const char *glr_timeout_error = "GLR_TIMEOUT_ERROR";

// networking
int64_t glr_timestamp_in_ms() {
  struct timeval t;
  //TODO replace with clock_gettime()
  gettimeofday(&t, NULL);
  return t.tv_sec * 1000 + t.tv_usec / 1000;
}


static void glr_event_loop() {
  printf("event_loop started\n");
  glr_runtime_t *r = &glr_runtime;
  const size_t max_events = 64;
  struct epoll_event revents[max_events];
  for (;;) {
    int timeout = 0;
    if (glr_runtime.scheduler_currently_in_queue == 0) {
      timeout = -1;
    }

    if (r->timers_len) {
      int64_t deadline = r->timers_deadlines[0];
      for (uint32_t i = 1; i < r->timers_len; ++i) {
        if (r->timers_deadlines[i] < deadline) {
          deadline = r->timers_deadlines[i];
        }
      }
      int64_t now = glr_timestamp_in_ms();
      timeout = deadline - now;
      if (timeout < 0) {
        timeout = 0;
      }
    }


    int count = epoll_wait(r->epoll_fd, revents, max_events, timeout);

    int64_t now = glr_timestamp_in_ms();
    for (uint32_t i = 0; i < r->timers_len;) {
      if (r->timers_deadlines[i] <= now) {
        glr_timer_t *t = r->timers[i];
        glr_remove_timer(t);
        t->callback(t);
      } else {
        ++i;
      }
    }

    for (int i = 0; i < count; ++i) {
      struct epoll_event *event = revents + i;
      glr_poll_t *poll = (glr_poll_t *)event->data.ptr;
      poll->last_epoll_event_bitset = event->events;
      if (poll->cb) {
        poll->cb(poll);
      }
    }

    glr_scheduler_yield(1);
  }

}

static void glr_async_consume(glr_poll_t *p);

static void glr_init_event_loop() {
  glr_runtime.event_loop_inited = 1;

  glr_runtime.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (glr_runtime.epoll_fd < 0) {
    //Global logger should be used here
    perror("Failed to create epoll instance");
    perror(strerror(errno));
    abort();
  }
  glr_runtime.event_loop_ctx = glr_go(glr_event_loop, NULL);

  glr_runtime.async_jobs_ringbuffer_cap = 65536;
  //glr_runtime.async_jobs_ringbuffer_cap = 10;
  size_t ringbuffer_size = sizeof(job_t) * glr_runtime.async_jobs_ringbuffer_cap;
  glr_runtime.async_jobs_ringbuffer = (atomic_job_t *) malloc(ringbuffer_size);
  memset(glr_runtime.async_jobs_ringbuffer, 0, ringbuffer_size);

  glr_runtime.async_eventfd_poll.fd = eventfd(0, EFD_NONBLOCK);
  if (glr_runtime.async_eventfd_poll.fd < 0) {
    //Global logger should be used here
    perror("Failed to create eventfd instance async posts");
    perror(strerror(errno));
    abort();
  }
  glr_runtime.async_eventfd_poll.cb = glr_async_consume;

  err_t err = {};
  glr_add_poll(&glr_runtime.async_eventfd_poll, EPOLLET|EPOLLIN, &err);
  if (err.error) {
    perror("Failed to poll eventfd instance of async tasks: ");
    str_t s = glr_stringbuilder_build(&err.msg);
    perror(s.data);
    abort();
 }
}

static inline uint32_t glr_runtime_get_epoll_fd() {
  if (glr_unlikely(glr_runtime.event_loop_inited == 0)) {
    glr_init_event_loop();
  }
  return glr_runtime.epoll_fd;
}

void glr_add_poll(glr_poll_t *poll, int flags, err_t *err) {
  if (err->error) {
    return;
  }

  int epoll_fd = glr_runtime_get_epoll_fd();

  struct epoll_event ev = {};
  ev.data.ptr = poll;
  ev.events = flags;
  int rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, poll->fd, &ev);
  if (rc == -1) {
    GLR_MAKE_POSIX_ERROR(err, "epoll_ctl(..., EPOLL_CTL_ADD, ...) failed");
  }
}

void glr_change_poll(glr_poll_t *poll, int flags, err_t *err) {
  if (err->error) {
    return;
  }

  int epoll_fd = glr_runtime_get_epoll_fd();

  struct epoll_event ev = {};
  ev.data.ptr = poll;
  ev.events = flags;
  int rc = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, poll->fd, &ev);
  if (rc == -1) {
    GLR_MAKE_POSIX_ERROR(err, "epoll_ctl(..., EPOLL_CTL_MOD, ...) failed");
  }
}

void glr_remove_poll(glr_poll_t *poll, err_t *err) {
  if (err->error) {
    return;
  }

  int epoll_fd = glr_runtime_get_epoll_fd();

  struct epoll_event ev = {};
  int rc = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, poll->fd, &ev);
  if (rc == -1) {
    GLR_MAKE_POSIX_ERROR(err, "epoll_ctl(..., EPOLL_CTL_DEL, ...) failed");
  }
}

void glr_add_context_poll_callback(glr_poll_t *p) {
  glr_scheduler_add((glr_exec_context_t *) p->cb_arg);
}

int glr_wait_for(int fd, uint32_t flags, err_t *err) {
  if (err->error) {
    return 0;
  }

  if (flags == 0) {
    err->error = GLR_INVALID_ARGUMENT_ERROR;
    glr_stringbuilder_printf(
        &err->msg, "%s:%d:%s glr_wait_for flags should not be 0",
        __FILE__, __LINE__, __func__);

    return 0;
  }

  glr_poll_t p;
  p.fd = fd;
  p.cb_arg = glr_current_context();
  p.cb = glr_add_context_poll_callback;

  glr_add_poll(&p, flags, err);
  if (err->error) {
    glr_stringbuilder_printf(
        &err->msg, "\n%s:%d glr_wait_for failed to add poll",
        __FILE__, __LINE__);
    return 0;
  }

  glr_scheduler_yield(0);

  glr_remove_poll(&p, err);
  if (err->error) {
    glr_stringbuilder_printf(
        &err->msg, "\n%s:%d glr_wait_for failed to remove poll",
        __FILE__, __LINE__);
    return 0;
  }

  return p.last_epoll_event_bitset;
}

void glr_add_timer(glr_timer_t *t) {
  glr_runtime_t *r = &glr_runtime;
  if (!r->event_loop_inited) {
    glr_init_event_loop();
  }

  if (r->timers_len + 1 > r->timers_cap) {
    uint32_t new_cap = r->timers_cap * 3;
    if (!new_cap) {
      new_cap = 64;
    }
    int64_t *new_deadlines
        = (int64_t *) malloc(new_cap * sizeof(int64_t));
    glr_timer_t **new_timers
        = (glr_timer_t **) malloc(new_cap * sizeof(glr_timer_t *));
    memcpy(new_deadlines, r->timers_deadlines,
           r->timers_len * sizeof(int64_t));
    memcpy(new_timers, r->timers,
           r->timers_len * sizeof(glr_timer_t *));
    free(r->timers_deadlines);
    free(r->timers);
    r->timers_cap = new_cap;
    r->timers_deadlines = new_deadlines;
    r->timers = new_timers;
  }

  r->timers[r->timers_len] = t;
  r->timers_deadlines[r->timers_len] = t->deadline_posix_milliseconds;

  t->internal_idx = r->timers_len;

  r->timers_len++;
}

void glr_remove_timer(glr_timer_t *t) {
  glr_runtime_t *r = &glr_runtime;
  uint32_t idx = t->internal_idx;

  if (idx >= r->timers_len) {
    //TODO: log message should be here
    //this is caused by error of library user
    abort();
  }

  if (r->timers[idx] != t) {
    //TODO: log message should be here
    //this is caused by error of library user
    abort();
  }

  r->timers[idx] = r->timers[r->timers_len - 1];
  r->timers_deadlines[idx] = r->timers_deadlines[r->timers_len - 1];
  r->timers[idx]->internal_idx = idx;
  r->timers_len--;

  t->internal_idx = -1;
}

static void glr_wakeup_on_timer(glr_timer_t *t) {
  glr_exec_context_t *ctx = t->arg;
  glr_scheduler_add(ctx);
}

void glr_sleep(int msec) {
  glr_timer_t t = {};
  t.deadline_posix_milliseconds = glr_timestamp_in_ms() + msec;
  t.arg = glr_current_context();
  t.callback = glr_wakeup_on_timer;
  glr_add_timer(&t);
  glr_scheduler_yield(0);
}

glr_runtime_t *glr_cur_thread_runtime() {
  if (!glr_runtime.event_loop_inited) {
    glr_init_event_loop();
  }
  return &glr_runtime;
}

void glr_async_post(glr_runtime_t *r, glr_job_fn_t fn, void *arg) {
  if (!fn) {
    abort();
  }

  job_t j = {fn, arg};
  uint32_t tmp_w_idx = r->async_jobs_w_idx;
  uint32_t new_w_idx = 0;
  do {
    new_w_idx = (tmp_w_idx + 1) % r->async_jobs_ringbuffer_cap;
  } while (!atomic_compare_exchange_weak(&r->async_jobs_w_idx, &tmp_w_idx, new_w_idx));

  job_t cur = r->async_jobs_ringbuffer[tmp_w_idx];
  while (cur.fn) {
    sched_yield();
    cur = r->async_jobs_ringbuffer[tmp_w_idx];
  }

  r->async_jobs_ringbuffer[tmp_w_idx] = j;
  if (!r->async_woken_up) {
    r->async_woken_up = 1;
    uint64_t c = 1;
    int n = write(r->async_eventfd_poll.fd, &c, sizeof(c));
    if (n != sizeof(c)) {
      //TODO: proper logging should be here
    }
  }
}

static void glr_async_consume(glr_poll_t *p) {
  (void)p;
  glr_runtime_t *r = &glr_runtime;

  uint64_t c;
  read(r->async_eventfd_poll.fd, &c, sizeof(c));
  r->async_woken_up = 0;

  const uint32_t cap = r->async_jobs_ringbuffer_cap;
  atomic_job_t *rb = r->async_jobs_ringbuffer;
  uint32_t r_idx = r->async_jobs_r_idx;
  const uint32_t w_idx = r->async_jobs_w_idx;

  job_t j = rb[r_idx];
  if (r_idx == w_idx && !j.fn) {
    return;
  }

  do {
    while (!j.fn) j = rb[r_idx];

    j.fn(j.arg);
    rb[r_idx] = (job_t){};
    r->async_jobs_r_idx = r_idx = (r_idx + 1) % cap;
    j = rb[r_idx];
  } while (r_idx != w_idx);
}

struct sockaddr_storage glr_resolve_address(const char *host, const char *port,
                                            err_t *err) {
  if (err->error) return (struct sockaddr_storage){};

  struct sockaddr_storage addr = {};

  struct addrinfo *result = NULL;
  int rc = getaddrinfo(host, port, NULL, &result);
  if (rc != 0 && rc != EAI_NONAME) {
    err->error = GLR_GETADDRINFO_ERROR;
    err->sub_error = rc;
    glr_stringbuilder_printf(
        &err->msg, "%s:%d:%s getaddrinfo(%s, %s) failed rc=%d, err=%s\n",
        __FILE__, __LINE__, __func__, host, port, rc, gai_strerror(rc));
    goto cleanup;
  }

  if (!result || rc == EAI_NONAME) {
    err->error = GLR_GETADDRINFO_NO_RESULT_ERROR;
    err->sub_error = 0;
    glr_stringbuilder_printf(
        &err->msg, "%s:%d:%s getaddrinfo(%s, %s) returned no result\n",
        __FILE__, __LINE__, __func__, host, port);

    goto cleanup;
  }

  memcpy(&addr, result->ai_addr, result->ai_addrlen);
cleanup:
  freeaddrinfo(result);
  return addr;
}

struct sockaddr_storage glr_resolve_address1(const char *host, int port,
                                             err_t *err) {
  char port_buffer[10];
  snprintf(port_buffer, 10, "%d", port);
  return glr_resolve_address(host, port_buffer, err);
}


struct sockaddr_storage glr_resolve_address2(const char *addr, err_t *err) {
  if (err->error) return (struct sockaddr_storage){};

  const char *host_begin = addr;
  const char *last_colon = NULL;
  const char *it = addr;

  while (*it) {
    if (*it == ':') {
      last_colon = it;
    }
    ++it;
  }

  if (last_colon == NULL) {
    err->error = GLR_INVALID_ARGUMENT_ERROR;
    err->sub_error = 0;
    glr_stringbuilder_printf(
        &err->msg, "%s:%d:%s failed to split \"%s\" to host and port\n",
        __FILE__, __LINE__, __func__, addr);

    return (struct sockaddr_storage){};
  }

  const char *port_end = it;
  const char *port_begin = last_colon + 1;
  const char *host_end = last_colon;

  char host[host_end - host_begin + 1];
  char port[port_end - port_begin + 1];
  strncpy(host, host_begin, host_end - host_begin);
  host[host_end - host_begin] = 0;
  strncpy(port, port_begin, port_end - port_begin);
  port[port_end - port_begin] = 0;
  return glr_resolve_address(host, port, err);
}

str_t glr_addr_to_string(const struct sockaddr_storage *addr) {
  switch (addr->ss_family) {
  case AF_INET:
  case AF_INET6: {
    char buffer[INET6_ADDRSTRLEN + 1];
    inet_ntop(addr->ss_family, &((struct sockaddr_in *)addr)->sin_addr, buffer,
              sizeof(buffer));
    stringbuilder_t sb = glr_make_stringbuilder(256);
    glr_stringbuilder_append(&sb, buffer, strlen(buffer));
    uint32_t port = 0;
    if (addr->ss_family == AF_INET) {
      port = ntohs(((struct sockaddr_in *)addr)->sin_port);
    } else {
      port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
    }
    glr_stringbuilder_printf(&sb, ":%u", port);
    str_t result = glr_stringbuilder_build(&sb);
    glr_stringbuilder_free_buffers(&sb);
    return result;
  } break;
  case AF_UNIX: {
    stringbuilder_t sb = glr_make_stringbuilder(256);
    glr_stringbuilder_append2(&sb, GLR_STR_LITERAL("unix:"));

    const struct sockaddr_un *a = (struct sockaddr_un *) addr;
    const char *path = a->sun_path;
    if (path[0] == 0) {
      path++;
      glr_stringbuilder_append2(&sb, GLR_STR_LITERAL("@"));
    }
    glr_stringbuilder_append(&sb, path, strlen(path));

    str_t result = glr_stringbuilder_build(&sb);
    glr_stringbuilder_free_buffers(&sb);
    return result;
  } break;
  default:
    return GLR_STRDUP_LITERAL("Unsupported family");
  }
}


int glr_addr_get_port(const struct sockaddr_storage *addr) {
  switch (addr->ss_family) {
  case AF_INET: {
    return ntohs(((struct sockaddr_in *)addr)->sin_port);
  } break;
  case AF_INET6: {
    return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
  } break;
  default:
    return -1;
  }
}


struct sockaddr_storage glr_resolve_unix_socket_addr(const char *path) {
  struct sockaddr_storage result = {};
  struct sockaddr_un *s = (struct sockaddr_un *)&result;
  s->sun_family = AF_UNIX;
  strncpy(s->sun_path, path, sizeof(s->sun_path) - 1);
  return result;
}

struct glr_fd_t {
  glr_poll_t poll;
  int64_t deadline;
  uint32_t desired_epoll_flags;
  glr_exec_context_t *ctx;
  void *ssl;
};

static void glr_fd_poll_callback(glr_poll_t *poll) {
  glr_fd_t *fd = poll->cb_arg;
  if (poll->last_epoll_event_bitset & fd->desired_epoll_flags) {
    glr_scheduler_add(fd->ctx);
  }
}

glr_fd_t *glr_init_fd(int fd, err_t *err) {
  if (err->error) return NULL;

  glr_runtime_t *r = &glr_runtime;
  glr_fd_t *result = NULL;

  if (r->fd_freelist) {
    result = r->fd_freelist;
    r->fd_freelist = *(glr_fd_t **)result;
  } else {
    result = malloc(sizeof(glr_fd_t));
  }

  *result = (glr_fd_t){};
  result->poll.fd = fd;
  result->poll.cb_arg = result;
  result->poll.cb = glr_fd_poll_callback;

  glr_add_poll(&result->poll, EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET, err);
  if (err->error) {
    glr_stringbuilder_printf(&err->msg,
                             "\n%s:%d:%s glr_add_poll() failed",
                             __FILE__, __LINE__, __func__);
    goto error_cleanup;
  }

  return result;
error_cleanup:
  if (result) {
    *(glr_fd_t **) result = r->fd_freelist;
    r->fd_freelist = result;
  }
  return NULL;
}

glr_fd_t *glr_listen(const struct sockaddr_storage *addr, int backlog,
                     int reuse_addr, err_t *err) {
  if (err->error) return NULL;

  int fd = -1;

  fd = socket(addr->ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    GLR_MAKE_POSIX_ERROR(err, "socket(...) failed");
    goto cleanup_after_error;
  }

  if (reuse_addr) {
    int reuse = reuse_addr;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
      GLR_MAKE_POSIX_ERROR(err, "setsockopt(SO_REUSEADDR) failed");
      goto cleanup_after_error;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
      GLR_MAKE_POSIX_ERROR(err, "setsockopt(SO_REUSEPORT) failed");
      goto cleanup_after_error;
    }
  }

  size_t sockaddr_len = sizeof(*addr);
  if (addr->ss_family == AF_UNIX) {
    sockaddr_len = sizeof(struct sockaddr_un);
  }
  int rc = bind(fd, (const struct sockaddr *)(addr), sockaddr_len);
  if (rc < 0) {
    GLR_MAKE_POSIX_ERROR(err, "bind(...) failed");
    goto cleanup_after_error;
  }

  rc = listen(fd, backlog);
  if (rc < 0) {
    GLR_MAKE_POSIX_ERROR(err, "listen(...) failed");
    goto cleanup_after_error;
  }

  glr_fd_t *result = glr_init_fd(fd, err);
  if (err->error) {
    err->error = GLR_GENERAL_ERROR;
    err->sub_error = 1;
    glr_stringbuilder_printf(&err->msg, "\n%s:%d:%s glr_make_fd() failed",
                             __FILE__, __LINE__, __func__);
    goto cleanup_after_error;
  }
  return result;
cleanup_after_error:
  if (fd > 0) {
    close(fd);
  }
  return NULL;
}

struct sockaddr_storage glr_socket_local_address(glr_fd_t *fd, err_t *err) {
  if (err->error) return (struct sockaddr_storage){};

  struct sockaddr_storage result = {};
  socklen_t len = sizeof(result);
  int rc = getsockname(fd->poll.fd, (struct sockaddr *)&result, &len);
  if (rc != 0) {
    GLR_MAKE_POSIX_ERROR(err, "getsockname(...) failed");
    return result;
  }
  return result;

}

typedef struct {
  int timer_fired;
  glr_exec_context_t *ctx;
} glr_fd_wait_timer_state_t;

void glr_fd_wait_timer_cb(glr_timer_t *t) {
  glr_fd_wait_timer_state_t *timer_state = t->arg;
  timer_state->timer_fired = 1;
  glr_scheduler_add(timer_state->ctx);
}

void glr_fd_wait_until(glr_fd_t *fd, int state, int64_t deadline, err_t *err) {
  if (err->error) return;

  glr_exec_context_t *cur_ctx = glr_current_context();
  glr_fd_wait_timer_state_t timer_state = {};
  timer_state.ctx = cur_ctx;

  glr_timer_t t = {};
  t.callback = glr_fd_wait_timer_cb;
  t.arg = &timer_state;
  t.deadline_posix_milliseconds = deadline;

  if (deadline != 0) {
    int64_t now = glr_timestamp_in_ms();
    if (now >= deadline) {
      err->error = GLR_TIMEOUT_ERROR;
      err->msg = glr_make_stringbuilder(256);
      glr_stringbuilder_printf(&err->msg, "%s:%d:%s deadline was reached",
                               __FILE__, __LINE__, __func__);
      return;
    }
    glr_add_timer(&t);
  }

  fd->ctx = cur_ctx;
  fd->desired_epoll_flags = state;

  glr_scheduler_yield(0);
  fd->desired_epoll_flags = 0;

  if (deadline != 0 && !timer_state.timer_fired) {
    glr_remove_timer(&t);
  }

  if (deadline != 0 && timer_state.timer_fired) {
    err->error = GLR_TIMEOUT_ERROR;
    err->msg = glr_make_stringbuilder(256);
    glr_stringbuilder_printf(&err->msg, "%s:%d:%s deadline was reached",
                             __FILE__, __LINE__, __func__);
    return;
  }
}

void glr_close(glr_fd_t *fd) {
  int rc = 0;
  rc = close(fd->poll.fd);

  if (rc != 0 && errno == EINTR) {
    rc = close(fd->poll.fd);
  }

#ifdef GLR_SSL
  if (fd->ssl) {
    SSL_free(fd->ssl);
  }
#endif

  glr_runtime_t *r = &glr_runtime;
  *(glr_fd_t **) fd = r->fd_freelist;
  r->fd_freelist = fd;
}

int glr_fd_get_native(glr_fd_t *fd) {
  return fd->poll.fd;
}

glr_accept_result_t glr_raw_accept(glr_fd_t *listener, err_t *err) {
  glr_accept_result_t result = {};
  if (err->error) return result;

  socklen_t len = sizeof(result.address);

  for (;;) {
    int fd = -1;
    fd = accept4(glr_fd_get_native(listener),
                 (struct sockaddr *)&result.address, &len,
                 SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd >= 0) {
      result.con = glr_init_fd(fd, err);
      return result;
    }

    switch (errno) {
    case ECONNABORTED:
    case EINTR: {
      continue;
    } break;
    //case EAGAIN:
    case EWOULDBLOCK:
    case ENETDOWN:
    case EPROTO:
    case ENOPROTOOPT:
    case EHOSTDOWN:
    case ENONET:
    case EHOSTUNREACH:
    case ENETUNREACH: {
      glr_fd_wait_until(listener, EPOLLIN, 0, err);
      if (err->error) {
        glr_stringbuilder_printf(&err->msg, "\n%s:%d:%s glr_fd_wait_until failed",
                                 __FILE__, __LINE__, __func__);
        return (glr_accept_result_t){};
      }
    } break;
    default: {
      GLR_MAKE_POSIX_ERROR(err, "accept4() failed");
      return result;
    }
    }
  }
}

glr_fd_t *glr_raw_connect(const struct sockaddr_storage *addr, int64_t deadline, err_t *err) {
  if (err->error) return NULL;
  int fd = socket(addr->ss_family, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
  if (fd < 0) {
    GLR_MAKE_POSIX_ERROR(err, "socket() failed");
    return NULL;
  }

  size_t sockaddr_len = sizeof(*addr);
  if (addr->ss_family == AF_UNIX) {
    sockaddr_len = sizeof(struct sockaddr_un);
  }
  int rc = 0;

  do {
    rc = connect(fd, (struct sockaddr *) addr, sockaddr_len);
  } while (rc != 0 && errno == EINTR);
  int saved_errno = errno;

  if (rc && errno != EINPROGRESS) {
    GLR_MAKE_POSIX_ERROR(err, "connect() failed");
    close(fd);
    return NULL;
  }

  glr_fd_t *result = glr_init_fd(fd, err);
  if (err->error) {
    glr_stringbuilder_printf(&err->msg, "\n%s:%d:%s glr_init_fd() failed",
                             __FILE__, __LINE__, __func__);
    close(fd);
    return NULL;
  }

  if (saved_errno == EINPROGRESS) {
    glr_fd_wait_until(result, EPOLLOUT|EPOLLHUP|EPOLLERR, deadline, err);
    if (err->error) {
      goto cleanup;
    }
    if (result->poll.last_epoll_event_bitset & (EPOLLHUP|EPOLLERR)) {
      err->error = GLR_GENERAL_ERROR;
      err->msg = glr_make_stringbuilder(256);
      glr_stringbuilder_printf(
          &err->msg,
          "%s:%d:%s connection was interupted before connect was established",
          __FILE__, __LINE__, __func__);
      goto cleanup;
    }
  }

  return result;
cleanup:
  glr_close(result);
  return NULL;
}

void glr_fd_set_deadline(glr_fd_t *fd, int64_t deadline) {
  fd->deadline = deadline;
}

int glr_fd_raw_send(glr_fd_t *fd, const char *data, int len, err_t *err) {
  if (err->error) return -1;
  for (;;) {
    int result = send(glr_fd_get_native(fd), data, len, MSG_NOSIGNAL);
    if (result >= 0) return result;
    if (errno == EINTR) continue;
    if (errno != EAGAIN) {
      GLR_MAKE_POSIX_ERROR(err, ": syscall send(..., ..., %d) failed", len);
      return -1;
    }
    glr_fd_wait_until(fd, EPOLLOUT|EPOLLHUP|EPOLLERR, fd->deadline, err);
    if (err->error) {
      glr_stringbuilder_printf(
          &err->msg, "\n%s:%d:%s glr_fd_wait_until(EPOLLOUT|EPOLLHUP|EPOLLERR)",
          __FILE__, __LINE__, __func__);
      return -1;
    }
  }
}


int glr_fd_raw_recv(glr_fd_t *fd, char *data, int len, err_t *err) {
  if (err->error) return -1;
  for (;;) {
    int result = recv(glr_fd_get_native(fd), data, len, MSG_NOSIGNAL);
    if (result >= 0) return result;
    if (errno == EINTR) continue;
    if (errno != EAGAIN) {
      GLR_MAKE_POSIX_ERROR(err, ": syscall recv(..., ..., %d) failed", len);
      return -1;
    }
    glr_fd_wait_until(fd, EPOLLIN|EPOLLRDHUP|EPOLLERR, fd->deadline, err);
    if (err->error) {
      glr_stringbuilder_printf(
          &err->msg, "\n%s:%d:%s glr_fd_wait_until(EPOLLIN|EPOLLRDHUP|EPOLLERR)",
          __FILE__, __LINE__, __func__);
      return -1;
    }
  }
}

void glr_fd_raw_shutdown(glr_fd_t *fd, err_t *err) {
  if (err->error) return;
  int result = shutdown(glr_fd_get_native(fd), SHUT_RDWR);
  if (result == -1) {
    GLR_MAKE_POSIX_ERROR(err, ": syscall shutdown(..., SHUT_RDWR) failed");
  }
}

//SSL
const char *glr_ssl_error = "GLR_SSL_ERROR";

#ifdef GLR_SSL

SSL_CTX *glr_ssl_server_context() {
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
  SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);

  // To avoid server trying to send data after main handshake causing
  // unnecessary EPIPE
  SSL_CTX_set_num_tickets(ctx, 0);

  return ctx;
}

SSL_CTX *glr_ssl_client_context() {
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
  SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
  SSL_CTX_set_default_verify_paths(ctx);

  return ctx;
}

void glr_ssl_ctx_set_verify_peer(SSL_CTX *ctx, int verify) {
  if (verify) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  } else {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  }
}

static int glr_ssl_password_cb(char *buf, int size, int rwflag,
                                void *u) {
  (void)rwflag;
  (void)size;
  //TODO should look into case when buffer size is smaller than password
  const char *passphrase = u;
  int passphrase_length = strlen(passphrase);
  memcpy(buf, passphrase, passphrase_length);
  return passphrase_length;
}

void glr_ssl_ctx_set_key(SSL_CTX *ctx, const char *path,
                             const char *password, err_t *error) {
  if (error->error) return;

  if (!SSL_CTX_use_PrivateKey_file(ctx, path, SSL_FILETYPE_PEM)) {
    error->error = GLR_SSL_ERROR;
    error->msg = glr_make_stringbuilder(256);
    glr_stringbuilder_printf(&error->msg,
                             "%s:%d:%s SSL_CTX failed to set PrivateKey file",
                             __FILE__, __LINE__, __func__);
    return;
  }

  if (password) {
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)password);
    SSL_CTX_set_default_passwd_cb(ctx, glr_ssl_password_cb);
  }
}

void glr_ssl_ctx_set_cert(SSL_CTX *ctx, const char *path, err_t *error) {
  if (error->error) return;

  if (!SSL_CTX_use_certificate_chain_file(ctx, path)) {
    error->error = GLR_SSL_ERROR;
    error->msg = glr_make_stringbuilder(256);
    glr_stringbuilder_printf(&error->msg,
                             "%s:%d:%s SSL_CTX failed to set certificate file",
                             __FILE__, __LINE__, __func__);

  }
}

static int glr_ssl_bio_init(BIO *bio) {
  BIO_set_init(bio, 1);
  return 1;
}

static int glr_ssl_bio_write(BIO *bio, const char *data, int len) {
  glr_fd_t *conn = BIO_get_data(bio);
  err_t err = {};
  int n = glr_fd_raw_send(conn, data, len, &err);
  if (err.error) {
    glr_err_cleanup(&err);
    return -1;
    //TODO: logging or error forwarding via glr_fd_t*
  }
  return n;
}

static int glr_ssl_bio_read(BIO *bio, char *data, int len) {
  glr_fd_t *conn = BIO_get_data(bio);
  err_t err = {};
  int n = glr_fd_raw_recv(conn, data, len, &err);
  if (err.error) {
    glr_err_cleanup(&err);
    return -1;
    //TODO: logging or error forwarding via glr_fd_t*
  }
  return n;

}

static long glr_ssl_bio_ctrl(BIO *bio, int cmd, long num, void *user) {
  (void) user;
  (void) num;
  (void) cmd;
  (void) bio;
  switch (cmd) {
    case BIO_CTRL_FLUSH:
      return 1;
    default:
      return 0;
  }
}

BIO_METHOD *glr_ssl_get_bio_method() {
  glr_runtime_t *r = glr_cur_thread_runtime();
  if (!r->ssl_bio_method) {
    int idx = BIO_get_new_index();
    r->ssl_bio_method = BIO_meth_new(idx, "GLR ssl stream");
    BIO_meth_set_create(r->ssl_bio_method, glr_ssl_bio_init);
    BIO_meth_set_write(r->ssl_bio_method, glr_ssl_bio_write);
    BIO_meth_set_read(r->ssl_bio_method, glr_ssl_bio_read);
    BIO_meth_set_ctrl(r->ssl_bio_method, glr_ssl_bio_ctrl);
  }
  return r->ssl_bio_method;
}

static int glr_ssl_error_cb(const char *line, size_t len, void *data) {
  stringbuilder_t *sb = data;
  glr_stringbuilder_append(sb, line, len);
  glr_stringbuilder_append(sb, "\n", 1);
  return 1;
}

static str_t glr_ssl_get_error_msg() {
  stringbuilder_t sb = glr_make_stringbuilder(256);
  ERR_print_errors_cb(glr_ssl_error_cb, &sb);
  return glr_stringbuilder_build(&sb);
}

void glr_ssl_client_conn_handshake(SSL_CTX *ctx, glr_fd_t *conn,
                                   const char *hostname, int64_t deadline,
                                   err_t *err) {
  if (err->error) return;
  SSL *ssl = SSL_new(ctx);
  BIO *bio = BIO_new(glr_ssl_get_bio_method());
  BIO_set_data(bio, conn);
  SSL_set_bio(ssl, bio, bio);
  SSL_set_connect_state(ssl);
  BIO_set_conn_hostname(bio, hostname);
  glr_fd_set_deadline(conn, deadline);
  conn->ssl = ssl;

  if (SSL_do_handshake(ssl) < 0) {
    str_t err_str = glr_ssl_get_error_msg();
    err->error = GLR_SSL_ERROR;
    err->msg = glr_make_stringbuilder(256);
    glr_stringbuilder_printf(&err->msg,
                             "%s:%d:%s SSL_do_handshake failed: %.*s", __FILE__,
                             __LINE__, __func__, err_str.len, err_str.data);
    glr_free(err_str.data);
    return;
  }
}

void glr_ssl_server_conn_upgrade(SSL_CTX *ctx, glr_fd_t *conn, int64_t deadline,
                     err_t *err) {
  glr_fd_set_deadline(conn, deadline);

  SSL *ssl = SSL_new(ctx);
  conn->ssl = ssl;

  BIO *bio = BIO_new(glr_ssl_get_bio_method());
  BIO_set_data(bio, conn);
  SSL_set_bio(ssl, bio, bio);
  if (SSL_accept(ssl) < 0) {
    str_t err_str = glr_ssl_get_error_msg();
    err->error = GLR_SSL_ERROR;
    err->msg = glr_make_stringbuilder(256);
    glr_stringbuilder_printf(&err->msg,
                             "%s:%d:%s SSL_do_handshake failed: %.*s", __FILE__,
                             __LINE__, __func__, err_str.len, err_str.data);
    glr_free(err_str.data);
    return;
  }
}

int glr_ssl_read(glr_fd_t *impl, char *buffer, size_t len, err_t *err) {
  if (err->error) return 0;

  SSL *ssl = impl->ssl;
  int n = SSL_read(ssl, buffer, len);
  if (glr_unlikely(n <= 0)) {
    switch (SSL_get_error(ssl, n)) {
      case SSL_ERROR_ZERO_RETURN: {
        return 0;
      } break;
      default: {
        str_t err_str = glr_ssl_get_error_msg();
        err->error = GLR_SSL_ERROR;
        err->msg = glr_make_stringbuilder(256);
        glr_stringbuilder_printf(
            &err->msg, "%s:%d:%s SSL_read failed: %.*s", __FILE__,
            __LINE__, __func__, err_str.len, err_str.data);
        glr_free(err_str.data);
        return 0;
      }
    }
  }
  return n;
}

int glr_ssl_write(glr_fd_t *impl, const char *buffer, size_t len, err_t *err) {
  SSL *ssl = impl->ssl;
  int n = SSL_write(ssl, buffer, len);
  if (glr_unlikely(n <= 0)) {
    switch (SSL_get_error(ssl, n)) {
      case SSL_ERROR_ZERO_RETURN: {
        return 0;
      } break;
      default: {
        str_t err_str = glr_ssl_get_error_msg();
        err->error = GLR_SSL_ERROR;
        err->msg = glr_make_stringbuilder(256);
        glr_stringbuilder_printf(
            &err->msg, "%s:%d:%s SSL_write failed: %.*s", __FILE__,
            __LINE__, __func__, err_str.len, err_str.data);
        glr_free(err_str.data);
        return 0;
      }
    }
  }
  return n;
}

void glr_ssl_shutdown(glr_fd_t *impl) {
  SSL *ssl = (SSL *) impl->ssl;
  SSL_shutdown(ssl);
}

SSL *glr_fd_conn_get_ssl(glr_fd_t *impl) {
  return impl->ssl;
}

SSL_CTX *glr_get_default_client_ssl_ctx() {
  glr_runtime_t *r = glr_cur_thread_runtime();
  if (!r->ssl_client_default_ctx) {
    r->ssl_client_default_ctx = glr_ssl_client_context();
  }
  return r->ssl_client_default_ctx;
}

#endif

//Network connection convenience
glr_fd_t *glr_tcp_dial_hostname_port_ex(const char *host, const char *port,
                                        int ssl, int64_t deadline, err_t *err) {
  if (err->error) return NULL;
  //FIXME: may block indefinetely in case of network issues
  struct sockaddr_storage sockaddr = glr_resolve_address(host, port, err);
  if (err->error) {
    glr_stringbuilder_printf(&err->msg, "\n%s:%d:%s failed to resolve address",
                             __FILE__, __LINE__, __func__);
    return NULL;
  }

  glr_fd_t *conn = glr_raw_connect(&sockaddr, deadline, err);
  if (err->error) {
    glr_stringbuilder_printf(&err->msg, "\n%s:%d:%s failed to connect",
                             __FILE__, __LINE__, __func__);
    return NULL;
  }

#ifdef GLR_SSL
  if (ssl) {
    SSL_CTX *ctx = glr_get_default_client_ssl_ctx();

    glr_ssl_client_conn_handshake(ctx, conn, host, deadline, err);

    if (err->error) {
      glr_stringbuilder_printf(&err->msg, "\n%s:%d:%s failed to perform ssl handshake",
                               __FILE__, __LINE__, __func__);
      return NULL;
    }
  }
#endif

  return conn;
}

glr_fd_t *glr_tcp_dial_addr(const char *addr, int64_t deadline, err_t *err) {
  if (err->error) return NULL;

  const char *host_begin = addr;
  const char *last_colon = NULL;
  const char *it = addr;

  while (*it) {
    if (*it == ':') {
      last_colon = it;
    }
    ++it;
  }

  if (last_colon == NULL) {
    err->error = GLR_INVALID_ARGUMENT_ERROR;
    err->sub_error = 0;
    glr_stringbuilder_printf(
        &err->msg, "%s:%d:%s failed to split \"%s\" to host and port\n",
        __FILE__, __LINE__, __func__, addr);

    NULL;
  }

  const char *port_end = it;
  const char *port_begin = last_colon + 1;
  const char *host_end = last_colon;

  char host[host_end - host_begin + 1];
  char port[port_end - port_begin + 1];
  strncpy(host, host_begin, host_end - host_begin);
  host[host_end - host_begin] = 0;
  strncpy(port, port_begin, port_end - port_begin);
  port[port_end - port_begin] = 0;

  return glr_tcp_dial_hostname_port_ex(host, port, 0, deadline, err);
}

glr_fd_t *glr_tcp_dial_hostname_port(const char *hostname, const char *port,
                                     int64_t deadline, err_t *err) {
  return glr_tcp_dial_hostname_port_ex(hostname, port, 0, deadline, err);
}

glr_fd_t *glr_tcp_dial_hostname_port2(const char *hostname, uint16_t port,
                                      int64_t deadline, err_t *err) {
  char port_buffer[7] = {0};
  snprintf(port_buffer, sizeof(port_buffer), "%d", port);
  return glr_tcp_dial_hostname_port_ex(hostname, port_buffer, 0, deadline, err);
}

#ifdef GLR_SSL
glr_fd_t *glr_tcp_dial_addr_ssl(const char *addr, int64_t deadline, err_t *err) {
  const char *host_begin = addr;
  const char *last_colon = NULL;
  const char *it = addr;

  while (*it) {
    if (*it == ':') {
      last_colon = it;
    }
    ++it;
  }

  if (last_colon == NULL) {
    err->error = GLR_INVALID_ARGUMENT_ERROR;
    err->sub_error = 0;
    glr_stringbuilder_printf(
        &err->msg, "%s:%d:%s failed to split \"%s\" to host and port\n",
        __FILE__, __LINE__, __func__, addr);

    NULL;
  }

  const char *port_end = it;
  const char *port_begin = last_colon + 1;
  const char *host_end = last_colon;

  char host[host_end - host_begin + 1];
  char port[port_end - port_begin + 1];
  strncpy(host, host_begin, host_end - host_begin);
  host[host_end - host_begin] = 0;
  strncpy(port, port_begin, port_end - port_begin);
  port[port_end - port_begin] = 0;

  return glr_tcp_dial_hostname_port_ex(host, port, 1, deadline, err);
}

glr_fd_t *glr_tcp_dial_hostname_port_ssl(const char *hostname, const char *port,
                                         int64_t deadline, err_t *err) {

  return glr_tcp_dial_hostname_port_ex(hostname, port, 1, deadline, err);
}

glr_fd_t *glr_tcp_dial_hostname_port_ssl2(const char *hostname, uint16_t port,
                                          int64_t deadline, err_t *err) {
  char port_buffer[7] = {0};
  snprintf(port_buffer, sizeof(port_buffer), "%d", port);
  return glr_tcp_dial_hostname_port_ex(hostname, port_buffer, 1, deadline, err);
}

#endif

int glr_fd_conn_send(glr_fd_t *conn, const char *data, size_t len, err_t *err) {
  if (err->error) return -1;
#ifdef GLR_SSL
  if (conn->ssl) return glr_ssl_write(conn, data, len, err);
#endif
  return glr_fd_raw_send(conn, data, len, err);
}

int glr_fd_conn_recv(glr_fd_t *conn, char *data, size_t len, err_t *err) {
  if (err->error) return -1;
#ifdef GLR_SSL
  if (conn->ssl) return glr_ssl_read(conn, data, len, err);
#endif
  return glr_fd_raw_recv(conn, data, len, err);
}

void glr_fd_conn_shutdown(glr_fd_t *conn, err_t *err) {
  if (err->error) return;
#ifdef GLR_SSL
  if (conn->ssl) return glr_ssl_shutdown(conn);
#endif
  return glr_fd_raw_shutdown(conn, err);
}

int glr_fd_conn_send_exactly(glr_fd_t *conn, const char *data, size_t len, err_t *err) {
  size_t sent = 0;
  while (sent < len) {
    int n = glr_fd_conn_send(conn, data + sent, len - sent, err);
    if (n <= 0 || err->error) return sent;
    sent += n;
  }
  return sent;
}

int glr_fd_conn_recv_exactly(glr_fd_t *conn, char *data, size_t len, err_t *err) {
  size_t have_read = 0;
  while (have_read < len) {
    int n = glr_fd_conn_recv(conn, data + have_read, len - have_read, err);
    if (n <= 0 || err->error) return have_read;
    have_read += n;
  }
  return have_read;
}
