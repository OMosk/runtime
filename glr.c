#include "glr.h"

#include <malloc.h>
#include <fcntl.h>
#include <pthread.h>
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
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

#define GLR_TRACE fprintf(stderr, "%s:%d:%s\n", __FILE__, __LINE__, __func__)
#define GLR_TRACES(X) fprintf(stderr, "%s:%d:%s " X "\n", __FILE__, __LINE__, __func__)

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
  glr_logger_t *logger;
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

#ifdef GLR_CURL
  CURLM *curl_multi_handle;
  glr_timer_t curl_timer;
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

static glr_allocator_t glr_default_allocator = {
  .data = NULL, .func = glr_malloc_free_adapter, .next = NULL
};

glr_allocator_t* glr_get_default_allocator() {
  return &glr_default_allocator;
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

glr_allocator_t glr_create_transient_allocator(glr_allocator_t *parent) {
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
      glr_runtime.cached_default_allocator = *glr_get_default_allocator();
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
    glr_free(old_blocks);
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

#ifdef GLR_CURL
  if (r->curl_multi_handle) {
    curl_multi_cleanup(r->curl_multi_handle);
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
  result->logger = NULL;
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
inline void glr_err_cleanup(glr_error_t *err) {
  glr_stringbuilder_free_buffers(&err->msg);
  *err = (glr_error_t) {};
}

const char *glr_posix_error = "GLR_POSIX_ERROR";

void glr_make_posix_error(glr_error_t *err, const char *file, int line,
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

  glr_error_t err = {};
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

void glr_add_poll(glr_poll_t *poll, int flags, glr_error_t *err) {
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

void glr_change_poll(glr_poll_t *poll, int flags, glr_error_t *err) {
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

void glr_remove_poll(glr_poll_t *poll, glr_error_t *err) {
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

int glr_wait_for(int fd, uint32_t flags, glr_error_t *err) {
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
    //abort();
    return;
    //will treat timers as set, trying to remove item from set that is not there probably not an error
    //this behavior is used for timer in curl multi handle thing
  }

  if (r->timers[idx] != t) {
    //TODO: log message should be here
    //this is caused by error of library user
    //abort();
    //will treat timers as set, trying to remove item from set that is not there probably not an error
    //this behavior is used for timer in curl multi handle thing
    return;
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
                                            glr_error_t *err) {
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
                                             glr_error_t *err) {
  char port_buffer[10];
  snprintf(port_buffer, 10, "%d", port);
  return glr_resolve_address(host, port_buffer, err);
}


struct sockaddr_storage glr_resolve_address2(const char *addr, glr_error_t *err) {
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

glr_fd_t *glr_init_fd(int fd, glr_error_t *err) {
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
                     int reuse_addr, glr_error_t *err) {
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

struct sockaddr_storage glr_socket_local_address(glr_fd_t *fd, glr_error_t *err) {
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

void glr_fd_wait_until(glr_fd_t *fd, int state, int64_t deadline, glr_error_t *err) {
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

glr_accept_result_t glr_raw_accept(glr_fd_t *listener, glr_error_t *err) {
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

glr_fd_t *glr_raw_connect(const struct sockaddr_storage *addr, int64_t deadline, glr_error_t *err) {
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

int glr_fd_raw_send(glr_fd_t *fd, const char *data, int len, glr_error_t *err) {
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


int glr_fd_raw_recv(glr_fd_t *fd, char *data, int len, glr_error_t *err) {
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

void glr_fd_raw_shutdown(glr_fd_t *fd, glr_error_t *err) {
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
                             const char *password, glr_error_t *error) {
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

void glr_ssl_ctx_set_cert(SSL_CTX *ctx, const char *path, glr_error_t *error) {
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
  glr_error_t err = {};
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
  glr_error_t err = {};
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
                                   glr_error_t *err) {
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
                     glr_error_t *err) {
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

int glr_ssl_read(glr_fd_t *impl, char *buffer, size_t len, glr_error_t *err) {
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

int glr_ssl_write(glr_fd_t *impl, const char *buffer, size_t len, glr_error_t *err) {
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
                                        int ssl, int64_t deadline, glr_error_t *err) {
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

glr_fd_t *glr_tcp_dial_addr(const char *addr, int64_t deadline, glr_error_t *err) {
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
                                     int64_t deadline, glr_error_t *err) {
  return glr_tcp_dial_hostname_port_ex(hostname, port, 0, deadline, err);
}

glr_fd_t *glr_tcp_dial_hostname_port2(const char *hostname, uint16_t port,
                                      int64_t deadline, glr_error_t *err) {
  char port_buffer[7] = {0};
  snprintf(port_buffer, sizeof(port_buffer), "%d", port);
  return glr_tcp_dial_hostname_port_ex(hostname, port_buffer, 0, deadline, err);
}

#ifdef GLR_SSL
glr_fd_t *glr_tcp_dial_addr_ssl(const char *addr, int64_t deadline, glr_error_t *err) {
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
                                         int64_t deadline, glr_error_t *err) {

  return glr_tcp_dial_hostname_port_ex(hostname, port, 1, deadline, err);
}

glr_fd_t *glr_tcp_dial_hostname_port_ssl2(const char *hostname, uint16_t port,
                                          int64_t deadline, glr_error_t *err) {
  char port_buffer[7] = {0};
  snprintf(port_buffer, sizeof(port_buffer), "%d", port);
  return glr_tcp_dial_hostname_port_ex(hostname, port_buffer, 1, deadline, err);
}

#endif

int glr_fd_conn_send(glr_fd_t *conn, const char *data, size_t len, glr_error_t *err) {
  if (err->error) return -1;
#ifdef GLR_SSL
  if (conn->ssl) return glr_ssl_write(conn, data, len, err);
#endif
  return glr_fd_raw_send(conn, data, len, err);
}

int glr_fd_conn_recv(glr_fd_t *conn, char *data, size_t len, glr_error_t *err) {
  if (err->error) return -1;
#ifdef GLR_SSL
  if (conn->ssl) return glr_ssl_read(conn, data, len, err);
#endif
  return glr_fd_raw_recv(conn, data, len, err);
}

void glr_fd_conn_shutdown(glr_fd_t *conn, glr_error_t *err) {
  if (err->error) return;
#ifdef GLR_SSL
  if (conn->ssl) return glr_ssl_shutdown(conn);
#endif
  return glr_fd_raw_shutdown(conn, err);
}

int glr_fd_conn_send_exactly(glr_fd_t *conn, const char *data, size_t len, glr_error_t *err) {
  size_t sent = 0;
  while (sent < len) {
    int n = glr_fd_conn_send(conn, data + sent, len - sent, err);
    if (n <= 0 || err->error) return sent;
    sent += n;
  }
  return sent;
}

int glr_fd_conn_recv_exactly(glr_fd_t *conn, char *data, size_t len, glr_error_t *err) {
  size_t have_read = 0;
  while (have_read < len) {
    int n = glr_fd_conn_recv(conn, data + have_read, len - have_read, err);
    if (n <= 0 || err->error) return have_read;
    have_read += n;
  }
  return have_read;
}

//Logging
void glr_logger_flush(glr_logger_t *logger);

struct glr_logger_t {
  int fd;
  int own;
  pthread_mutex_t mtx;
  glr_log_level_t min_level;
  uint16_t buffer_used;
  char buffer[4096];
};

void glr_log_start_flusher_thread();
void glr_log_stop_flusher_thread();

static glr_logger_t glr_stdout_logger = {
  .fd = STDIN_FILENO, .own = 0, .mtx = PTHREAD_MUTEX_INITIALIZER,
};

static glr_logger_t glr_stderr_logger = {
  .fd = STDERR_FILENO, .own = 0, .mtx = PTHREAD_MUTEX_INITIALIZER,
};

static glr_logger_t *glr_default_logger = &glr_stderr_logger;
glr_logger_t *glr_get_default_logger() {
  return glr_default_logger;
}

void glr_set_default_logger(glr_logger_t *logger) {
  glr_default_logger = logger;
}

glr_logger_t *glr_get_logger() {
  glr_exec_context_t *ctx = glr_current_context();
  if (ctx->logger) return ctx->logger;
  return glr_get_default_logger();
}

void glr_set_logger(glr_logger_t *logger) {
  glr_exec_context_t *ctx = glr_current_context();
  ctx->logger = logger;
}

void glr_set_min_log_level(glr_logger_t *logger, glr_log_level_t level) {
  logger->min_level = level;
}

glr_logger_t *glr_get_stdout_logger() {
  return &glr_stdout_logger;
}

glr_logger_t *glr_get_stderr_logger() {
  return &glr_stderr_logger;
}

static glr_logger_t *glr_log_flusher_thread_list[128] = {
  &glr_stdout_logger, &glr_stderr_logger,
};
static int glr_log_flusher_thread_list_len = 2;
static pthread_mutex_t glr_log_flusher_list_mtx = PTHREAD_MUTEX_INITIALIZER;

static pthread_t glr_log_flusher_thread;
static pthread_once_t glr_log_flusher_thread_is_iniitialized = PTHREAD_ONCE_INIT;
static pthread_once_t glr_log_atexit_is_iniitialized = PTHREAD_ONCE_INIT;
static atomic_int glr_log_flusher_thread_should_stop;

struct glr_logger_t *glr_logger_create(const char *filename, glr_error_t *e) {
  if (e->error) return NULL;

  int permissions = 0600;
  int fd = open(filename, O_WRONLY|O_APPEND|O_CREAT, permissions);
  if (fd < 0) {
    GLR_MAKE_POSIX_ERROR(
        e, ": open (%s) O_APPEND|O_CREATE with permissions(%o) failed",
        filename, permissions);
    return NULL;
  }

  struct glr_logger_t *result = GLR_ALLOCATE_TYPE(struct glr_logger_t);
  result->fd = fd;
  result->own = 1;
  result->buffer_used = 0;
  result->min_level = GLR_LOG_LEVEL_TRACE;
  pthread_mutex_init(&result->mtx, NULL);

  glr_log_start_flusher_thread();

  pthread_mutex_lock(&glr_log_flusher_list_mtx);
  glr_log_flusher_thread_list[glr_log_flusher_thread_list_len++] = result;
  pthread_mutex_unlock(&glr_log_flusher_list_mtx);

  return result;
}

void glr_logger_destroy(struct glr_logger_t *logger) {
  glr_logger_flush(logger);

  pthread_mutex_lock(&glr_log_flusher_list_mtx);
  for (int i = 0; i < glr_log_flusher_thread_list_len; ++i) {
    if (glr_log_flusher_thread_list[i] == logger) {
      glr_log_flusher_thread_list[i]
        = glr_log_flusher_thread_list[--glr_log_flusher_thread_list_len];
      break;
    }
  }
  pthread_mutex_unlock(&glr_log_flusher_list_mtx);

  pthread_mutex_destroy(&logger->mtx);
  glr_free(logger);
}

str_t glr_log_level_trace_str   = GLR_STR_LITERAL("[trace]");
str_t glr_log_level_debug_str   = GLR_STR_LITERAL("[debug]");
str_t glr_log_level_info_str    = GLR_STR_LITERAL("[info] ");
str_t glr_log_level_warning_str = GLR_STR_LITERAL("[warn] ");
str_t glr_log_level_error_str   = GLR_STR_LITERAL("[error]");
str_t glr_log_level_crit_str    = GLR_STR_LITERAL("[crit] ");

static void glr_safe_write(int fd, const char *data, int len) {
  // for file FD and less than 4096 bytes of data writes should be atomic, but
  // if write was interrupted by a signal there are cases ...
  // See NOTES https://linux.die.net/man/2/write
  int written = 0;
  int n = 0;
  while (written < len) {
    n = write(fd, data + written, len - written);
    printf("called write(..) = %d\n", n);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      } else {
        //Our logging system failed, totally unexpected error happened
        //TODO: decide what to do here
        perror(strerror(errno));
        abort();
      }
    }
    written += n;
  }
}

void glr_logger_flush(glr_logger_t *logger) {
  glr_safe_write(logger->fd, logger->buffer, logger->buffer_used);
  fdatasync(logger->fd);
  logger->buffer_used = 0;
}

void glr_flush_logs() {
  pthread_mutex_lock(&glr_log_flusher_list_mtx);
  for (int i = 0; i < glr_log_flusher_thread_list_len; ++i) {
    glr_logger_t *logger = glr_log_flusher_thread_list[i];
    pthread_mutex_lock(&logger->mtx);
    if (logger->buffer_used) {
      glr_logger_flush(logger);
    }
    pthread_mutex_unlock(&logger->mtx);
  }
  pthread_mutex_unlock(&glr_log_flusher_list_mtx);
}

void* glr_log_flusher_thread_func() {
  while (!glr_log_flusher_thread_should_stop) {
    glr_flush_logs();
    sleep(1/*seconds*/);
  }
  return NULL;
}

void glr_log_start_flusher_thread_fn() {
  pthread_create(&glr_log_flusher_thread, NULL, glr_log_flusher_thread_func,
                 NULL);
}

void glr_log_cleanup_atexit_fn() {
  glr_flush_logs();
}

void glr_log_cleanup_atexit_once_setup_fn() {
  atexit(glr_log_cleanup_atexit_fn);
}

void glr_log_start_flusher_thread() {
  pthread_once(&glr_log_flusher_thread_is_iniitialized,
               glr_log_start_flusher_thread_fn);

  pthread_once(&glr_log_atexit_is_iniitialized,
               glr_log_cleanup_atexit_once_setup_fn);
}

void glr_log_stop_flusher_thread() {
  glr_log_flusher_thread_should_stop = 1;
  pthread_join(glr_log_flusher_thread, NULL);
  glr_log_flusher_thread_is_iniitialized = PTHREAD_ONCE_INIT;
}

void glr_log_detailed(glr_logger_t *logger, glr_log_level_t level,
                      cstr_t source_location, cstr_t function_name,
                      const char *format, ...) {
  if (logger->min_level > level) {
    return;
  }
  glr_allocator_t a = glr_create_transient_allocator(glr_get_default_allocator());
  glr_push_allocator(&a);

  char datetime_buffer[128];
  int64_t ts_in_milliseconds = glr_timestamp_in_ms();
  time_t ts_in_seconds = ts_in_milliseconds / 1000;
  int32_t milliseconds = ts_in_milliseconds % 1000;

  struct tm ts_breakdown = {};
  gmtime_r(&ts_in_seconds, &ts_breakdown);

  int datetime_len = strftime(datetime_buffer, sizeof(datetime_buffer) - 1,
                              "%F %T.", &ts_breakdown);

  datetime_len += snprintf(datetime_buffer + datetime_len,
                           sizeof(datetime_buffer) - datetime_len - 1, "%03d",
                           milliseconds);

  str_t level_str = {};
  switch (level) {
    case GLR_LOG_LEVEL_TRACE: level_str = glr_log_level_trace_str; break;
    case GLR_LOG_LEVEL_DEBUG: level_str = glr_log_level_debug_str; break;
    case GLR_LOG_LEVEL_INFO: level_str = glr_log_level_info_str; break;
    case GLR_LOG_LEVEL_WARNING: level_str = glr_log_level_warning_str; break;
    case GLR_LOG_LEVEL_ERROR: level_str = glr_log_level_error_str; break;
    case GLR_LOG_LEVEL_CRITICAL: level_str = glr_log_level_crit_str; break;
  }

  stringbuilder_t sb = glr_make_stringbuilder(512);
  glr_stringbuilder_printf(&sb, "[%.*s] [%.*s:%.*s] %.*s ",
                           datetime_len, datetime_buffer,
                           source_location.len, source_location.data,
                           function_name.len, function_name.data,
                           level_str.len, level_str.data);

  va_list va;
  va_start(va, format);
  glr_stringbuilder_vprintf(&sb, format, va);
  va_end(va);
  glr_stringbuilder_append(&sb, "\n", 1);

  str_t entry = glr_stringbuilder_build(&sb);

  //printf("%.*s\n", entry.len, entry.data);

  pthread_mutex_lock(&logger->mtx);

  ssize_t cap = sizeof(logger->buffer);
  ssize_t cap_left = cap - logger->buffer_used;
  if (cap_left < entry.len) {
    glr_logger_flush(logger);
  }

  if (entry.len <= cap) {
    memcpy(logger->buffer + logger->buffer_used, entry.data, entry.len);
    logger->buffer_used += entry.len;
  } else {
    glr_safe_write(logger->fd, entry.data, entry.len);
  }

  pthread_mutex_unlock(&logger->mtx);

  glr_pop_allocator();
  glr_destroy_allocator(&a);
}


#ifdef GLR_CURL
const char *glr_curl_error = "GLR_CURL_ERROR";

typedef struct {
  glr_exec_context_t *in_context;
  CURLcode out_response_code;
  glr_error_t *err;
} glr_curl_callback_info_t;

typedef struct {
  glr_poll_t poll_handle;
  curl_socket_t sockfd;
  CURLM *multi_info;
} glr_curl_socket_data_t;

void glr_curl_check_multi_info();
void glr_curl_on_timeout(glr_timer_t *req);
int glr_curl_handle_socket(CURL * /*easy*/, curl_socket_t s, int action,
                          void *userp, void *socketp);
int glr_curl_start_timer(CURLM * /*multi*/, long timeout_ms, void *userp);

CURLM *glr_get_curl_multi_handle(glr_error_t *err) {
  if (err->error) return NULL;
  glr_runtime_t *r = glr_cur_thread_runtime();
  if (!r->curl_multi_handle) {
    r->curl_multi_handle = curl_multi_init();
    if (!r->curl_multi_handle) {
      err->error = GLR_CURL_ERROR;
      err->msg = glr_make_stringbuilder(256);
      glr_stringbuilder_printf(&err->msg,
                               "%s:%d:%s failed to init multi handle", __FILE__,
                               __LINE__, __func__);
      return NULL;
    }
    curl_multi_setopt(r->curl_multi_handle, CURLMOPT_SOCKETFUNCTION,
                      glr_curl_handle_socket);
    curl_multi_setopt(r->curl_multi_handle, CURLMOPT_SOCKETDATA,
                      r->curl_multi_handle);
    curl_multi_setopt(r->curl_multi_handle, CURLMOPT_TIMERFUNCTION,
                      glr_curl_start_timer);
  }
  return r->curl_multi_handle;
}

void glr_curl_check_multi_info(CURLM *multi_handle) {
  CURLMsg *message;
  int pending;
  CURL *easy_handle;
  glr_curl_callback_info_t *request;

  while ((message = curl_multi_info_read(multi_handle, &pending))) {
    switch (message->msg) {
      case CURLMSG_DONE:
        easy_handle = message->easy_handle;
        curl_easy_getinfo(easy_handle, CURLINFO_PRIVATE, &request);
        if (request) {
          request->out_response_code = message->data.result;
          glr_scheduler_add(request->in_context);
        }
        curl_multi_remove_handle(multi_handle, easy_handle);
        break;
      default:
        // fprintf(stderr, "CURLMSG default\n");
        break;
    }
  }
}

void glr_curl_perform_internal(glr_poll_t *req) {
  glr_curl_socket_data_t *context = req->cb_arg;
  CURLM *multi_info = context->multi_info;
  int flags = 0;
  if (context->poll_handle.last_epoll_event_bitset & EPOLLIN)
    flags |= CURL_CSELECT_IN;
  if (context->poll_handle.last_epoll_event_bitset & EPOLLOUT)
    flags |= CURL_CSELECT_OUT;
  if (context->poll_handle.last_epoll_event_bitset & EPOLLERR)
    flags |= CURL_CSELECT_ERR;

  int running_handles;
  curl_multi_socket_action(multi_info, context->sockfd,
                               flags, &running_handles);
  glr_curl_check_multi_info(multi_info);
}

void glr_curl_on_timeout(glr_timer_t *req) {
  CURLM *multi_info = req->arg;
  int running_handles;
  curl_multi_socket_action(multi_info, CURL_SOCKET_TIMEOUT, 0,
                               &running_handles);
  glr_curl_check_multi_info(multi_info);
}

int glr_curl_start_timer(CURLM *multi_info, long timeout_ms, void *userp) {
  (void) userp;
  glr_runtime_t *r = glr_cur_thread_runtime();
  if (timeout_ms < 0) {
    glr_remove_timer(&r->curl_timer);
  } else {
    if (timeout_ms == 0) {
      timeout_ms = 1; /* 0 means directly call socket_action, but we'll do it
                         in a bit */
    }
    int64_t now = glr_timestamp_in_ms();
    r->curl_timer.deadline_posix_milliseconds = now + timeout_ms;
    r->curl_timer.callback = glr_curl_on_timeout;
    r->curl_timer.arg = multi_info;
    glr_remove_timer(&r->curl_timer);
    glr_add_timer(&r->curl_timer);
  }
  return 0;
}

glr_curl_socket_data_t *glr_curl_create_socket(curl_socket_t sockfd,
                                               CURLM *multi_info, glr_error_t *err) {
  glr_curl_socket_data_t *context = malloc(sizeof(glr_curl_socket_data_t));
  context->sockfd = sockfd;
  context->multi_info = multi_info;

  context->poll_handle = (glr_poll_t){};
  context->poll_handle.fd = sockfd;
  context->poll_handle.cb_arg = context;
  glr_add_poll(&context->poll_handle, 0, err);
  if (err->error) {
    glr_stringbuilder_printf(&err->msg,
                             "\n%s:%d:%s failed to add poll of curl socket",
                             __FILE__, __LINE__, __func__);
    free(context);
    return NULL;
  }

  return context;
}

int glr_curl_handle_socket(CURL *easy, curl_socket_t s, int action,
                          void *userp, void *socketp) {

  CURLM *multi_info = userp;
  glr_curl_callback_info_t *info = NULL;
  curl_easy_getinfo(easy, CURLINFO_PRIVATE, &info);

  glr_error_t *err = info->err;
  glr_curl_socket_data_t *curl_context;
  switch (action) {
    case CURL_POLL_IN:
    case CURL_POLL_OUT:
    case CURL_POLL_INOUT: {
      curl_context = socketp ? socketp
                             : glr_curl_create_socket(s, multi_info, err);
      if (err->error) {
        glr_stringbuilder_printf(
            &err->msg, "\n%s:%d:%s failed to init glr structure for curl socket",
            __FILE__, __LINE__, __func__);
        return 1;
      }
      curl_multi_assign(multi_info, s, curl_context);

      int kind = ((action & CURL_POLL_IN) ? EPOLLIN : 0) |
                 ((action & CURL_POLL_OUT) ? EPOLLOUT : 0);

      glr_change_poll(&curl_context->poll_handle, kind, err);
      if (err->error) {
        glr_stringbuilder_printf(
            &err->msg, "\n%s:%d:%s failed to change poll flags of curl socket",
            __FILE__, __LINE__, __func__);
        return 1;
      }

      curl_context->poll_handle.cb = glr_curl_perform_internal;
    } break;
    case CURL_POLL_REMOVE:
      if (socketp) {
        curl_context = socketp;
        glr_remove_poll(&curl_context->poll_handle, err);
        curl_multi_assign(multi_info, s, NULL);
        free(socketp);
        if (err->error) {
          glr_stringbuilder_printf(
              &err->msg, "\n%s:%d:%s failed to remove poll of curl socket",
              __FILE__, __LINE__, __func__);
          return 1;
        }
      }
      break;
    default:
      abort();
  }
  return 0;
}



CURLcode glr_curl_perform(CURL *handle, glr_error_t *err) {
  if (err->error) return 0;


  glr_curl_callback_info_t info = {};
  info.in_context = glr_current_context();
  info.out_response_code = CURLE_OK;
  info.err = err;

  void *old_private;
  curl_easy_getinfo(handle, CURLINFO_PRIVATE, &old_private);

  curl_easy_setopt(handle, CURLOPT_PRIVATE, &info);
  CURLM *multi_handle = glr_get_curl_multi_handle(err);
  if (err->error) {
    glr_err_printf(err, "\n%s:%d:%s failed to get curl multi handle", __FILE__,
                   __LINE__, __func__);
    return CURLE_OK;
  }
  curl_multi_add_handle(multi_handle, handle);

  glr_scheduler_yield(0);

  curl_easy_setopt(handle, CURLOPT_PRIVATE, old_private);

  return info.out_response_code;
}

#endif
