#include "glr.h"
#include <malloc.h>
#include <stdint.h>
#include <string.h>
#include <stdalign.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

//Features
#define GLR_VALGRIND

#ifdef GLR_VALGRIND
#    include <valgrind/valgrind.h>
#endif


#define thread_local _Thread_local

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

    a->blocks = (glr_memory_block *)malloc(new_cap * sizeof(glr_memory_block));
    a->cap = new_cap;

    memcpy(a->blocks, old_blocks, old_blocks_cap * sizeof(glr_memory_block));
    free(old_blocks);
  }

  a->blocks[a->len].cap = cap;
  a->blocks[a->len].data = malloc(cap);
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
      free(a->blocks[block_idx].data);
    }
    free(a->blocks);
    free(a);
  } break;
  }

  return NULL;
}

glr_allocator_t glr_get_transient_allocator() {
  glr_allocator_t result = {};

  glr_transient_allocator *tmp
      = (glr_transient_allocator *) malloc(sizeof(glr_transient_allocator));
  *tmp = (glr_transient_allocator){};

  tmp->default_block_cap = 4096;
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

thread_local glr_allocator_t *current_allocator;

void glr_push_allocator(glr_allocator_t *a) {
  a->next = current_allocator;
  current_allocator = a;
}

glr_allocator_t* glr_pop_allocator() {
  glr_allocator_t *result = current_allocator;
  current_allocator = current_allocator->next;
  return result;
}

thread_local glr_allocator_t cached_default_allocator;

glr_allocator_t* glr_current_allocator() {
  if (!current_allocator) {
    if (!cached_default_allocator.func) {
      cached_default_allocator = glr_get_default_allocator();
    }
    current_allocator = &cached_default_allocator;
  }

  return current_allocator;
}

void *glr_malloc(size_t size, size_t alignment) {
  return glr_allocator_alloc(glr_current_allocator(), size, alignment);
}

void glr_free(void *data) {
  return glr_allocator_free(glr_current_allocator(), data);
}

str_t glr_sprintf(glr_allocator_t *a, const char *format, ...) {
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

void glr_stringbuilder_printf(stringbuilder_t *sb, const char *format, ...) {
  va_list args;
  va_start(args, format);
  int needed_cap = vsnprintf(NULL, 0, format, args) + 1;
  va_end(args);

  str_t *active_block = sb->blocks + sb->active_block_idx;
  if (!sb->len || active_block->len + needed_cap > active_block->cap) {
    glr_stringbuilder_use_next_block(sb, needed_cap);
    active_block = sb->blocks + sb->active_block_idx;
  }

  char *data_ptr = active_block->data + active_block->len;
  int cap_left = active_block->cap - active_block->len;

  va_start(args, format);
  int written = vsnprintf(data_ptr, cap_left, format, args);
  va_end(args);

  active_block->len += written;
}

str_t glr_stringbuilder_build(stringbuilder_t *sb) {
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

struct glr_exec_stack_t {
  void *original_allocation;
  void *sptr;
  size_t size;
  int valgrind_id;
};

struct glr_exec_context_t {
  void **sp;
  glr_exec_stack_t *stack;
};

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
} glr_coro_runtime_t;

static thread_local glr_exec_context_t thread_context;
static thread_local glr_coro_runtime_t glr_coro_runtime;

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
  glr_coro_runtime_t *r = &glr_coro_runtime;

  for (uint32_t i = 0; i < r->scheduler_currently_in_queue; ++i) {
    uint32_t idx = (r->scheduler_read_idx + i) % r->scheduler_q_cap;
    glr_exec_context_t *ctx = r->scheduler_q[idx];
    glr_exec_context_cleanup(ctx, &ss);
  }
  free(r->scheduler_q);

  for (uint32_t i = 0; i < r->free_contexts_len; ++i) {
    glr_exec_context_t *ctx = r->free_contexts[i];
    glr_exec_context_cleanup(ctx, &ss);
  }
  free(r->free_contexts);
  *r = (glr_coro_runtime_t) {};
}


glr_exec_context_t *glr_current_context() {
  if (!glr_coro_runtime.cur_context) {
    return &thread_context;
  }
  return glr_coro_runtime.cur_context;
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
  if (!glr_coro_runtime.free_contexts_len) {
    glr_preallocate_contexts(1);
  }
  glr_exec_context_t *result = glr_coro_runtime.free_contexts[0];
  glr_coro_runtime.free_contexts[0]
      = glr_coro_runtime.free_contexts[glr_coro_runtime.free_contexts_len - 1];
  glr_coro_runtime.free_contexts_len--;
  return result;
}


void glr_put_context_to_freelist(glr_exec_context_t *context) {
  glr_coro_runtime_t *r = &glr_coro_runtime;
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
  glr_coro_runtime.cur_context = next;
  glr_coro_transfer(prev, next);
}

void glr_transfer_to(glr_exec_context_t *next) {
  glr_transfer(glr_current_context(), next);
}

void glr_coro_init(void) {
  glr_coro_func_t func = glr_coro_runtime.new_coro_func;
  void *arg = glr_coro_runtime.new_coro_arg;

  glr_exec_context_t *own_context = glr_coro_runtime.new_coro_context;

  glr_transfer(glr_coro_runtime.new_coro_context,
               glr_coro_runtime.creator_context);

#if __GCC_HAVE_DWARF2_CFI_ASM && __amd64
  // From now on the previous value of register rip can’t be restored anymore
  asm(".cfi_undefined rip");
#endif

  func((void *)arg);

  glr_put_context_to_freelist(own_context);
  glr_scheduler_yield(0);

  /* the new coro returned. bad. just abort() for now */
  abort();
}

void glr_create_coro(glr_exec_context_t *ctx, glr_coro_func_t fn, void *arg) {
  glr_coro_runtime_t *r = &glr_coro_runtime;
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
  glr_coro_runtime_t *r = &glr_coro_runtime;
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
  glr_coro_runtime_t *r = &glr_coro_runtime;
  if (!r->scheduler_currently_in_queue) {
    //TODO: logger should be here
    abort();
  }

  glr_exec_context_t *next_ctx = r->scheduler_q[r->scheduler_read_idx];
  r->scheduler_read_idx = (r->scheduler_read_idx + 1) % r->scheduler_q_cap;
  r->scheduler_currently_in_queue--;

  glr_exec_context_t *cur_ctx = glr_current_context();

  if (reschedule_current_ctx) {
    glr_scheduler_add(cur_ctx);
  }
  glr_transfer(cur_ctx, next_ctx);
}

