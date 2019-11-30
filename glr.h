#ifndef GLR_H
#define GLR_H

#include <stddef.h>
#include <stdint.h>

enum {
  GLR_ALLOCATOR_ALLOC,
  GLR_ALLOCATOR_FREE,
  GLR_ALLOCATOR_RESET,
  GLR_ALLOCATOR_DESTROY,
};

typedef void* (glr_allocator_function)(
    void *allocator_data, int op, size_t size, size_t alignment, void *ptr);

typedef struct glr_allocator_s {
  void *data;
  glr_allocator_function *func;
  struct glr_allocator_s *next;
} glr_allocator_t;

void *glr_allocator_alloc(glr_allocator_t *a, size_t size, size_t alignment);
void glr_allocator_free(glr_allocator_t *a, void *ptr);
void glr_reset_allocator(glr_allocator_t *a);
void glr_destroy_allocator(glr_allocator_t *a);

glr_allocator_t glr_get_default_allocator();
glr_allocator_t glr_get_transient_allocator();

typedef struct {
  void *data;
  uint32_t cap;
} glr_memory_block;

typedef struct {
  char *data;
  uint32_t len;
  uint32_t cap;
} str_t;

str_t glr_sprintf(glr_allocator_t *a, const char *format, ...)
  __attribute__((format(printf, 2, 3)));

void glr_push_allocator(glr_allocator_t *a);
glr_allocator_t* glr_pop_allocator();
glr_allocator_t* glr_current_allocator();

void *glr_malloc(size_t size, size_t alignment);
#define GLR_ALLOCATE_TYPE(T) ((T*) glr_malloc(sizeof(T), alignof(T)))
void glr_free(void *data);

typedef struct {
  str_t *blocks;
  uint32_t len;
  uint32_t cap;
  uint32_t active_block_idx;
  uint32_t default_block_cap;
} stringbuilder_t;

stringbuilder_t glr_make_stringbuilder(size_t default_buffer_cap);

void glr_stringbuilder_printf(stringbuilder_t *sb, const char *format, ...)
  __attribute__((format(printf, 2, 3)));

void glr_stringbuilder_append(stringbuilder_t *sb, const char *data, size_t len);

str_t glr_stringbuilder_build(stringbuilder_t *sb);
void glr_stringbuilder_reset(stringbuilder_t *sb);
void glr_stringbuilder_free_buffers(stringbuilder_t *sb);

typedef struct glr_freelist_node_s {
  void *data;
  struct glr_freelit_node_s *next;
} glr_freelist_node_t;

typedef struct {
  glr_freelist_node_t *top;
} glr_freelist_t;
void glr_freelist_put(glr_freelist_t *fl, void *data);
void *glr_freelist_get(glr_freelist_t *fl);

//coroutines

typedef struct glr_exec_stack_t glr_exec_stack_t;

typedef struct glr_exec_context_t glr_exec_context_t;

void glr_preallocate_contexts(size_t count);
glr_exec_context_t *glr_get_context_from_freelist();
void glr_put_context_to_freelist(glr_exec_context_t *context);

glr_exec_context_t *glr_current_context();

void glr_transfer(glr_exec_context_t *prev, glr_exec_context_t *next);
void glr_transfer_to(glr_exec_context_t *next);

typedef void (*glr_coro_func_t)(void *arg);

void glr_create_coro(glr_exec_context_t *ctx, glr_coro_func_t fn, void *arg);
glr_exec_context_t *glr_go(glr_coro_func_t fn, void *arg);
void glr_cur_thread_runtime_cleanup();

void glr_scheduler_add(glr_exec_context_t *ctx);
void glr_scheduler_yield(int reschedule_current_ctx);

#endif //GLR_H
