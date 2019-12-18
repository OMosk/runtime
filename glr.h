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
glr_allocator_t glr_get_transient_allocator(glr_allocator_t *parent);

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

str_t glr_strdup(str_t s);

#define GLR_STRDUP_LITERAL(s) \
  (glr_strdup((str_t){s, sizeof(s) - 1, sizeof(s) - 1}))

void glr_push_allocator(glr_allocator_t *a);
glr_allocator_t* glr_pop_allocator(void);
glr_allocator_t* glr_current_allocator(void);

void *glr_malloc(size_t size, size_t alignment);
#define GLR_ALLOCATE_TYPE(T) ((T*) glr_malloc(sizeof(T), alignof(T)))
#define GLR_ALLOCATE_ARRAY(T, n) ((T*) glr_malloc(sizeof(T)*n, alignof(T)))
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

//error handling

enum {
  ERROR_NONE = 0,
};

typedef struct {
  int error;
  int sub_error;
  stringbuilder_t msg;
} err_t;

void err_cleanup(err_t *err);

//networking
int64_t glr_timestamp_in_ms();

typedef struct glr_poll_t {
  int32_t fd;
  uint32_t last_epoll_event_bitset;
  void (*cb)(struct glr_poll_t *);
  void *cb_arg;
} glr_poll_t;

typedef enum poll_error_t {
  POLL_ERROR_NONE,
  POLL_ERROR_FAILED_EPOLL_CTL,
  POLL_ERROR_INVALID_ARG,
} poll_error_t;

void glr_add_poll(glr_poll_t *poll, int flags, err_t *err);
void glr_change_poll(glr_poll_t *poll, int flags, err_t *err);
void glr_remove_poll(glr_poll_t *poll, err_t *err);
int glr_wait_for(int fd, uint32_t flags, err_t *err);

typedef struct glr_timer_t {
  int64_t deadline_posix_milliseconds;
  void *arg;
  void (*callback)(struct glr_timer_t *timer);
  int32_t internal_idx;
} glr_timer_t;

void glr_add_timer(glr_timer_t *timer);
void glr_remove_timer(glr_timer_t *timer);
void glr_sleep(int msec);

typedef void (*glr_job_fn_t)(void *);
typedef struct glr_runtime_t glr_runtime_t;

glr_runtime_t *glr_cur_thread_runtime();

void glr_async_post(glr_runtime_t *r, glr_job_fn_t fn, void *arg);

void glr_run_in_thread_pool(glr_job_fn_t fn, void *arg);

typedef enum resolve_addr_err_t {
  RESOLVE_ADDR_ERROR_NONE,
  RESOLVE_ADDR_ERROR_GETADDRINFO_FAILED,
  RESOLVE_ADDR_ERROR_NO_RESULT,
  RESOLVE_ADDR_ERROR_FAILED_TO_PARSE_ADDR_STR,
} resolve_addr_err_t;

struct sockaddr_storage glr_resolve_address(const char *host, const char *port, err_t *err);
struct sockaddr_storage glr_resolve_address1(const char *host, int port, err_t *err);
struct sockaddr_storage glr_resolve_address2(const char *addr, err_t *err);

str_t glr_addr_to_string(const struct sockaddr_storage *addr);

struct glr_fd;
typedef struct glr_fd glr_fd;


#endif //GLR_H
