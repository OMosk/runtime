#pragma once

//Features
#define GLR_VALGRIND
#define GLR_SSL
#define GLR_CURL

#define _GNU_SOURCE 1
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <stdarg.h>

#ifdef GLR_SSL
#   include <openssl/ossl_typ.h>
#endif

#ifdef GLR_CURL
#   include <curl/curl.h>
#endif


//enum {
//  GLR_ALLOCATOR_ALLOC,
//  GLR_ALLOCATOR_FREE,
//  GLR_ALLOCATOR_RESET,
//  GLR_ALLOCATOR_DESTROY,
//};
//
//typedef void* (glr_allocator_function)(
//    void *allocator_data, int op, size_t size, size_t alignment, void *ptr);
//
//typedef struct glr_allocator_s {
//  void *data;
//  glr_allocator_function *func;
//  struct glr_allocator_s *next;
//} glr_allocator_t;
//
//void *glr_allocator_alloc(glr_allocator_t *a, size_t size, size_t alignment);
//void glr_allocator_free(glr_allocator_t *a, void *ptr);
//void glr_reset_allocator(glr_allocator_t *a);
//void glr_destroy_allocator(glr_allocator_t *a);

//glr_allocator_t* glr_get_default_allocator();
//glr_allocator_t glr_create_transient_allocator(glr_allocator_t *parent);

typedef struct glr_transient_allocator_t glr_transient_allocator_t;

glr_transient_allocator_t *glr_create_transient_allocator();
glr_transient_allocator_t *glr_create_transient_allocator_detailed(uint32_t block_cap_in_4k_pages);
void *glr_alloc_from_transient_allocator(glr_transient_allocator_t *a, uint32_t size, uint32_t alignment);
void glr_reset_transient_allocator(glr_transient_allocator_t *a);
void glr_destroy_transient_allocator(glr_transient_allocator_t *a);

typedef struct {
  void *data;
  uint32_t cap;
} glr_memory_block;

typedef struct {
  const char *data;
  uint32_t len;
  uint32_t cap;
} cstr_t;


typedef struct {
  char *data;
  uint32_t len;
  uint32_t cap;
} str_t;

str_t glr_sprintf_ex(glr_transient_allocator_t *a, const char *format, ...)
  __attribute__((format(printf, 2, 3)));

#define glr_sprintf(...) glr_sprintf_ex(glr_current_allocator(), __VA_ARGS__)

str_t glr_strdup(str_t s);

//TODO: resolve issue `const str_t` <-> `cstr_t`
#define GLR_CSTR_LITERAL(s) ((cstr_t){(s), sizeof(s) - 1, sizeof(s) - 1})
#define GLR_STR_LITERAL(s) ((str_t){(s), sizeof(s) - 1, sizeof(s) - 1})
#define GLR_STRDUP_LITERAL(s) (glr_strdup(GLR_STR_LITERAL(s)))

void glr_push_allocator(glr_transient_allocator_t *a);
glr_transient_allocator_t* glr_pop_allocator(void);
glr_transient_allocator_t* glr_current_allocator(void);

glr_transient_allocator_t *glr_create_and_push_transient_allocator();
glr_transient_allocator_t *glr_create_and_push_transient_allocator_detailed(uint32_t block_cap_in_4k_pages);
glr_transient_allocator_t *glr_pop_and_destroy_transient_allocator();

typedef struct {
  glr_transient_allocator_t *a;
  uint32_t block_idx;
  uint32_t block_used;
} glr_temporary_area_bound_t;

glr_temporary_area_bound_t glr_start_temporary_area();
void glr_reset_to_start_of_temporary_area(glr_temporary_area_bound_t bound);

//void *glr_malloc(size_t size, size_t alignment);
#define GLR_ALLOCATE_TYPE(T) ((T*) glr_alloc_from_transient_allocator(glr_current_allocator(), sizeof(T), alignof(T)))
#define GLR_ALLOCATE_ARRAY(T, n) ((T*) glr_alloc_from_transient_allocator(glr_current_allocator(), sizeof(T)*(n), alignof(T)))
//void glr_free(void *data);

typedef struct {
  str_t *blocks;
  uint32_t len;
  uint32_t cap;
  uint32_t active_block_idx;
  uint32_t default_block_cap;
} stringbuilder_t;

stringbuilder_t glr_make_stringbuilder(size_t default_buffer_cap);

void glr_stringbuilder_vprintf(stringbuilder_t *sb, const char *format, va_list va);
void glr_stringbuilder_printf(stringbuilder_t *sb, const char *format, ...)
  __attribute__((format(printf, 2, 3)));

void glr_stringbuilder_append(stringbuilder_t *sb, const char *data, size_t len);
void glr_stringbuilder_append2(stringbuilder_t *sb, const str_t s);

str_t glr_stringbuilder_build(stringbuilder_t *sb);
void glr_stringbuilder_reset(stringbuilder_t *sb);
//void glr_stringbuilder_free_buffers(stringbuilder_t *sb);

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

typedef struct {
  void *error;
  int sub_error;
  stringbuilder_t msg;
} glr_error_t;

//void glr_err_cleanup(glr_error_t *err);
#define glr_err_printf(err, ...) glr_stringbuilder_printf(&((err)->msg), __VA_ARGS__)

extern const char *glr_posix_error;
#define GLR_POSIX_ERROR (&glr_posix_error)

void glr_make_posix_error(glr_error_t *err, const char *file, int line,
                          const char *func, const char *format, ...)
    __attribute__((format(printf, 5, 6)));
#define GLR_MAKE_POSIX_ERROR(err, ...) \
  glr_make_posix_error(err, __FILE__, __LINE__, __func__, __VA_ARGS__)

extern const char *glr_invalid_argument_error;
#define GLR_INVALID_ARGUMENT_ERROR (&glr_invalid_argument_error)

extern const char *glr_getaddrinfo_error;
#define GLR_GETADDRINFO_ERROR (&glr_getaddrinfo_error)

extern const char *glr_getaddrinfo_no_result_error;
#define GLR_GETADDRINFO_NO_RESULT_ERROR (&glr_getaddrinfo_no_result_error)

extern const char *glr_general_error;
#define GLR_GENERAL_ERROR (&glr_general_error)

extern const char *glr_timeout_error;
#define GLR_TIMEOUT_ERROR (&glr_timeout_error)

//networking
int64_t glr_timestamp_in_ms();

typedef struct glr_poll_t {
  int32_t fd;
  uint32_t last_epoll_event_bitset;
  void (*cb)(struct glr_poll_t *);
  void *cb_arg;
} glr_poll_t;

void glr_add_poll(glr_poll_t *poll, int flags, glr_error_t *err);
void glr_change_poll(glr_poll_t *poll, int flags, glr_error_t *err);
void glr_remove_poll(glr_poll_t *poll, glr_error_t *err);
int glr_wait_for(int fd, uint32_t flags, glr_error_t *err);

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

struct sockaddr_storage glr_resolve_address(const char *host, const char *port, glr_error_t *err);
struct sockaddr_storage glr_resolve_address1(const char *host, int port, glr_error_t *err);
struct sockaddr_storage glr_resolve_address2(const char *addr, glr_error_t *err);
struct sockaddr_storage glr_resolve_unix_socket_addr(const char *path);

str_t glr_addr_to_string(const struct sockaddr_storage *addr);
int glr_addr_get_port(const struct sockaddr_storage *addr);

struct glr_fd_t;
typedef struct glr_fd_t glr_fd_t;

glr_fd_t *glr_init_fd(int fd, glr_error_t *err);
void glr_close(glr_fd_t *fd);
int glr_fd_get_native(glr_fd_t *fd);

glr_fd_t *glr_listen(const struct sockaddr_storage *addr, int backlog,
                     int reuse_port, glr_error_t *err);

typedef enum getsockname_glr_error_t {
  GETSOCKNAME_ERROR_NONE,
  GETSOCKNAME_ERROR_FAILED,
} getsockname_glr_error_t;

struct sockaddr_storage glr_socket_local_address(glr_fd_t *fd, glr_error_t *err);

typedef struct {
  glr_fd_t *con;
  struct sockaddr_storage address;
} glr_accept_result_t;

glr_accept_result_t glr_raw_accept(glr_fd_t *listener, glr_error_t *err);

glr_fd_t *glr_raw_connect(const struct sockaddr_storage *addr, int64_t deadline, glr_error_t *err);

void glr_fd_set_deadline(glr_fd_t *fd, int64_t deadline);
int glr_fd_raw_send(glr_fd_t *fd, const char *data, int len, glr_error_t *err);
int glr_fd_raw_recv(glr_fd_t *fd, char *data, int len, glr_error_t *err);
void glr_fd_raw_shutdown(glr_fd_t *fd, glr_error_t *err);

// implemented for signalfd
int glr_fd_raw_read(glr_fd_t *fd, char *data, int len, glr_error_t *err);

//SSL
extern const char *glr_ssl_error;
#define GLR_SSL_ERROR (&glr_ssl_error)

#ifdef GLR_SSL
SSL_CTX *glr_ssl_server_context();
SSL_CTX *glr_ssl_client_context();
void glr_ssl_ctx_set_verify_peer(SSL_CTX *ctx, int verify);
void glr_ssl_ctx_set_key(SSL_CTX *ctx, const char *path,
                         const char *password, glr_error_t *error);
void glr_ssl_ctx_set_cert(SSL_CTX *ctx, const char *path, glr_error_t *error);

void glr_ssl_client_conn_handshake(SSL_CTX *ctx, glr_fd_t *conn,
                                   const char *hostname, int64_t deadline,
                                   glr_error_t *err);
void glr_ssl_server_conn_upgrade(SSL_CTX *context, glr_fd_t *conn,
                                 int64_t deadline, glr_error_t *err);
int glr_ssl_read(glr_fd_t *impl, char *buffer, size_t len, glr_error_t *err);
int glr_ssl_write(glr_fd_t *impl, const char *buffer, size_t len, glr_error_t *err);
void glr_ssl_shutdown(glr_fd_t *impl);
SSL *glr_fd_conn_get_ssl(glr_fd_t *impl);
SSL_CTX *glr_fd_conn_get_ssl_ctx(glr_fd_t *impl);
#endif

//Connection convenience tools
glr_fd_t *glr_tcp_dial_hostname_port_ex(const char *host, const char *port,
                                        int ssl, int64_t deadline, glr_error_t *err);

glr_fd_t *glr_tcp_dial_addr(const char *addr, int64_t deadline, glr_error_t *err);
glr_fd_t *glr_tcp_dial_addr_ssl(const char *addr, int64_t deadline, glr_error_t *err);
glr_fd_t *glr_tcp_dial_hostname_port(const char *hostname, const char *port,
                                     int64_t deadline, glr_error_t *err);
glr_fd_t *glr_tcp_dial_hostname_port_ssl(const char *hostname, const char *port,
                                         int64_t deadline, glr_error_t *err);

glr_fd_t *glr_tcp_dial_hostname_port2(const char *hostname, uint16_t port,
                                      int64_t deadline, glr_error_t *err);
glr_fd_t *glr_tcp_dial_hostname_port_ssl2(const char *hostname, uint16_t port,
                                          int64_t deadline, glr_error_t *err);

int glr_fd_conn_send(glr_fd_t *conn, const char *data, size_t len, glr_error_t *err);
int glr_fd_conn_recv(glr_fd_t *conn, char *data, size_t len, glr_error_t *err);
void glr_fd_conn_shutdown(glr_fd_t *conn, glr_error_t *err);

int glr_fd_conn_send_exactly(glr_fd_t *conn, const char *data, size_t len, glr_error_t *err);
int glr_fd_conn_recv_exactly(glr_fd_t *conn, char *data, size_t len, glr_error_t *err);

//Logging

typedef enum {
  GLR_LOG_LEVEL_TRACE,
  GLR_LOG_LEVEL_DEBUG,
  GLR_LOG_LEVEL_INFO,
  GLR_LOG_LEVEL_WARNING,
  GLR_LOG_LEVEL_ERROR,
  GLR_LOG_LEVEL_CRITICAL,
} glr_log_level_t;

struct glr_logger_t;
typedef struct glr_logger_t glr_logger_t;

struct glr_logger_t *glr_logger_create(const char *filename, glr_error_t *e);
void glr_logger_destroy(struct glr_logger_t *logger);

glr_logger_t *glr_get_stdout_logger();
glr_logger_t *glr_get_stderr_logger();

glr_logger_t *glr_get_default_logger();
void glr_set_default_logger(glr_logger_t *logger);
glr_logger_t *glr_get_logger();
void glr_set_logger(glr_logger_t *logger);
void glr_set_min_log_level(glr_logger_t *logger, glr_log_level_t level);

#define GLR_SOURCE_LOCATION_STRINGIFY2(X) #X
#define GLR_SOURCE_LOCATION_STRINGIFY(X) GLR_SOURCE_LOCATION_STRINGIFY2(X)
#define GLR_SOURCE_LOCATION \
  GLR_CSTR_LITERAL(__FILE__ ":" GLR_SOURCE_LOCATION_STRINGIFY(__LINE__))

void glr_log_detailed(glr_logger_t *logger, glr_log_level_t level,
                      cstr_t source_location, cstr_t function_name,
                      const char *format, ...)
    __attribute__((format(printf, 5, 6)));

#define glr_log2(logger, level, ...)                    \
  glr_log_detailed(logger, level, GLR_SOURCE_LOCATION, \
                   GLR_CSTR_LITERAL(__func__), __VA_ARGS__)

#define glr_log(level, ...) glr_log2(glr_get_logger(), level, __VA_ARGS__)
#define glr_log_trace(...) glr_log(GLR_LOG_LEVEL_TRACE, __VA_ARGS__)
#define glr_log_debug(...) glr_log(GLR_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define glr_log_info(...) glr_log(GLR_LOG_LEVEL_INFO, __VA_ARGS__)
#define glr_log_warn(...) glr_log(GLR_LOG_LEVEL_WARNING, __VA_ARGS__)
#define glr_log_error(...) glr_log(GLR_LOG_LEVEL_ERROR, __VA_ARGS__)
#define glr_log_crit(...) glr_log(GLR_LOG_LEVEL_CRITICAL, __VA_ARGS__)

str_t glr_get_logging_context();
void glr_cleanup_logging_context();
void glr_reset_logging_context();
void glr_append_logging_context(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

//
void glr_daemonize();

typedef void (*glr_signal_handling_function)(int signal, void *data);
void glr_launch_signal_handling_thread(glr_signal_handling_function fn,
                                       void *data);

glr_fd_t *glr_signalfd(int *signals, glr_error_t *e);
void glr_block_signals(int *signals, glr_error_t *e);

#ifdef GLR_CURL
extern const char *glr_curl_error;
#define GLR_CURL_ERROR (&glr_curl_error)

CURLcode glr_curl_perform(CURL *handle, glr_error_t *err);
#endif //GLR_CURL


#if __has_extension(blocks)
static inline void glr_call_block(void (^*b)(void)) { (*b)(); }

#define GLR_COMBINE1(X, Y) X ## Y
#define GLR_COMBINE(X, Y) GLR_COMBINE1(X, Y)
#define glr_defer __attribute__((cleanup(glr_call_block))) void (^GLR_COMBINE(defer_scopevar_,__LINE__))() =^
#else
#define glr_defer #error "clang blocks was used but not available, add -fblock -l:libBlocksRuntime.a to compilation flags"
#endif

