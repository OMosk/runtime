#include <malloc.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/signalfd.h>
#include <sys/un.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

#include "glr.h"

#define TEST printf("%s:%d:%s started\n", __FILE__, __LINE__, __func__)

static void label_pointers(void) {
  TEST;
  int a = 0;
  void *label_ptr = &&my_label;
  goto *label_ptr;

  a++;

my_label:
  if (a != 0) {
    printf("%s:%d:%s failed\n", __FILE__, __LINE__, __func__);
  }
}

static void error_handling(void) {
  TEST;
  void *cleanup = &&exit;

  int *a = (int *)malloc(sizeof(int));
  if (!a) goto *cleanup;
  cleanup = &&free_variable_a;

  *a = 5;

  if (time(NULL) % 2) {
    // Unexpected error
    printf("%s:%d:%s Caught expected error returning with appropiate cleanup\n",
           __FILE__, __LINE__, __func__);
    goto *cleanup;
  }

  int *b = (int *)malloc(sizeof(int));
  if (!b) goto *cleanup;
  cleanup = &&free_variable_b;

  /**
   *
   * Many many lines of code
   *
   */
free_variable_b:
  free(b);
  printf("%s:%d:%s freed b\n", __FILE__, __LINE__, __func__);
free_variable_a:
  free(a);
  printf("%s:%d:%s freed a\n", __FILE__, __LINE__, __func__);
exit:
  return;
}

static void test_global_malloc_free_adapter() {
  TEST;
  glr_allocator_t *global = glr_get_default_allocator();
  int *a = (int *)glr_allocator_alloc(global, sizeof(int), alignof(int));
  *a = 5;
  glr_allocator_free(global, a);
  glr_reset_allocator(global);
  glr_destroy_allocator(global);
}

static void test_body_transient_allocator(glr_allocator_t *alloc) {
  TEST;
  typedef struct {
    uint32_t field1;
    uint64_t field2;
    char field3;
    double field4;

    double x;
    double y;
    double z;
  } test_struct_t;

  struct {
    const char *comment;
    ssize_t size;
    size_t alignment;
    void *result_ptr;
  } * c, cases[] = {
             {"int", sizeof(int), alignof(int), NULL},
             {"float", sizeof(float), alignof(float), NULL},
             {"uint8_t", sizeof(uint8_t), alignof(uint8_t), NULL},
             {"int64_t", sizeof(int64_t), alignof(int64_t), NULL},
             {"double", sizeof(double), alignof(double), NULL},
             {"char[256]", sizeof(char[256]), alignof(char[256]), NULL},
             {"test_struct_t", sizeof(test_struct_t), alignof(test_struct_t),
              NULL},
             {"char[9600]", sizeof(char[9600]), alignof(char[9600]), NULL},
             {"uint8_t", sizeof(uint8_t), alignof(uint8_t), NULL},
         };

  int cases_len = sizeof(cases) / sizeof(cases[0]);
  for (int i = 0; i < cases_len; ++i) {
    cases[i].result_ptr =
        glr_allocator_alloc(alloc, cases[i].size, cases[i].alignment);
  }

  for (int i = 0; i < cases_len; ++i) {
    c = cases + i;
    int aligned = ((uintptr_t)c->result_ptr % c->alignment) == 0;
    ssize_t ptrdiff_to_next = 0;
    int enough_size = 1;
    if (i < cases_len - 1) {
      ptrdiff_to_next = ((char *)(c + 1)->result_ptr - (char *)c->result_ptr);
      enough_size = ptrdiff_to_next >= c->size;
    }
    printf(
        "Alloc %s size=%ld alignment=%ld data=%p aligned=%d "
        "ptrdiff=%ld enough_size=%d\n",
        c->comment, c->size, c->alignment, c->result_ptr, aligned,
        ptrdiff_to_next, enough_size);

    char *data = c->result_ptr;
    for (char *it = data, *end = data + c->size; it < end; ++it) {
      *it = 'A';
    }

    glr_allocator_free(alloc, c->result_ptr);
  }
}

static void test_transient_allocator() {
  TEST;
  glr_allocator_t alloc = glr_create_transient_allocator(NULL);

  test_body_transient_allocator(&alloc);

  printf(">>>Resetting transient allocator\n");
  glr_reset_allocator(&alloc);

  test_body_transient_allocator(&alloc);

  glr_destroy_allocator(&alloc);
}

static void test_transient_allocator2() {
  TEST;
  printf("%s:%d:%s \n", __FILE__, __LINE__, __func__);
  // Allocating in way that forces transient allocator allocate 3 4096 blocks
  // resetting allocator, request allocating of 8192, 0th block would not be
  // able to contain this data as 1st, so it should allocated 8192 block and swap
  // it with 1st
  glr_allocator_t alloc = glr_create_transient_allocator(NULL);

  glr_allocator_alloc(&alloc, 4096, 1);
  glr_allocator_alloc(&alloc, 4096, 1);
  glr_allocator_alloc(&alloc, 4096, 1);
  glr_reset_allocator(&alloc);
  printf(">>>Resetting transient allocator\n");
  char *data = glr_allocator_alloc(&alloc, 8192, 1);
  for (int i = 0; i < 8192; ++i) {
    data[i] = 'z';
  }

  glr_destroy_allocator(&alloc);
}

static void test_glr_sprintf() {
  TEST;
  glr_allocator_t a = glr_create_transient_allocator(NULL);

  printf("%s:%d:%s Float=%.6f'\n", __FILE__, __LINE__, __func__, 123.45);

  str_t string = glr_sprintf_ex(&a, "%s:%d:%s Float=%.6fEnd", __FILE__,
                                __LINE__, __func__, 123.45);

  fwrite(string.data, 1, string.len, stdout);
  printf("\n");

  if (string.data[string.len - 1] != 'd') {
    abort();
  }

  glr_destroy_allocator(&a);
}

static void test_glr_malloc_free() {
  int *a = GLR_ALLOCATE_TYPE(int);
  *a = 5;
  glr_free(a);
}

static void test_allocators_stack() {
  if (glr_current_allocator() == NULL) {
    abort();
  }

  glr_allocator_t a1 = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a1);

  glr_allocator_t *cur = glr_current_allocator();
  if (cur != &a1) {
    abort();
  }

  int *a = GLR_ALLOCATE_TYPE(int);
  *a = 5;

  cur = glr_pop_allocator();
  if (cur != &a1) {
    abort();
  }

  glr_destroy_allocator(&a1);
}

static void test_stringbuilder() {
  TEST;
  glr_allocator_t a1 = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a1);

  stringbuilder_t sb = glr_make_stringbuilder(256);
  glr_stringbuilder_printf(&sb, "Hello world %d, %s", 123, "End");
  if (sb.len != 1) {
    abort();
  }

  if (sb.active_block_idx != 0) {
    abort();
  }

  str_t result = glr_stringbuilder_build(&sb);
  printf("%s\n", result.data);
  if (strcmp(result.data, "Hello world 123, End") != 0) {
    abort();
  }

  glr_pop_allocator();
  glr_destroy_allocator(&a1);
}

static void test_stringbuilder2() {
  TEST;
  glr_allocator_t a1 = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a1);

  stringbuilder_t sb = glr_make_stringbuilder(5);
  glr_stringbuilder_printf(&sb, "Hello world %d, %s", 123, "End");
  glr_stringbuilder_printf(&sb, "Hello world %d, %s", 123, "End");
  if (sb.len != 2) {
    abort();
  }

  if (sb.active_block_idx != 1) {
    abort();
  }

  str_t result = glr_stringbuilder_build(&sb);
  printf("%s\n", result.data);

  glr_pop_allocator();
  glr_destroy_allocator(&a1);
}

static void test_stringbuilder3() {
  TEST;
  printf("%s:%d:%s \n", __FILE__, __LINE__, __func__);
  // testing append
  glr_allocator_t a1 = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a1);

  const char str[] = "'Hello World'";

  stringbuilder_t sb = glr_make_stringbuilder(5);
  glr_stringbuilder_append(&sb, str, sizeof(str) - 1);
  glr_stringbuilder_append(&sb, str, sizeof(str) - 1);
  if (sb.len != 2) {
    abort();
  }

  if (sb.active_block_idx != 1) {
    abort();
  }

  str_t result = glr_stringbuilder_build(&sb);
  printf("%s\n", result.data);
  glr_stringbuilder_reset(&sb);

  const char str2[] = "'Much bigger hello world'";
  glr_stringbuilder_append(&sb, str2, sizeof(str2) - 1);
  result = glr_stringbuilder_build(&sb);
  printf("%s\n", result.data);

  glr_pop_allocator();
  glr_destroy_allocator(&a1);
}

static void test_stringbuilder4() {
  TEST;
  // Test buffers cleanup
  printf("%s:%d:%s \n", __FILE__, __LINE__, __func__);
  stringbuilder_t sb = glr_make_stringbuilder(5);
  const char str[] = "'Hello World'";
  glr_stringbuilder_append(&sb, str, sizeof(str) - 1);
  glr_stringbuilder_append(&sb, str, sizeof(str) - 1);

  str_t result = glr_stringbuilder_build(&sb);
  glr_stringbuilder_free_buffers(&sb);
  printf("%s\n", result.data);
  glr_free(result.data);
}

static void bench_emptysnprintf_len_calculation() {
  TEST;
  printf("%s:%d:%s \n", __FILE__, __LINE__, __func__);
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  int n = 10000;
  for (int i = 0; i < n; ++i) {
    (void)snprintf(NULL, 0, "");
    //(void)snprintf(NULL, 0, "String='%s' int='%d' float='%f'\n",
    //               "Hello world", 12345, 987.654);
  }
  struct timespec end;
  clock_gettime(CLOCK_MONOTONIC, &end);
  int64_t elapsed =
      (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
  printf("%d iterations took = %f secs\n", n, elapsed / 1e9);
}

static void bench_snprintf_len_calculation() {
  printf("%s:%d:%s \n", __FILE__, __LINE__, __func__);
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  int n = 10000;
  for (int i = 0; i < n; ++i) {
    (void)snprintf(NULL, 0, "String='%s' int='%d' float='%f'\n", "Hello world",
                   12345, 987.654);
  }
  struct timespec end;
  clock_gettime(CLOCK_MONOTONIC, &end);
  int64_t elapsed =
      (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
  printf("%d iterations took = %f secs\n", n, elapsed / 1e9);
}

static void bench_snprintf_len_calculation2() {
  printf("%s:%d:%s \n", __FILE__, __LINE__, __func__);
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  int n = 10000;
  for (int i = 0; i < n; ++i) {
    (void)snprintf(NULL, 0, "String='%.*s' int='%d' float='%f'\n", 11,
                   "Hello world", 12345, 987.654);
  }
  struct timespec end;
  clock_gettime(CLOCK_MONOTONIC, &end);
  int64_t elapsed =
      (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
  printf("%d iterations took = %f secs\n", n, elapsed / 1e9);
}

typedef struct {
  void *main_ctx;
  int called;
} coro_transfer_test_data;

static void test_coro_func(void *arg) {
  TEST;
  coro_transfer_test_data *tdata = arg;
  tdata->called = 1;
  printf("coro was executed\n");
  glr_transfer_to(tdata->main_ctx);
}

static void test_coro_transfer() {
  TEST;
  coro_transfer_test_data tdata = {glr_current_context(), 0};
  glr_exec_context_t *coro_ctx = glr_get_context_from_freelist();
  glr_create_coro(coro_ctx, test_coro_func, &tdata);
  glr_transfer(tdata.main_ctx, coro_ctx);

  if (!tdata.called) {
    abort();
  }
  printf("exited cleanly\n");
  glr_put_context_to_freelist(coro_ctx);
  glr_cur_thread_runtime_cleanup();
}

static void test_coro_func2(void *arg) {
  TEST;
  coro_transfer_test_data *tdata = arg;
  tdata->called = 1;
  printf("coro was executed\n");
  glr_scheduler_yield(1);
}

static void test_scheduler() {
  TEST;
  coro_transfer_test_data tdata = {glr_current_context(), 0};
  glr_go(test_coro_func2, &tdata);
  glr_scheduler_yield(1);

  if (!tdata.called) {
    abort();
  }
  printf("exited cleanly\n");
  glr_scheduler_yield(1);
  glr_cur_thread_runtime_cleanup();
}

static void test_coro_func3(void *arg) {
  TEST;
  coro_transfer_test_data *tdata = arg;
  tdata->called++;
}

static void test_scheduler_resizing() {
  TEST;
  coro_transfer_test_data tdata = {glr_current_context(), 0};
  glr_go(test_coro_func3, &tdata);
  glr_go(test_coro_func3, &tdata);
  glr_go(test_coro_func3, &tdata);
  glr_scheduler_yield(1);

  if (tdata.called != 3) {
    abort();
  }

  for (uint32_t i = 0; i < 128; ++i) {
    glr_go(test_coro_func3, &tdata);
  }
  glr_go(test_coro_func3, &tdata);
  glr_scheduler_yield(1);
  if (tdata.called != 132) {
    abort();
  }

  printf("exited cleanly\n");
  glr_cur_thread_runtime_cleanup();
}

typedef struct {
  uint32_t *sum;
  uint32_t number;
} sum_data_t;

static void test_coro_func4(void *arg) {
  sum_data_t *sum_data = arg;
  *sum_data->sum += sum_data->number;
}

static void test_scheduler_execution() {
  TEST;
  // to mess with indexes in scheduler ring buffer
  coro_transfer_test_data tdata = {glr_current_context(), 0};
  glr_go(test_coro_func3, &tdata);
  glr_go(test_coro_func3, &tdata);
  glr_go(test_coro_func3, &tdata);
  glr_scheduler_yield(1);

  uint32_t sum = 0;

  sum_data_t arr[128];

  for (uint32_t i = 0; i < 128; ++i) {
    arr[i].sum = &sum;
    arr[i].number = i;
    glr_go(test_coro_func4, arr + i);
  }
  glr_scheduler_yield(1);
  if (sum != 8128) {  // sum of arithmetic progression
    abort();
  }

  printf("arithmethic test exited cleanly\n");
  glr_cur_thread_runtime_cleanup();
}

void poll_test_coro(void *arg) {
  uintptr_t large_fd = (uintptr_t)arg;
  int fd = large_fd;
  int64_t add = 5;
  printf("Written to fd=%d\n", fd);
  int rc = write(fd, &add, 8);
  if (rc != 8) {
    abort();
  }
}

static void test_poll() {
  TEST;
  glr_error_t err = {};
  int fd = eventfd(0, EFD_NONBLOCK);
  printf("Inited fd=%d\n", fd);
  uintptr_t large_fd = fd;
  glr_go(poll_test_coro, (void *)large_fd);
  int rc = glr_wait_for(fd, EPOLLIN | EPOLLET, &err);

  int64_t new_val = 0;
  rc = read(fd, &new_val, 8);
  if (rc == -1) {
    abort();
  }
  if (new_val != 5) {
    abort();
  }

  close(fd);
  glr_cur_thread_runtime_cleanup();
  glr_err_cleanup(&err);
}

static void test_error_handling() {
  TEST;
  glr_error_t err = {};
  int fd = 1213456;
  glr_wait_for(fd, EPOLLIN | EPOLLET, &err);
  if (err.error) {
    str_t msg = glr_stringbuilder_build(&err.msg);
    printf("Expected error: %*s\n", msg.len, msg.data);
    glr_free(msg.data);
  } else {
    abort();
  }

  glr_cur_thread_runtime_cleanup();
  glr_err_cleanup(&err);
}

static void test_transient_allocator_embedding() {
  TEST;
  glr_allocator_t a1 = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a1);

  glr_allocator_t a2 = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a2);

  stringbuilder_t sb = {};
  glr_stringbuilder_printf(&sb, "%s", "Hello world");
  str_t s = glr_stringbuilder_build(&sb);
  printf("Built string: %.*s\n", s.len, s.data);

  glr_pop_allocator();
  glr_pop_allocator();
  glr_destroy_allocator(&a1);
}

static void bench_transient_allocation() {
  TEST;
  glr_allocator_t a1 = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a1);

  printf("%s:%d:%s \n", __FILE__, __LINE__, __func__);
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  int n = 10000;
  for (int i = 0; i < n; ++i) {
    (void)glr_malloc(1, 1);
  }
  struct timespec end;
  clock_gettime(CLOCK_MONOTONIC, &end);
  int64_t elapsed =
      (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec);
  printf("transient malloc: %d iterations took = %f secs\n", n, elapsed / 1e9);

  glr_pop_allocator();
  glr_destroy_allocator(&a1);
}

struct test_timers_data {
  int *arr;
  int *len;
  int cap;
  int idx;
  glr_exec_context_t *main_ctx;
};

static void test_timers_coro(glr_timer_t *t) {
  TEST;
  struct test_timers_data *td = t->arg;
  td->arr[(*td->len)++] = td->idx;
  printf("Timer #%d fired (%d/%d)\n", td->idx, *td->len, td->cap);
  if (*td->len == td->cap) {
    glr_scheduler_add(td->main_ctx);
  }
}

static void test_timers() {
  TEST;
  glr_exec_context_t *cur = glr_current_context();
  int execution_order[10] = {};
  int len = 0;
  int timeouts[10];
  timeouts[0] = 130;
  timeouts[1] = 150;
  timeouts[2] = 170;
  timeouts[3] = 190;
  timeouts[4] = 200;
  timeouts[5] = 180;
  timeouts[6] = 160;
  timeouts[7] = 140;
  timeouts[8] = 120;
  timeouts[9] = 110;

  struct test_timers_data td[10] = {};
  glr_timer_t timers[10] = {};

  int64_t now = glr_timestamp_in_ms();
  for (int i = 0; i < 10; ++i) {
    td[i].arr = execution_order;
    td[i].len = &len;
    td[i].cap = sizeof(execution_order) / sizeof(execution_order[0]);
    td[i].idx = i;
    td[i].main_ctx = cur;
    timers[i].arg = td + i;
    timers[i].callback = test_timers_coro;
    timers[i].deadline_posix_milliseconds = now + timeouts[i];
    glr_add_timer(timers + i);
  }

  printf("launching timers\n");
  glr_scheduler_yield(0);

#define CHECK(cond) \
  if (!(cond)) abort();
  CHECK(execution_order[0] == 9);
  CHECK(execution_order[1] == 8);
  CHECK(execution_order[2] == 0);
  CHECK(execution_order[3] == 7);
  CHECK(execution_order[4] == 1);
  CHECK(execution_order[5] == 6);
  CHECK(execution_order[6] == 2);
  CHECK(execution_order[7] == 5);
  CHECK(execution_order[8] == 3);
  CHECK(execution_order[9] == 4);
#undef CHECK

  glr_cur_thread_runtime_cleanup();
}

static void allocator_use_coro(void *arg) {
  (void)arg;
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);
  glr_scheduler_yield(1);

  if (glr_current_allocator() != &a) {
    abort();
  }

  glr_pop_allocator();
  glr_destroy_allocator(&a);
}

static void test_allocator_preserving_between_coros() {
  TEST;
  glr_go(allocator_use_coro, 0);
  glr_go(allocator_use_coro, 0);
  glr_scheduler_yield(1);
  glr_scheduler_yield(1);

  glr_cur_thread_runtime_cleanup();
}

typedef struct {
  glr_runtime_t *r;
  glr_exec_context_t *ctx;
} async_test_data;

void test_async1_job_fn(void *arg) { glr_scheduler_add(arg); }

void *test_async1_thread_fn(void *arg) {
  async_test_data *td = arg;
  glr_async_post(td->r, test_async1_job_fn, td->ctx);
  return NULL;
}

static void test_async1() {
  TEST;

  async_test_data td = {glr_cur_thread_runtime(), glr_current_context()};

  pthread_t pt;
  if (pthread_create(&pt, NULL, test_async1_thread_fn, &td)) {
    abort();
  }
  glr_scheduler_yield(0);
  if (pthread_join(pt, NULL)) {
    abort();
  }

  glr_cur_thread_runtime_cleanup();
}

typedef struct {
  int n;
  int called;
  glr_runtime_t *r;
  glr_exec_context_t *ctx;
} async_test2_data;

void test_async2_job_fn(void *arg) {
  async_test2_data *td = arg;
  if (++td->called == td->n) {
    glr_scheduler_add(td->ctx);
  }
}

void *test_async2_thread_fn(void *arg) {
  async_test2_data *td = arg;
  for (int i = 0; i < td->n; ++i) {
    glr_async_post(td->r, test_async2_job_fn, td);
  }
  return NULL;
}

static void test_async2(int n) {
  TEST;

  async_test2_data td = {n, 0, glr_cur_thread_runtime(), glr_current_context()};

  int64_t begin = glr_timestamp_in_ms();
  pthread_t pt;
  if (pthread_create(&pt, NULL, test_async2_thread_fn, &td)) {
    abort();
  }
  glr_scheduler_yield(0);
  if (pthread_join(pt, NULL)) {
    abort();
  }
  int64_t end = glr_timestamp_in_ms();
  printf("Test for %d (%d) asyncs took %ld ms\n", td.n, td.called, end - begin);
  if (td.n != td.called) {
    abort();
  }

  glr_cur_thread_runtime_cleanup();
}

void *test_async3_thread_fn(void *arg) {
  async_test2_data *td = arg;
  struct timespec req = {};
  for (int i = 0; i < td->n; ++i) {
    glr_async_post(td->r, test_async2_job_fn, td);
    req.tv_nsec = (i % 1000) * 10;
    nanosleep(&req, NULL);
  }
  return NULL;
}

static void test_async3(int n) {
  TEST;

  async_test2_data td = {n, 0, glr_cur_thread_runtime(), glr_current_context()};

  int64_t begin = glr_timestamp_in_ms();
  pthread_t pt;
  if (pthread_create(&pt, NULL, test_async3_thread_fn, &td)) {
    abort();
  }
  glr_scheduler_yield(0);
  if (pthread_join(pt, NULL)) {
    abort();
  }
  int64_t end = glr_timestamp_in_ms();
  printf("Test for %d (%d) asyncs took %ld ms\n", td.n, td.called, end - begin);
  if (td.n != td.called) {
    abort();
  }

  glr_cur_thread_runtime_cleanup();
}

typedef struct {
  int64_t *sum;
  int64_t number;
} async_test4_data;

static void test_async4_job_fn(void *arg) {
  async_test4_data *td = arg;
  *td->sum += td->number;
}

static void test_async4() {
  TEST;

  int64_t sum = 0;

  async_test4_data td[1000];
  for (int i = 0; i < 1000; ++i) {
    td[i].sum = &sum;
    td[i].number = i;
    glr_async_post(glr_cur_thread_runtime(), test_async4_job_fn, td + i);
  }

  glr_scheduler_yield(1);

  if (sum != (0. + 999.) / 2. * 1000.) {
    abort();
  }

  glr_cur_thread_runtime_cleanup();
}

typedef struct {
  int64_t *sum;
  int64_t number;
  int64_t expected;
  int called;
  int should_be_called;
  glr_exec_context_t *ctx;
} async_test5_job_data;

int test_async5_called;
static void test_async5_job_fn(void *arg) {
  test_async5_called++;
  async_test5_job_data *data = arg;
  data->called++;
  *data->sum += data->number;
  if (data->expected == *data->sum) {
    glr_scheduler_add(data->ctx);
  }
  if (data->called > data->should_be_called) {
    abort();
  }
  //  if (test_async5_called % 10000 == 0) {
  //    printf("%s called %d times(exp=%ld cur=%ld)\n", __func__,
  //    test_async5_called,
  //           data->expected, *data->sum);
  //  }
}

typedef struct {
  async_test5_job_data *arr;
  int arr_len;
  glr_runtime_t *r;
  pthread_t pthread;
} async_test5_thread_data;

static void *test_async5_thread_fn(void *arg) {
  async_test5_thread_data *data = arg;
  for (int i = 0; i < data->arr_len; ++i) {
    glr_async_post(data->r, test_async5_job_fn, data->arr + i);
  }
  return NULL;
}

static void test_async5(int n) {
  test_async5_called = 0;
  TEST;

  int64_t sum = 0;
  int threads = 3;
  int64_t expected_sum = threads * (0. + (double)(n - 1)) / 2. * n;
  glr_exec_context_t *main_ctx = glr_current_context();
  async_test5_job_data *job_data = GLR_ALLOCATE_ARRAY(async_test5_job_data, n);
  for (int i = 0; i < n; ++i) {
    job_data[i].sum = &sum;
    job_data[i].number = i;
    job_data[i].expected = expected_sum;
    job_data[i].ctx = main_ctx;
    job_data[i].called = 0;
    job_data[i].should_be_called = threads;
  }

  async_test5_thread_data thread_data[threads];
  for (int i = 0; i < threads; ++i) {
    thread_data[i].arr = job_data;
    thread_data[i].arr_len = n;
    thread_data[i].r = glr_cur_thread_runtime();
  }

  int64_t begin = glr_timestamp_in_ms();
  for (int i = 0; i < threads; ++i) {
    if (pthread_create(&thread_data[i].pthread, NULL, test_async5_thread_fn,
                       thread_data + i)) {
      abort();
    }
  }
  glr_scheduler_yield(0);
  for (int i = 0; i < threads; ++i) {
    if (pthread_join(thread_data[i].pthread, NULL)) {
      abort();
    }
  }

  int64_t end = glr_timestamp_in_ms();
  printf("Test for %d asyncs from %d threads took %ld ms\n", n * threads,
         threads, end - begin);

  glr_cur_thread_runtime_cleanup();
}

static void test_sleep() {
  TEST;

  glr_sleep(1);

  glr_cur_thread_runtime_cleanup();
}

static void test_address_resolving(const char *addr) {
  TEST;
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);

  glr_error_t e = {};
  struct sockaddr_storage packed_address = glr_resolve_address2(addr, &e);
  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s glr_resolve_address2 failed: %.*s", __FILE__, __LINE__,
           __func__, msg.len, msg.data);
    abort();
  }

  str_t ip_port_str = glr_addr_to_string(&packed_address);
  printf("%s resolved to %.*s\n", addr, ip_port_str.len, ip_port_str.data);

  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
}

static void test_address_not_resolving(const char *addr) {
  TEST;
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);

  glr_error_t e = {};
  struct sockaddr_storage packed_address = glr_resolve_address2(addr, &e);
  if (e.error == GLR_GETADDRINFO_NO_RESULT_ERROR) {
  } else {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf(
        "%s:%d:%s glr_resolve_address2 failed: '%s' was resolved unexpectedly "
        "(%.*s)",
        __FILE__, __LINE__, __func__, addr, msg.len, msg.data);
    abort();
  }
  (void)packed_address;

  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
}

static void test_tcp_listening(const char *requested_addr) {
  TEST;
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);
  glr_error_t e = {};

  struct sockaddr_storage packed_address =
      glr_resolve_address2(requested_addr, &e);

  glr_fd_t *listener = glr_listen(&packed_address, 1000, 1, &e);

  (void)listener;
  struct sockaddr_storage res = glr_socket_local_address(listener, &e);

  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }

  str_t addr = glr_addr_to_string(&res);
  printf("%s:%d:%s listening on %.*s (expected %s)\n", __FILE__, __LINE__,
         __func__, addr.len, addr.data, requested_addr);

  glr_close(listener);

  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
}

static void test_unix_listening(const char *requested_addr) {
  TEST;
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);
  glr_error_t e = {};

  struct sockaddr_storage packed_address =
      glr_resolve_unix_socket_addr(requested_addr);

  unlink(requested_addr);
  glr_fd_t *listener = glr_listen(&packed_address, 1000, 0, &e);

  (void)listener;
  struct sockaddr_storage res = glr_socket_local_address(listener, &e);

  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s\n", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }

  str_t addr = glr_addr_to_string(&res);
  printf("%s:%d:%s listening on %.*s (expected %s)\n", __FILE__, __LINE__,
         __func__, addr.len, addr.data, requested_addr);

  glr_close(listener);

  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
}

static void test_fd_freelist_reuse(const char *unix_socket_addr) {
  TEST;
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);
  glr_error_t e = {};

  struct sockaddr_storage packed_address =
      glr_resolve_unix_socket_addr(unix_socket_addr);
  for (int i = 0; i < 5; ++i) {
    unlink(unix_socket_addr);
    glr_fd_t *listener = glr_listen(&packed_address, 1000, 0, &e);

    (void)listener;
    struct sockaddr_storage res = glr_socket_local_address(listener, &e);

    if (e.error) {
      str_t msg = glr_stringbuilder_build(&e.msg);
      printf("%s:%d:%s %.*s\n", __FILE__, __LINE__, __func__, msg.len,
             msg.data);
      abort();
    }

    str_t addr = glr_addr_to_string(&res);
    printf("%s:%d:%s listening on %.*s (expected %s)\n", __FILE__, __LINE__,
           __func__, addr.len, addr.data, unix_socket_addr);

    glr_close(listener);
  }

  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
}

void *test_accept_thread_fn(void *arg) {
  const char *requested_addr = arg;
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, requested_addr, sizeof(addr.sun_path));
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    abort();
  }
  int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (rc) {
    abort();
  }
  close(fd);
  return NULL;
}

static void test_accept(const char *requested_addr) {
  TEST;
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);
  glr_error_t e = {};

  struct sockaddr_storage packed_address =
      glr_resolve_unix_socket_addr(requested_addr);

  unlink(requested_addr);
  glr_fd_t *listener = glr_listen(&packed_address, 1000, 0, &e);

  (void)listener;
  struct sockaddr_storage res = glr_socket_local_address(listener, &e);

  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s\n", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }

  str_t addr = glr_addr_to_string(&res);
  printf("%s:%d:%s listening on %.*s (expected %s)\n", __FILE__, __LINE__,
         __func__, addr.len, addr.data, requested_addr);

  pthread_t connect_thread;
  if (pthread_create(&connect_thread, NULL, test_accept_thread_fn,
                     (void *)requested_addr)) {
    abort();
  }

  glr_accept_result_t accept_result = glr_raw_accept(listener, &e);

  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s accept failed: %.*s\n", __FILE__, __LINE__, __func__,
           msg.len, msg.data);
    abort();
  }

  addr = glr_addr_to_string(&accept_result.address);
  printf("%s:%d:%s accepted connection from %.*s\n", __FILE__, __LINE__,
         __func__, addr.len, addr.data);
  pthread_join(connect_thread, NULL);

  glr_close(accept_result.con);

  glr_close(listener);

  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
}

typedef struct {
  struct sockaddr_storage *addr;
} test_send_recv_data_t;

static void test_send_recv_coro_fn(void *arg) {
  test_send_recv_data_t *td = arg;
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);

  glr_error_t e = {};
  glr_fd_t *conn = glr_raw_connect(td->addr, glr_timestamp_in_ms() + 1000, &e);
  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s\n", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }
  const char data[] = "Hello world";
  int n = glr_fd_raw_send(conn, data, sizeof(data) - 1, &e);
  printf("%s:%d:%s Written %d bytes\n", __FILE__, __LINE__, __func__, n);
  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s\n", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }
  glr_close(conn);
  glr_destroy_allocator(&a);
}

static void test_send_recv() {
  TEST;
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);
  glr_error_t e = {};

  struct sockaddr_storage packed_address =
      glr_resolve_address2("127.0.0.1:0", &e);

  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d %.*s\n", __FILE__, __LINE__, msg.len, msg.data);
    abort();
  }

  glr_fd_t *listener = glr_listen(&packed_address, 1000, 0, &e);

  packed_address = glr_socket_local_address(listener, &e);

  test_send_recv_data_t td = {&packed_address};
  glr_go(test_send_recv_coro_fn, &td);

  glr_fd_t *conn = glr_raw_accept(listener, &e).con;
  char input_buffer[256];
  int n = glr_fd_raw_recv(conn, input_buffer, 255, &e);
  printf("%s:%d:%s Received %d bytes, '%.*s'\n", __FILE__, __LINE__, __func__,
         n, n, input_buffer);
  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d %.*s\n", __FILE__, __LINE__, msg.len, msg.data);
    abort();
  }

  glr_close(conn);
  glr_close(listener);
  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
}

static void test_connect_timeout() {
  TEST;
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);
  glr_error_t e = {};

  struct sockaddr_storage packed_address =
      glr_resolve_address2("www.google.com:444", &e);

  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d %.*s\n", __FILE__, __LINE__, msg.len, msg.data);
    abort();
  }

  glr_fd_t *conn =
      glr_raw_connect(&packed_address, glr_timestamp_in_ms() + 100, &e);
  if (e.error != GLR_TIMEOUT_ERROR) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s\n", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }

  (void)conn;
  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
}

static void test_recv_timeout() {
  TEST;
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);
  glr_error_t e = {};

  struct sockaddr_storage packed_address =
      glr_resolve_address2("127.0.0.1:0", &e);

  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d %.*s\n", __FILE__, __LINE__, msg.len, msg.data);
    abort();
  }

  glr_fd_t *listener = glr_listen(&packed_address, 1000, 0, &e);

  packed_address = glr_socket_local_address(listener, &e);

  glr_fd_t *conn = glr_raw_connect(&packed_address, 0, &e);
  glr_fd_set_deadline(conn, glr_timestamp_in_ms() + 50);
  char input_buffer[256] = {0};
  if (e.error) {
    abort();
  }
  int n = glr_fd_raw_recv(conn, input_buffer, 255, &e);
  if (e.error != GLR_TIMEOUT_ERROR) {
    abort();
  }

  printf("%s:%d:%s Received %d bytes, '%.*s'\n", __FILE__, __LINE__, __func__,
         n, n, input_buffer);

  glr_close(conn);
  glr_close(listener);
  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
}

static void test_send_timeout() {
  TEST;
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);
  glr_error_t e = {};

  struct sockaddr_storage packed_address =
      glr_resolve_address2("127.0.0.1:0", &e);

  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d %.*s\n", __FILE__, __LINE__, msg.len, msg.data);
    abort();
  }

  glr_fd_t *listener = glr_listen(&packed_address, 1000, 0, &e);

  packed_address = glr_socket_local_address(listener, &e);

  glr_fd_t *conn = glr_raw_connect(&packed_address, 0, &e);

  size_t output_buffer_len = 10 * 1024 * 1024;
  char *output_buffer = GLR_ALLOCATE_ARRAY(char, output_buffer_len);
  memset(output_buffer, 0, output_buffer_len);
  if (e.error) {
    abort();
  }

  while (e.error != GLR_TIMEOUT_ERROR) {
    glr_fd_set_deadline(conn, glr_timestamp_in_ms() + 50);
    int n = glr_fd_raw_send(conn, output_buffer, output_buffer_len, &e);
    printf("%s:%d:%s Sent %d of %ld bytes\n", __FILE__, __LINE__, __func__, n,
           output_buffer_len);
    if (e.error && e.error != GLR_TIMEOUT_ERROR) {
      abort();
    }
  }

  glr_close(conn);
  glr_close(listener);
  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
}

static void test_ssl_connect(const char *domain, const char *port) {
  printf("%s:%d:%s ssl connect %s:%s\n", __FILE__, __LINE__, __func__, domain,
         port);

  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);
  glr_error_t e = {};

  struct sockaddr_storage packed_address =
      glr_resolve_address(domain, port, &e);

  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d %.*s\n", __FILE__, __LINE__, msg.len, msg.data);
    abort();
  }
  SSL_CTX *ctx = glr_ssl_client_context();

  glr_ssl_ctx_set_verify_peer(ctx, 1);

  glr_fd_t *conn = glr_raw_connect(&packed_address, 0, &e);
  glr_ssl_client_conn_handshake(ctx, conn, domain, 0, &e);

  glr_ssl_shutdown(conn);

  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d %.*s\n", __FILE__, __LINE__, msg.len, msg.data);
    abort();
  }

  SSL_CTX_free(ctx);
  glr_close(conn);
  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
}

typedef struct {
  str_t hostname;
  str_t port;
} ssl_accept_test_data_t;

void *ssl_accept_test_connection_thread(void *arg) {
  ssl_accept_test_data_t *td = arg;
  SSL_CTX *ctx = glr_ssl_client_context();
  // SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

  BIO *bio = BIO_new_ssl_connect(ctx);
  if (!bio) abort();

  SSL *ssl = NULL;
  BIO_get_ssl(bio, &ssl);

  int rc = 0;
  printf("%s:%d:%s connecting to %.*s:%.*s  \n", __FILE__, __LINE__, __func__,
         td->hostname.len, td->hostname.data, td->port.len, td->port.data);

  rc = BIO_set_conn_hostname(bio, td->hostname.data);
  if (rc != 1) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  rc = BIO_set_conn_port(bio, td->port.data);
  if (rc != 1) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  rc = SSL_set_tlsext_host_name(ssl, "test.localhost");
  if (rc != 1) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  rc = BIO_do_connect(bio);
  if (rc != 1) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  rc = BIO_do_handshake(bio);
  if (rc != 1) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  rc = BIO_puts(bio, "Hello");
  if (rc <= 0) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  char buffer[256];
  int len = BIO_read(bio, buffer, 256);
  printf("%s:%d:%s BIO_read returned %d \n", __FILE__, __LINE__, __func__, len);

  BIO_free_all(bio);

  SSL_CTX_free(ctx);
  return NULL;
}

static void test_ssl_accept() {
  TEST;
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);
  glr_error_t e = {};
  SSL_CTX *ctx = glr_ssl_server_context();
  glr_ssl_ctx_set_key(ctx, "./certs/key.pem", /*password*/ NULL, &e);
  glr_ssl_ctx_set_cert(ctx, "./certs/cert.pem", &e);
  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }

  struct sockaddr_storage packed_address =
      glr_resolve_address2("0.0.0.0:0", &e);

  glr_fd_t *listener = glr_listen(&packed_address, 1000, 1, &e);

  struct sockaddr_storage res = glr_socket_local_address(listener, &e);

  str_t addr = glr_addr_to_string(&res);
  printf("%s:%d:%s listening on %.*s\n", __FILE__, __LINE__, __func__, addr.len,
         addr.data);

  ssl_accept_test_data_t td = {
      GLR_STR_LITERAL("127.0.0.1"),
      glr_sprintf("%d", glr_addr_get_port(&res)),
  };
  pthread_t client_thread;
  if (pthread_create(&client_thread, NULL, ssl_accept_test_connection_thread,
                     (void *)&td)) {
    abort();
  }

  glr_accept_result_t accept_result = glr_raw_accept(listener, &e);
  glr_ssl_server_conn_upgrade(ctx, accept_result.con, 0, &e);
  glr_ssl_shutdown(accept_result.con);
  pthread_join(client_thread, NULL);

  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }

  glr_close(accept_result.con);
  glr_close(listener);
  SSL_CTX_free(ctx);
  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
}

static void test_convenient_connect() {
  TEST;
  glr_fd_t *conn = NULL;
  glr_error_t e = {};

  conn = glr_tcp_dial_addr("google.com:80", 0, &e);
  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }
  glr_close(conn);

  conn = glr_tcp_dial_addr_ssl("google.com:443", 0, &e);
  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }
  glr_close(conn);

  conn = glr_tcp_dial_hostname_port("google.com", "80", 0, &e);
  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }
  glr_close(conn);

  conn = glr_tcp_dial_hostname_port_ssl("google.com", "443", 0, &e);
  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }
  glr_close(conn);

  conn = glr_tcp_dial_hostname_port2("google.com", 80, 0, &e);
  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }
  glr_close(conn);

  conn = glr_tcp_dial_hostname_port_ssl2("google.com", 443, 0, &e);
  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }
  glr_close(conn);

  glr_cur_thread_runtime_cleanup();
}

static void test_fd_conn_functions() {
  TEST;
  str_t payload = GLR_STR_LITERAL(
      "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n");

  char recv_buffer[256] = {};
  int received = 0;
  glr_fd_t *conn = NULL;
  glr_error_t e = {};

  conn = glr_tcp_dial_addr("google.com:80", 0, &e);
  glr_fd_conn_send_exactly(conn, payload.data, payload.len, &e);
  received = glr_fd_conn_recv_exactly(conn, recv_buffer, 20, &e);
  glr_fd_conn_shutdown(conn, &e);
  glr_close(conn);

  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }

  printf("%s:%d:%s RECEIVED from 80 port %d bytes: %.*s\n", __FILE__, __LINE__,
         __func__, received, received, recv_buffer);

  conn = glr_tcp_dial_addr_ssl("google.com:443", 0, &e);
  glr_fd_conn_send_exactly(conn, payload.data, payload.len, &e);
  received = glr_fd_conn_recv_exactly(conn, recv_buffer, 20, &e);
  glr_fd_conn_shutdown(conn, &e);
  glr_close(conn);

  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }

  printf("%s:%d:%s RECEIVED from 443 ssl port %d bytes: %.*s\n", __FILE__,
         __LINE__, __func__, received, received, recv_buffer);

  glr_cur_thread_runtime_cleanup();
}

typedef struct {
  glr_allocator_t a;
  stringbuilder_t sb;
} curl_perform_test_data_t;

size_t curl_perform_write_cb(void *contents, size_t size, size_t nmemb,
                             void *userp) {
  (void)userp;
  size_t realsize = size * nmemb;
  curl_perform_test_data_t *td = userp;
  glr_push_allocator(&td->a);
  glr_stringbuilder_append(&td->sb, contents, realsize);
  glr_pop_allocator();
  // printf("received %lu bytes, total=%lu\n", realsize, response_body->size());
  return realsize;
}

static void curl_perform_test(const char *url, ssize_t expected_size) {
  printf("\n%s:%d:%s %s Started\n", __FILE__, __LINE__, __func__, url);

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl_easy_init();
  if (!curl) {
    abort();
  }

  CURLcode res = CURLE_OK;

  curl_perform_test_data_t td = {};
  td.a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&td.a);
  td.sb = glr_make_stringbuilder(4096);

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_perform_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &td);
  curl_easy_setopt(curl, CURLOPT_PRIVATE, url);
  // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  // curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);
  glr_error_t e = {};
  res = glr_curl_perform(curl, &e);
  if (e.error) {
    str_t msg = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s", __FILE__, __LINE__, __func__, msg.len, msg.data);
    abort();
  }

  const char *p;
  curl_easy_getinfo(curl, CURLINFO_PRIVATE, &p);

  if (url != p) {
    fprintf(stderr, "CurlPerform messed up private pointer\n");
    abort();
  }

  if (res != CURLE_OK) {
    const char *what = curl_easy_strerror(res);
    fprintf(stderr, "curl_easy_perform() failed: %s\n", what);
    abort();
  }

  str_t response = glr_stringbuilder_build(&td.sb);

  if (response.len == 0) {
    abort();
  }

  printf("%s:%d:%s %s response is %u bytes long\n", __FILE__, __LINE__,
         __func__, url, response.len);

  if (expected_size >= 0 && response.len != (size_t)expected_size) {
    abort();
  }

  curl_easy_cleanup(curl);

  curl_global_cleanup();
  glr_destroy_allocator(&td.a);
  glr_cur_thread_runtime_cleanup();
  printf("%s:%d:%s %s DONE\n", __FILE__, __LINE__, __func__, url);
}

static void test_loggers() {
  printf("\n%s:%d:%s Started\n", __FILE__, __LINE__, __func__);
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);

  glr_error_t e = {};

  // test default sinks
  struct glr_logger_t *stdout_logger = glr_get_stdout_logger();
  if (stdout_logger == NULL) {
    abort();
  }

  struct glr_logger_t *stdout_logger2 = glr_get_stdout_logger();
  if (stdout_logger != stdout_logger2) {
    abort();
  }

  struct glr_logger_t *stderr_logger = glr_get_stderr_logger();
  if (stderr_logger == NULL) {
    abort();
  }

  struct glr_logger_t *stderr_logger2 = glr_get_stderr_logger();
  if (stderr_logger != stderr_logger2) {
    abort();
  }

  struct glr_logger_t *no_logger = glr_logger_create("/etc/forbidden.123", &e);
  if (no_logger) {
    abort();
  }

  if (e.error == 0) {
    abort();
  }
  str_t msg = glr_stringbuilder_build(&e.msg);
  printf("%s:%d:%s Expected error %.*s\n", __FILE__, __LINE__, __func__, msg.len,
         msg.data);

  glr_err_cleanup(&e);
  const char *path = "/tmp/glr.log";
  unlink(path);
  struct glr_logger_t *file_logger = glr_logger_create(path, &e);
  if (file_logger == NULL) {
    abort();
  }
  if (e.error) {
    printf("%s:%d:%s Unexpected error %.*s\n", __FILE__, __LINE__, __func__,
           msg.len, msg.data);
    abort();
  }


  //
  glr_log2(file_logger, GLR_LOG_LEVEL_TRACE, "It really works %d", 123);
  glr_log2(file_logger, GLR_LOG_LEVEL_DEBUG, "It really works %d", 234);
  glr_log2(file_logger, GLR_LOG_LEVEL_INFO, "It really works %d", 345);
  glr_log2(file_logger, GLR_LOG_LEVEL_WARNING, "It really works %d", 456);
  glr_log2(file_logger, GLR_LOG_LEVEL_ERROR, "It really works %d", 567);
  glr_log2(file_logger, GLR_LOG_LEVEL_CRITICAL, "It really works %d", 678);

  if (glr_get_default_logger() != stderr_logger) {
    abort();
  }
  glr_set_default_logger(stdout_logger);
  if (glr_get_default_logger() != stdout_logger) {
    abort();
  }

  if (glr_get_logger() != stdout_logger) {
    abort();
  }

  glr_set_logger(file_logger);
  if (glr_get_logger() != file_logger) {
    abort();
  }

  glr_log(GLR_LOG_LEVEL_CRITICAL, "Logger from context works");
  glr_log_error("Convenient logging also works");

  glr_set_min_log_level(file_logger, GLR_LOG_LEVEL_DEBUG);
  glr_log_trace("these message SHOULD NOT be outputted");

  glr_set_logger(NULL);
  glr_logger_destroy(file_logger);

  glr_pop_allocator();
  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
  printf("%s:%d:%s DONE\n", __FILE__, __LINE__, __func__);
}

static void test_loggers_flush() {
  printf("\n%s:%d:%s Started\n", __FILE__, __LINE__, __func__);

  struct glr_logger_t *stderr_logger = glr_get_stderr_logger();
  glr_log2(stderr_logger, GLR_LOG_LEVEL_TRACE, "These should be printed %d!!!", 123);

  printf("%s:%d:%s DONE\n", __FILE__, __LINE__, __func__);
}

static void test_logging_context() {
  printf("\n%s:%d:%s Started\n", __FILE__, __LINE__, __func__);

  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);

  glr_append_logging_context("user_id=%d;ip=%s;",123, "127.0.0.1");
  glr_log_info("Testing logging context");

  glr_append_logging_context("handler=%s;", "sign-in");
  glr_log_info("Testing logging context again");

  glr_pop_allocator();
  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();

  printf("%s:%d:%s DONE\n", __FILE__, __LINE__, __func__);
}

static void test_logger_autoflush_on_high_levels() {
  printf("\n%s:%d:%s Started\n", __FILE__, __LINE__, __func__);
  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);

  struct glr_logger_t *stdout_logger = glr_get_stdout_logger();
  glr_set_default_logger(stdout_logger);

  glr_log_trace("Minor log message");
  glr_log_error("Serious error message");

  glr_pop_allocator();
  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();
  printf("%s:%d:%s DONE\n", __FILE__, __LINE__, __func__);
}

void signal_handling_function(int signal, void *data) {
  printf("received signal %d data=%p on %ld\n", signal, data, syscall(SYS_gettid));
}

static void test_signal_handling_thread() {
  printf("\n%s:%d:%s Started\n", __FILE__, __LINE__, __func__);
  int a = 0;
  printf("setup signal handler data=%p on %ld\n", &a, syscall(SYS_gettid));
  glr_launch_signal_handling_thread(signal_handling_function, &a);
  printf("sending %d signal\n", SIGUSR1);
  int n = kill(getpid(), SIGUSR1);
  if (n) {
    printf("raise() failed\n");
  }
  glr_sleep(100);
  printf("%s:%d:%s DONE\n", __FILE__, __LINE__, __func__);
}

static void test_signalfd() {
  printf("\n%s:%d:%s Started\n", __FILE__, __LINE__, __func__);

  glr_allocator_t a = glr_create_transient_allocator(NULL);
  glr_push_allocator(&a);

  glr_error_t e = {};

  int signals[] = {SIGALRM, 0};
  glr_block_signals(signals, &e);
  if (e.error) {
    str_t s = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s\n",
      __FILE__, __LINE__, __func__, s.len, s.data);
    abort();
  }

  glr_fd_t *fd = glr_signalfd(signals, &e);
  if (e.error) {
    str_t s = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s\n",
      __FILE__, __LINE__, __func__, s.len, s.data);
    abort();
  }

  alarm(1);

  struct signalfd_siginfo siginfo = {};
  glr_fd_raw_read(fd, (char *)&siginfo, sizeof(siginfo), &e);
  if (e.error) {
    str_t s = glr_stringbuilder_build(&e.msg);
    printf("%s:%d:%s %.*s\n",
      __FILE__, __LINE__, __func__, s.len, s.data);
    abort();
  }

  printf("Caught signal %d (SIGALRM=%d)\n", siginfo.ssi_signo, SIGALRM);

  if (siginfo.ssi_signo != SIGALRM) {
    printf("%s:%d:%s received wrong signal: %d instead of %d\n",
      __FILE__, __LINE__, __func__,
      siginfo.ssi_signo, SIGALRM);
  }

  glr_close(fd);

  glr_pop_allocator();
  glr_destroy_allocator(&a);
  glr_cur_thread_runtime_cleanup();

  printf("%s:%d:%s DONE\n", __FILE__, __LINE__, __func__);
}

int main() {
  int async_tests_enabled = 0;
  int dns_tests_enabled = 0;
  int curl_tests_enabled = 0;
  test_signalfd();
  test_signal_handling_thread();

  label_pointers();
  error_handling();
  test_global_malloc_free_adapter();
  test_transient_allocator();
  test_glr_sprintf();
  test_glr_malloc_free();
  test_allocators_stack();
  test_stringbuilder();
  test_stringbuilder2();
  test_transient_allocator2();
  test_stringbuilder3();
  test_stringbuilder4();
  bench_emptysnprintf_len_calculation();
  bench_snprintf_len_calculation();
  bench_snprintf_len_calculation2();
  test_coro_transfer();
  test_scheduler();
  test_scheduler_resizing();
  test_scheduler_execution();
  test_poll();
  test_error_handling();
  test_transient_allocator_embedding();
  bench_transient_allocation();
  test_timers();
  test_allocator_preserving_between_coros();

  if (async_tests_enabled) {
    test_async1();
    for (int i = 0; i < 100; ++i) {
      test_async2(10000);
    }
    for (int i = 0; i < 100; ++i) {
      test_async2(100000);
    }
    for (int i = 0; i < 10; ++i) {
      test_async3(10000);
    }
    test_async4();
    for (int i = 0; i < 100; ++i) {
      test_async5(100000);
    }
  }

  test_sleep();

  if (dns_tests_enabled) {
    test_address_resolving("www.google.com:443");
    test_address_resolving("youtube.com:443");
    test_address_resolving("facebook.com:443");
    test_address_not_resolving("my.abra.cadabra:443");
    test_address_not_resolving("othe.rser.vice:1024");
  }

  test_tcp_listening("127.0.0.1:12345");
  test_tcp_listening("0.0.0.0:0");

  test_unix_listening("/tmp/glr.sock");
  test_fd_freelist_reuse("/tmp/glr.sock");

  test_accept("/tmp/glr.sock");
  test_send_recv();
  test_connect_timeout();
  test_recv_timeout();
  test_send_timeout();

  test_ssl_connect("httpbin.org", "443");
  test_ssl_accept();
  test_convenient_connect();
  test_fd_conn_functions();

  if (curl_tests_enabled) {
    curl_perform_test("http://example.com", -1);
    curl_perform_test("https://example.com", -1);
    curl_perform_test("https://httpbin.org/bytes/10000", 10000);
    curl_perform_test("https://httpbin.org/bytes/100000", 100000);
    curl_perform_test("https://www.google.com", -1);
  }

  test_loggers();
  test_logging_context();
  test_logger_autoflush_on_high_levels();

  //these test should be last
  test_loggers_flush();
}
