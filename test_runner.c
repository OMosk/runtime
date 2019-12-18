#include <stdio.h>
#include <malloc.h>
#include <time.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <stdatomic.h>

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

  int *a = (int*) malloc(sizeof(int));
  if (!a) goto *cleanup;
  cleanup = &&free_variable_a;

  *a = 5;

  if (time(NULL) % 2) {
    //Unexpected error
    printf("%s:%d:%s Caught expected error returning with appropiate cleanup\n",
           __FILE__, __LINE__, __func__);
    goto *cleanup;
  }

  int *b = (int*) malloc(sizeof(int));
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
  glr_allocator_t global = glr_get_default_allocator();
  int *a = (int *) glr_allocator_alloc(&global, sizeof(int), alignof(int));
  *a = 5;
  glr_allocator_free(&global, a);
  glr_reset_allocator(&global);
  glr_destroy_allocator(&global);
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
  } *c, cases[] = {
    {"int", sizeof(int), alignof(int), NULL},
    {"float", sizeof(float), alignof(float), NULL},
    {"uint8_t", sizeof(uint8_t), alignof(uint8_t), NULL},
    {"int64_t", sizeof(int64_t), alignof(int64_t), NULL},
    {"double", sizeof(double), alignof(double), NULL},
    {"char[256]", sizeof(char[256]), alignof(char[256]), NULL},
    {"test_struct_t", sizeof(test_struct_t), alignof(test_struct_t), NULL},
    {"char[9600]", sizeof(char[9600]), alignof(char[9600]), NULL},
    {"uint8_t", sizeof(uint8_t), alignof(uint8_t), NULL},
  };

  int cases_len = sizeof(cases) / sizeof(cases[0]);
  for (int i = 0; i < cases_len; ++i) {
    cases[i].result_ptr
        = glr_allocator_alloc(alloc, cases[i].size, cases[i].alignment);
  }

  for (int i = 0; i < cases_len; ++i) {
    c = cases + i;
    int aligned = ((uintptr_t) c->result_ptr % c->alignment) == 0;
    ssize_t ptrdiff_to_next = 0;
    int enough_size = 1;
    if (i < cases_len - 1) {
      ptrdiff_to_next = ((char *)(c+1)->result_ptr - (char *)c->result_ptr);
      enough_size = ptrdiff_to_next >= c->size;
    }
    printf("Alloc %s size=%ld alignment=%ld data=%p aligned=%d "
           "ptrdiff=%ld enough_size=%d\n",
           c->comment, c->size, c->alignment, c->result_ptr, aligned,
           ptrdiff_to_next, enough_size
           );

    char *data = c->result_ptr;
    for (char *it = data, *end = data + c->size; it < end; ++it) {
      *it = 'A';
    }

    glr_allocator_free(alloc, c->result_ptr);
  }
}

static void test_transient_allocator() {
  TEST;
  glr_allocator_t alloc = glr_get_transient_allocator(NULL);

  test_body_transient_allocator(&alloc);

  printf(">>>Resetting transient allocator\n");
  glr_reset_allocator(&alloc);

  test_body_transient_allocator(&alloc);

  glr_destroy_allocator(&alloc);
}

static void test_transient_allocator2() {
  TEST;
  printf("%s:%d:%s \n", __FILE__, __LINE__, __func__);
  //Allocating in way that forces transient allocator allocate 3 4096 blocks
  //resetting allocator, request allocating of 8192, 0th block would not be able
  //to contain this data as 1st, so it should allocated 8192 block and swap it
  //with 1st
  glr_allocator_t alloc = glr_get_transient_allocator(NULL);

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
  glr_allocator_t a = glr_get_transient_allocator(NULL);

  printf("%s:%d:%s Float=%.6f'\n", __FILE__, __LINE__, __func__, 123.45);

  str_t string = glr_sprintf(&a, "%s:%d:%s Float=%.6fEnd",
                             __FILE__, __LINE__, __func__, 123.45);

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

  glr_allocator_t a1 = glr_get_transient_allocator(NULL);
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
  glr_allocator_t a1 = glr_get_transient_allocator(NULL);
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

  glr_pop_allocator();
  glr_destroy_allocator(&a1);
}

static void test_stringbuilder2() {
  TEST;
  glr_allocator_t a1 = glr_get_transient_allocator(NULL);
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
  //testing append
  glr_allocator_t a1 = glr_get_transient_allocator(NULL);
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
  //Test buffers cleanup
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
  int64_t elapsed = (end.tv_sec - start.tv_sec) * 1e9 +
      (end.tv_nsec - start.tv_nsec);
  printf("%d iterations took = %f secs\n", n, elapsed / 1e9);
}

static void bench_snprintf_len_calculation() {
  printf("%s:%d:%s \n", __FILE__, __LINE__, __func__);
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  int n = 10000;
  for (int i = 0; i < n; ++i) {
    (void)snprintf(NULL, 0, "String='%s' int='%d' float='%f'\n",
                   "Hello world", 12345, 987.654);
  }
  struct timespec end;
  clock_gettime(CLOCK_MONOTONIC, &end);
  int64_t elapsed = (end.tv_sec - start.tv_sec) * 1e9 +
      (end.tv_nsec - start.tv_nsec);
  printf("%d iterations took = %f secs\n", n, elapsed / 1e9);
}

static void bench_snprintf_len_calculation2() {
  printf("%s:%d:%s \n", __FILE__, __LINE__, __func__);
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  int n = 10000;
  for (int i = 0; i < n; ++i) {
    (void)snprintf(NULL, 0, "String='%.*s' int='%d' float='%f'\n",
                   11, "Hello world", 12345, 987.654);
  }
  struct timespec end;
  clock_gettime(CLOCK_MONOTONIC, &end);
  int64_t elapsed = (end.tv_sec - start.tv_sec) * 1e9 +
      (end.tv_nsec - start.tv_nsec);
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
  coro_transfer_test_data tdata = { glr_current_context(), 0};
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
  coro_transfer_test_data tdata = { glr_current_context(), 0};
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
  coro_transfer_test_data tdata = { glr_current_context(), 0};
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
  //to mess with indexes in scheduler ring buffer
  coro_transfer_test_data tdata = { glr_current_context(), 0};
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
  if (sum != 8128) {//sum of arithmetic progression
    abort();
  }

  printf("arithmethic test exited cleanly\n");
  glr_cur_thread_runtime_cleanup();
}

void poll_test_coro(void *arg) {
  uintptr_t large_fd = (uintptr_t) arg;
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
  err_t err = {};
  int fd = eventfd(0, EFD_NONBLOCK);
  printf("Inited fd=%d\n", fd);
  uintptr_t large_fd = fd;
  glr_go(poll_test_coro, (void *)large_fd);
  int rc = glr_wait_for(fd, EPOLLIN|EPOLLET, &err);

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
  err_cleanup(&err);
}

static void test_error_handling() {
  TEST;
  err_t err = {};
  int fd = 1213456;
  glr_wait_for(fd, EPOLLIN|EPOLLET, &err);
  if (err.error) {
    str_t msg = glr_stringbuilder_build(&err.msg);
    printf("Expected error: %*s\n", msg.len, msg.data);
    glr_free(msg.data);
  } else {
    abort();
  }

  glr_cur_thread_runtime_cleanup();
  err_cleanup(&err);
}

static void test_transient_allocator_embedding() {
  TEST;
  glr_allocator_t a1 = glr_get_transient_allocator(NULL);
  glr_push_allocator(&a1);

  glr_allocator_t a2 = glr_get_transient_allocator(NULL);
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
  glr_allocator_t a1 = glr_get_transient_allocator(NULL);
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
  int64_t elapsed = (end.tv_sec - start.tv_sec) * 1e9 +
      (end.tv_nsec - start.tv_nsec);
  printf("transient malloc: %d iterations took = %f secs\n",
         n, elapsed / 1e9);

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
    td[i].cap = sizeof(execution_order)/sizeof(execution_order[0]);
    td[i].idx = i;
    td[i].main_ctx = cur;
    timers[i].arg = td + i;
    timers[i].callback = test_timers_coro;
    timers[i].deadline_posix_milliseconds = now + timeouts[i];
    glr_add_timer(timers + i);
  }

  printf("launching timers\n");
  glr_scheduler_yield(0);

#define CHECK(cond) if (!(cond)) abort();
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
  (void) arg;
  glr_allocator_t a = glr_get_transient_allocator(NULL);
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

void test_async1_job_fn(void *arg) {
  glr_scheduler_add(arg);
}

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
  printf("Test for %d (%d) asyncs took %ld ms\n", td.n, td.called, end-begin);
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
  printf("Test for %d (%d) asyncs took %ld ms\n", td.n, td.called, end-begin);
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
//    printf("%s called %d times(exp=%ld cur=%ld)\n", __func__, test_async5_called,
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
  int64_t expected_sum = threads * (0. + (double)(n-1)) / 2. * n;
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
    if (pthread_create(&thread_data[i].pthread, NULL, test_async5_thread_fn, thread_data + i)) {
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
  printf("Test for %d asyncs from %d threads took %ld ms\n", n*threads, threads, end-begin);

  glr_cur_thread_runtime_cleanup();

}

int main() {
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
