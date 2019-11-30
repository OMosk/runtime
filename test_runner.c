#include <stdio.h>
#include <malloc.h>
#include <time.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "glr.h"

static void label_pointers(void) {
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
  glr_allocator_t global = glr_get_default_allocator();
  int *a = (int *) glr_allocator_alloc(&global, sizeof(int), alignof(int));
  *a = 5;
  glr_allocator_free(&global, a);
  glr_reset_allocator(&global);
  glr_destroy_allocator(&global);
}

static void test_body_transient_allocator(glr_allocator_t *alloc) {
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
  glr_allocator_t alloc = glr_get_transient_allocator();

  test_body_transient_allocator(&alloc);

  printf(">>>Resetting transient allocator\n");
  glr_reset_allocator(&alloc);

  test_body_transient_allocator(&alloc);

  glr_destroy_allocator(&alloc);
}

static void test_transient_allocator2() {
  printf("%s:%d:%s \n", __FILE__, __LINE__, __func__);
  //Allocating in way that forces transient allocator allocate 3 4096 blocks
  //resetting allocator, request allocating of 8192, 0th block would not be able
  //to contain this data as 1st, so it should allocated 8192 block and swap it
  //with 1st
  glr_allocator_t alloc = glr_get_transient_allocator();

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
  glr_allocator_t a = glr_get_transient_allocator();

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

  glr_allocator_t a1 = glr_get_transient_allocator();
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
  glr_allocator_t a1 = glr_get_transient_allocator();
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
  glr_allocator_t a1 = glr_get_transient_allocator();
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
  printf("%s:%d:%s \n", __FILE__, __LINE__, __func__);
  //testing append
  glr_allocator_t a1 = glr_get_transient_allocator();
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
    (void)snprintf(NULL, 0, "String='%*s' int='%d' float='%f'\n",
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
  coro_transfer_test_data *tdata = arg;
  tdata->called = 1;
  printf("coro was executed\n");
  glr_transfer_to(tdata->main_ctx);
}

static void test_coro_transfer() {
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
  coro_transfer_test_data *tdata = arg;
  tdata->called = 1;
  printf("coro was executed\n");
  glr_scheduler_yield(1);
}

static void test_scheduler() {
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
  coro_transfer_test_data *tdata = arg;
  tdata->called++;
}

static void test_scheduler_resizing() {
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
}
