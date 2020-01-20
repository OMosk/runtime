COV_FLAGS:=-fprofile-instr-generate -fcoverage-mapping
ADDITIONAL_CHECKS:=-Wall -Wextra #-Werror
CFLAGS:=$(ADDITIONAL_CHECKS) $(COV_FLAGS) -march=native -pthread
#CFLAGS:=$(ADDITIONAL_CHECKS) -O3 -march=native -pthread
LIBS:=-l:libssl.a -l:libcrypto.a -ldl -lcurl
b:
	time clang -g $(CFLAGS) all.c -o test $(LIBS)

cov:
	llvm-profdata merge -sparse default.profraw -o default.profdata
	llvm-cov export -format=lcov -instr-profile=default.profdata test > default.lcov
	genhtml default.lcov -o cov

clean:
	rm -rf *core* *default.* test cov

.PHONY: cov
