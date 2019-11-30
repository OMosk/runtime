COV_FLAGS:=-fprofile-instr-generate -fcoverage-mapping
b:
	time clang -g -O3 $(COV_FLAGS) all.c -o test

cov:
	llvm-profdata merge -sparse default.profraw -o default.profdata
	llvm-cov export -format=lcov -instr-profile=default.profdata test > default.lcov
	genhtml default.lcov -o cov

clean:
	rm -rf *core* *default.* test cov

.PHONY: cov
