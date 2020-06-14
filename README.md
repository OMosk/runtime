# GLR runtime
Additional C runtime for Linux amd64 with stackfull coroutines, non-blocking IO, error handling, memory management and more

## Motivation
Most of my professional work consists of backend service development that require doing a lot of IO. I was fascinated by convenience and simplicity of Golang but I still wanted more control over memory so I decided to create additional runtime for C that will provide this convenience.
After stackfull coroutines and IO was done I decided to add opiniated error handling and memory management.
