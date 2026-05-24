# Scratch OCI image that just carries the Unikraft helloworld
# unikernel binary at /kernel. The build workflow pulls the
# binary from unikraft.org/helloworld:latest first, then this
# Dockerfile packages it.
#
# Reminder: `docker create` on a FROM-scratch image needs a
# dummy command, e.g. `docker create unikernel:local /kernel`.

FROM scratch
COPY helloworld_fc-x86_64 /kernel
