FROM aflplusplus/aflplusplus:latest
WORKDIR /work
COPY vendor/Open-SAE-J1939 /src
COPY fuzz/harness.c /work/harness.c
# Compile the stack + harness. Paths follow upstream Src/ layout.
RUN find /src/Src -name '*.c' ! -name 'Main.c' ! -name 'SocketCAN_Transmit_Receive.c' > /tmp/srcs.txt \
 && afl-clang-fast -DOPENSAE_J1939_TARGET_PLATFORM=INTERNAL_CALLBACK \
      -I/src/Src -I/src/Src/Open_SAE_J1939 \
      /work/harness.c $(cat /tmp/srcs.txt) -o /work/j1939-harness || \
    clang -DOPENSAE_J1939_TARGET_PLATFORM=INTERNAL_CALLBACK \
      -I/src/Src -I/src/Src/Open_SAE_J1939 \
      /work/harness.c $(cat /tmp/srcs.txt) -o /work/j1939-harness
COPY fuzz/seed /work/seed
CMD ["afl-fuzz", "-i", "/work/seed", "-o", "/work/out", "--", "/work/j1939-harness"]
