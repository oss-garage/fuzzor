FROM fuzzor-base

RUN apt-get update && apt-get install -y \
  libgtk-3-dev pax-utils python3-msgpack \
  python3-jinja2 libcapstone-dev \
  libssl-dev

# Install rust
ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
RUN rustup install nightly && rustup default nightly

# Build qemu-nyx and libnyx
# Avoid "libcapstone.so.4 not found ld error" by setting lib path (not sure why this is necessary)
RUN cd /AFLplusplus/nyx_mode/ && \
  LIBRARY_PATH=/AFLplusplus/nyx_mode/QEMU-Nyx/capstone_v4/tests/:$LIBRARY_PATH ./build_nyx_support.sh
# Compile nyx htools
RUN cd /AFLplusplus/nyx_mode/packer/packer/linux_x86_64-userspace && \
  ./compile_64.sh
ENV FUZZOR_AFLPP_BIN_PATH=/AFLplusplus
ENV FUZZOR_DOCKER_NO_STACK_LIMIT=1

# Sanitized libc++ for the msan and tsan builds.
ARG LLVM_RELEASE=llvmorg-19.1.7
RUN git clone --depth=1 -b ${LLVM_RELEASE} https://github.com/llvm/llvm-project /llvm-project && \
  for san in msan tsan; do \
    cmake -G Ninja -S /llvm-project/runtimes -B /libcxx_san_build \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DLIBCXXABI_USE_LLVM_UNWINDER=OFF \
      -DLIBCXX_HARDENING_MODE=debug \
      -DLIBCXX_INCLUDE_TESTS=OFF \
      -DLIBCXX_ABI_DEFINES="_LIBCPP_ABI_BOUNDED_ITERATORS;_LIBCPP_ABI_BOUNDED_ITERATORS_IN_STD_ARRAY;_LIBCPP_ABI_BOUNDED_ITERATORS_IN_STRING;_LIBCPP_ABI_BOUNDED_ITERATORS_IN_VECTOR;_LIBCPP_ABI_BOUNDED_UNIQUE_PTR" \
      -DLLVM_ENABLE_PER_TARGET_RUNTIME_DIR=OFF \
      -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi" \
      -DCMAKE_INSTALL_PREFIX=/libcxx_san_$san \
      -DLLVM_TARGETS_TO_BUILD=Native \
      -DLLVM_USE_SANITIZER=$([ $san = tsan ] && echo Thread || echo Memory) && \
    ninja -C /libcxx_san_build install && \
    rm -rf /libcxx_san_build; \
  done && \
  rm -rf /llvm-project

ARG OWNER=bitcoin
ARG REPO=bitcoin
ARG BRANCH=master
ARG REVISION=

ENV SOURCES_PATH=/depends_sources

RUN git clone --depth 1 --branch $BRANCH https://github.com/$OWNER/$REPO.git
RUN make -C bitcoin/depends NO_QT=1 NO_ZMQ=1 NO_USDT=1 download-linux SOURCES_PATH=$SOURCES_PATH

RUN mv ./bitcoin/test/sanitizer_suppressions/tsan ./tsan_suppressions
RUN mv ./bitcoin/test/sanitizer_suppressions/ubsan ./ubsan_suppressions

ARG FUZZAMOTO_OWNER=oss-garage
ARG FUZZAMOTO_BRANCH=master
RUN git clone --depth 1 --branch $FUZZAMOTO_BRANCH https://github.com/$FUZZAMOTO_OWNER/fuzzamoto.git

COPY ./config.yaml .
COPY ./build.sh .
COPY ./run-coverage .

RUN --mount=type=cache,target=/ccache/ \
    --mount=type=cache,target=/ccache_asan/  \
    --mount=type=cache,target=/ccache_msan/  \
    --mount=type=cache,target=/ccache_tsan/  \
    --mount=type=cache,target=/ccache_ubsan/ \
    builder $PWD/config.yaml $PWD/build.sh $FUZZOR_HARNESSES

