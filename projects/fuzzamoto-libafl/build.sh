#!/bin/bash

set -ex

# Check that we are on an x86_64 machine.
if [[ $(uname -m) != "x86_64" ]]; then
  echo "Error: The fuzzamoto project is only supported on x86 machines due to Nyx's dependency on x86"
  exit 1
fi

case "$FUZZING_ENGINE" in
  fuzzamoto_libafl_asan)  SANITIZER=asan; CORE_SANITIZERS=address ;;
  fuzzamoto_libafl_msan)  SANITIZER=msan; CORE_SANITIZERS=memory ;;
  fuzzamoto_libafl_tsan)  SANITIZER=tsan; CORE_SANITIZERS=thread ;;
  fuzzamoto_libafl_ubsan) SANITIZER=ubsan; CORE_SANITIZERS=undefined,integer ;;
  coverage) SANITIZER=coverage ;;
  *) exit 0 ;;
esac

if [ "$SANITIZER" = coverage ]; then
  # Mirror fuzzamoto's Dockerfile.coverage instead of fuzzor's libFuzzer coverage flags.
  export CC=clang CXX=clang++
  unset CFLAGS CXXFLAGS LIB_FUZZING_ENGINE
  COV_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
  CMAKE_ARGS=(-DAPPEND_CFLAGS="$COV_FLAGS" -DAPPEND_CXXFLAGS="$COV_FLAGS" -DAPPEND_LDFLAGS="$COV_FLAGS")
else
  export AFL_LLVM_DENYLIST=$PWD/fuzzamoto/target-patches/bitcoin-core-ir-denylist.txt
  CMAKE_ARGS=(-DSANITIZERS=$CORE_SANITIZERS)
  # As in fuzzamoto's Dockerfile.libafl: msan and tsan link against a sanitized libc++.
  if [ "$SANITIZER" = msan ] || [ "$SANITIZER" = tsan ]; then
    SAN_CFLAGS="-fsanitize=$CORE_SANITIZERS"
    SAN_CXXFLAGS="${SAN_CFLAGS} -nostdinc++ -nostdlib++ -isystem /libcxx_san_$SANITIZER/include/c++/v1 -L/libcxx_san_$SANITIZER/lib -Wl,-rpath,/libcxx_san_$SANITIZER/lib -lc++ -lc++abi -lpthread -Wno-unused-command-line-argument"
    DEPENDS_ARGS=(CFLAGS="$SAN_CFLAGS" CXXFLAGS="$SAN_CXXFLAGS")
    CMAKE_ARGS+=(-DCMAKE_C_FLAGS="$SAN_CFLAGS" -DCMAKE_CXX_FLAGS="$SAN_CXXFLAGS")
  fi
fi

pushd bitcoin

# The script runs once per build against the same checkout, so only apply what is missing.
apply_patch() {
  git apply --reverse --check "$1" 2>/dev/null || git apply "$1"
}
apply_patch ../fuzzamoto/target-patches/bitcoin-core-aggressive-rng.patch
if [ "$SANITIZER" = coverage ]; then
  apply_patch ../fuzzamoto/target-patches/bitcoin-core-reset-coverage-counters.patch
fi

# afl-cc reads -fcf-protection as a cfi request and forces -flto, which mold can't link.
sed -i '/try_append_cxx_flags("-fcf-protection=full"/d' ./CMakeLists.txt

sed -i --regexp-extended '/.*rm -rf .*extract_dir.*/d' ./depends/funcs.mk  # Keep extracted source
# Cap'n Proto builds its own fuzz harness when LIB_FUZZING_ENGINE is set.
env -u LIB_FUZZING_ENGINE make -C depends DEBUG=1 NO_QT=1 NO_ZMQ=1 NO_USDT=1 \
     SOURCES_PATH=$SOURCES_PATH \
     "${DEPENDS_ARGS[@]}" \
     AR=llvm-ar NM=llvm-nm RANLIB=llvm-ranlib STRIP=llvm-strip -j$(nproc)

cmake -B build_fuzz \
  --toolchain depends/$(./depends/config.guess)/toolchain.cmake \
  "${CMAKE_ARGS[@]}" \
  -DAPPEND_CPPFLAGS="-DFUZZAMOTO_FUZZING -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DABORT_ON_FAILED_ASSUME -U_FORTIFY_SOURCE"

cmake --build build_fuzz -j$(nproc) --target bitcoind

BITCOIND=$PWD/build_fuzz/bin/bitcoind
CARGO_ENV=(CC="" CXX="" CFLAGS="" CXXFLAGS="" LDFLAGS="" BITCOIND_PATH=$BITCOIND)

# Reproduction build (no nyx), used for coverage and for reproducing solutions.
env "${CARGO_ENV[@]}" cargo build --release \
  --manifest-path ../fuzzamoto/Cargo.toml \
  --target-dir ../fuzzamoto/target-repro \
  --package fuzzamoto-scenarios \
  --features "fuzzamoto-scenarios/reproduce"

if [ "$SANITIZER" = coverage ]; then
  for scenario in ../fuzzamoto/target-repro/release/scenario-ir; do
    [ -f "$scenario" ] && [ -x "$scenario" ] || continue
    dir=$OUT/fuzzamoto_$(basename $scenario)
    mkdir -p $dir
    cp $scenario $dir/scenario
    cp $BITCOIND $dir/bitcoind
    cp /workdir/run-coverage $dir/run-coverage
  done
else
  clang -fPIC -DENABLE_NYX -D_GNU_SOURCE -DNO_PT_NYX \
    ../fuzzamoto/fuzzamoto-nyx-sys/src/nyx-crash-handler.c -ldl -I. -shared -o libnyx_crash_handler.so

  cargo clean --release --manifest-path ../fuzzamoto/Cargo.toml -p fuzzamoto-nyx-sys

  env "${CARGO_ENV[@]}" cargo build --release \
    --manifest-path ../fuzzamoto/Cargo.toml \
    --package fuzzamoto-scenarios --package fuzzamoto-cli --package fuzzamoto-libafl \
    --features "fuzzamoto/fuzz,fuzzamoto-scenarios/fuzz,fuzzamoto-libafl/fuzz"

  cp ../fuzzamoto/target/release/fuzzamoto-libafl $OUT/

  # Pass in both the suppressions file and the symbolizer.
  if [ "$SANITIZER" = tsan ]; then
    SAN_ARGS=(--sanitizer-suppressions /workdir/tsan_suppressions --symbolizer-path /usr/bin/llvm-symbolizer)
  elif [ "$SANITIZER" = ubsan ]; then
    SAN_ARGS=(--sanitizer-suppressions /workdir/ubsan_suppressions --symbolizer-path /usr/bin/llvm-symbolizer)
  fi

  for scenario in ../fuzzamoto/target/release/scenario-ir; do
    [ -f "$scenario" ] && [ -x "$scenario" ] || continue
    scenario_name=$(basename $scenario)
    dir=$OUT/fuzzamoto_${scenario_name}

    ../fuzzamoto/target/release/fuzzamoto-cli init \
      --sharedir $dir \
      --crash-handler ./libnyx_crash_handler.so \
      --bitcoind $BITCOIND \
      --scenario $scenario \
      --nyx-dir /AFLplusplus/nyx_mode \
      --sanitizer $SANITIZER \
      "${SAN_ARGS[@]}" \

    mkdir -p $dir/repro
    cp ../fuzzamoto/target-repro/release/$scenario_name $dir/repro/scenario
    ln -sf ../bitcoind $dir/repro/bitcoind
  done
fi

# This build script is executed repeatedly. Make sure there are no left over
# build artifacts from previous executions, and that no build artifacts
# are in the final image.
rm -rf build_fuzz
make clean -C depends

popd
