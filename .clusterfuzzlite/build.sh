#!/bin/bash -eu
# Copyright (c) 2026 Daniel Tillett. Part of Klin; see the LICENSE file.
#
# Build every fuzz target in fuzz/ for ClusterFuzzLite (doc/FUZZING), with
# the compiler, sanitizer flags ($CFLAGS) and engine ($LIB_FUZZING_ENGINE)
# it provides, into $OUT with their seed corpora and dictionaries. Written
# to serve unchanged as an OSS-Fuzz project's build.sh.

cd "$SRC/klin"

# LibU at the commit pinned in build/dependencies.json
if [ ! -d libu ]; then
    url=$(python3 -c 'import json; print(json.load(open("build/dependencies.json"))["libu"]["url"])')
    commit=$(python3 -c 'import json; print(json.load(open("build/dependencies.json"))["libu"]["commit"])')
    git -c core.autocrlf=false clone --no-checkout "$url" libu
    git -C libu -c advice.detachedHead=false checkout --detach "$commit"
fi

# OpenSSL 3 from the Dockerfile (elsewhere, the system's), static like zlib:
# the fuzzers run in another image. libFuzzer is C++: CMake links the
# targets with $CXX.
openssl=()
if [ -d /opt/openssl ]; then
    openssl=(-DOPENSSL_ROOT_DIR=/opt/openssl)
fi
cmake -S . -B "$WORK/build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DKLIN_FUZZ=ON -DKLIN_FUZZ_ENGINE="$LIB_FUZZING_ENGINE" \
    -DKLIN_HARDENING=OFF \
    "${openssl[@]}" -DOPENSSL_USE_STATIC_LIBS=TRUE -DZLIB_USE_STATIC_LIBS=ON
targets=$(grep -E '^[a-z_]+$' fuzz/targets.txt)
cmake --build "$WORK/build" --target $(for t in $targets; do echo "fuzz_$t"; done)

for t in $targets; do
    cp "$WORK/build/fuzz/fuzz_$t" "$OUT/"
    if [ -d "fuzz/seeds/$t" ]; then
        (cd "fuzz/seeds/$t" && python3 -m zipfile -c "$OUT/fuzz_${t}_seed_corpus.zip" *)
    fi
    if [ -f "fuzz/fuzz_$t.dict" ]; then
        cp "fuzz/fuzz_$t.dict" "$OUT/"
    fi
done
