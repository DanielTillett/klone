# Klin fuzz targets for ClusterFuzzLite (doc/FUZZING). Written to work
# unchanged as an OSS-Fuzz project's Dockerfile: OSS-Fuzz projects keep
# theirs in the oss-fuzz repository and clone the source instead of the
# COPY below.
#
# The image is OSS-Fuzz's base-builder (Ubuntu 20.04, clang), pinned by
# digest. It has OpenSSL 1.1, and Klin needs 3.x: OpenSSL is built here,
# static and from a pinned tag (checked against its commit), so that the
# fuzzers carry it with them to the runner image.
FROM gcr.io/oss-fuzz-base/base-builder:v1@sha256:1f9cf74bc3d7029b528494542f9d9851b256dceed38d3f420989434dc5ae0760

RUN apt-get update && apt-get install -y --no-install-recommends \
        make perl pkg-config zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# CMake 3.24 or later (Ubuntu 20.04 has 3.16), and Ninja
RUN pip3 install --no-cache-dir cmake==3.31.6 ninja==1.11.1.4

ARG OPENSSL_TAG=openssl-3.5.9
ARG OPENSSL_COMMIT=45e844fa2a14ec92d146bd8f5778ac130b6625fb
RUN git -c advice.detachedHead=false clone --depth 1 --branch "$OPENSSL_TAG" \
        https://github.com/openssl/openssl.git /tmp/openssl && \
    test "$(git -C /tmp/openssl rev-parse HEAD)" = "$OPENSSL_COMMIT" && \
    cd /tmp/openssl && \
    ./Configure no-shared no-tests no-docs no-apps --prefix=/opt/openssl \
        --libdir=lib && \
    make -j"$(nproc)" build_libs && make install_dev && \
    rm -rf /tmp/openssl

COPY . $SRC/klin
WORKDIR $SRC/klin
COPY .clusterfuzzlite/build.sh $SRC/
