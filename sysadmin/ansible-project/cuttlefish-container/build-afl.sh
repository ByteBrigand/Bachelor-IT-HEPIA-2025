#!/bin/bash
set -euox pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: $0 <ndk_dir> [patch_file]"
    exit 1
fi

export NDK_DIR="$(realpath "$1")"
export PATCH_FILE=""
if [ "$#" -eq 2 ]; then
    PATCH_FILE="$(realpath "$2")"
    if [ ! -f "$PATCH_FILE" ]; then
        echo "Error: patch file '$PATCH_FILE' not found"
        exit 1
    fi
fi

export AFLPLUSPLUS_VERSION="4.33c"
export API_LEVEL=33
export NUM_JOBS="$(nproc)"
export TARGET_TRIPLE="aarch64-linux-android"
export TOOLCHAIN_DIR="${NDK_DIR}/toolchains/llvm/prebuilt/linux-aarch64"
export SYSROOT_DIR="${TOOLCHAIN_DIR}/sysroot"
export ANDROID_AFL="/opt/afl-android"
export CLANG_VERSION=18

curl -L "https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/v${AFLPLUSPLUS_VERSION}.tar.gz" | tar xz

cd "AFLplusplus-${AFLPLUSPLUS_VERSION}"
if [ -n "$PATCH_FILE" ]; then
    patch -p1 < "$PATCH_FILE"
fi

make clean
make distrib \
    SYS=Android \
    ARCH=aarch64 \
    NDK_DIR=$NDK_DIR \
    API_LEVEL=$API_LEVEL \
    CODE_COVERAGE=1 \
    NO_CORESIGHT=1 \
    NO_NYX=1 \
    NO_UNICORN_ARM64=1 \
    LLVM_CONFIG=$TOOLCHAIN_DIR/bin/llvm-config \
    -j"${NUM_JOBS}"

mkdir -p "${ANDROID_AFL}"/{bin,include/afl,lib/afl}

cp *.so *.a *.o dynamic_list.txt "${ANDROID_AFL}"/lib/afl/
cp include/* "${ANDROID_AFL}"/include/afl/
cp afl-* "${ANDROID_AFL}"/bin/


make clean
make distrib -j"${NUM_JOBS}" CODE_COVERAGE=1 NO_CORESIGHT=1 NO_NYX=1 NO_UNICORN_ARM64=1
make install

cd ..
[ -d "AFLplusplus-${AFLPLUSPLUS_VERSION}" ] && rm -rf "AFLplusplus-${AFLPLUSPLUS_VERSION}"

cat > "/usr/local/bin/afl-clang-android" << EOF
#!/bin/sh
set -e
export AFL_PATH="${ANDROID_AFL}/lib/afl"
exec /usr/local/bin/afl-cc \\
    -target "${TARGET_TRIPLE}${API_LEVEL}" \\
    --sysroot="${SYSROOT_DIR}" \\
    -resource-dir="${TOOLCHAIN_DIR}/lib/clang/${CLANG_VERSION}" \\
    "\$@" \\
    "${ANDROID_AFL}/lib/afl/afl-compiler-rt.o"
EOF

chmod +x "/usr/local/bin/afl-clang-android"
