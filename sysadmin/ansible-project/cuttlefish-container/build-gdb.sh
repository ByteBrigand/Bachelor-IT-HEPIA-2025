#!/bin/bash
set -euox pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <ndk_dir>"
    exit 1
fi

NDK_DIR="$(realpath "$1")"
NUM_JOBS="$(nproc)"
TARGET_TRIPLE="aarch64-linux-android"
API_LEVEL=33
TOOLCHAIN_DIR="${NDK_DIR}/toolchains/llvm/prebuilt/linux-aarch64"
SYSROOT_DIR="${TOOLCHAIN_DIR}/sysroot"

# Versions
GDB_VERSION="16.3"
GMP_VERSION="6.3.0"
MPFR_VERSION="4.2.2"
LIBICONV_VERSION="1.18"
READLINE_VERSION="8.3"
EXPAT_VERSION="2.7.1"

# Build directories
WORK_DIR="$(mktemp -d)"
GDB_BUILD_DIR="${WORK_DIR}/build"
PREFIX="${GDB_BUILD_DIR}/android-deps"
OUTPUT_DIR="${WORK_DIR}/output/gdb-android"
OUTPUT_TARBALL="$(pwd)/gdb-android.tar.gz"

# Cleanup function
cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

# Utility functions
download_and_extract() {
    local url="$1"
    local output="$2"
    local extract_dir="$3"

    wget -O "${output}" "${url}"
    tar xf "${output}" -C "$(dirname "${extract_dir}")"
    rm "${output}"
}

# Create work directories
mkdir -p "${GDB_BUILD_DIR}" "${PREFIX}/include" "${OUTPUT_DIR}"

# Create custom glob.h
cat > "${PREFIX}/include/glob.h" << 'EOF'
#include_next <glob.h>

#ifndef __GLOB_FLAGS
#define __GLOB_FLAGS   (GLOB_ERR | GLOB_MARK | GLOB_NOSORT | GLOB_DOOFFS | GLOB_NOESCAPE | GLOB_NOCHECK | GLOB_APPEND | GLOB_PERIOD | GLOB_ALTDIRFUNC | GLOB_BRACE | GLOB_NOMAGIC | GLOB_TILDE | GLOB_ONLYDIR | GLOB_TILDE_CHECK)
#endif

#ifndef GLOB_ONLYDIR
#define GLOB_ONLYDIR     0x100
#endif

#ifndef GLOB_TILDE
#define GLOB_TILDE       0x200
#endif

#ifndef GLOB_TILDE_CHECK
#define GLOB_TILDE_CHECK 0x400
#endif

#ifndef GLOB_PERIOD
#define GLOB_PERIOD      0x800
#endif
EOF

# Setup toolchain symlinks
TRIPLE_PATH="${TOOLCHAIN_DIR}/bin/${TARGET_TRIPLE}"
GDB_TRIPLE_PATH="${GDB_BUILD_DIR}/bin/${TARGET_TRIPLE}"

mkdir -p "${GDB_BUILD_DIR}/bin"
ln -sf "${TOOLCHAIN_DIR}/bin/llvm-ar" "${GDB_TRIPLE_PATH}-ar"
ln -sf "${TOOLCHAIN_DIR}/bin/llvm-ranlib" "${GDB_TRIPLE_PATH}-ranlib"
ln -sf "${TOOLCHAIN_DIR}/bin/llvm-nm" "${GDB_TRIPLE_PATH}-nm"
ln -sf "${TOOLCHAIN_DIR}/bin/llvm-strip" "${GDB_TRIPLE_PATH}-strip"

# Configure build environment
export PATH="${GDB_BUILD_DIR}/bin:$PATH"
export CC="${TRIPLE_PATH}${API_LEVEL}-clang"
export CXX="${TRIPLE_PATH}${API_LEVEL}-clang++"
export AR="${GDB_TRIPLE_PATH}-ar"
export RANLIB="${GDB_TRIPLE_PATH}-ranlib"
export NM="${GDB_TRIPLE_PATH}-nm"
export STRIP="${GDB_TRIPLE_PATH}-strip"
export CFLAGS="--sysroot=${SYSROOT_DIR} -DANDROID -D__ANDROID_API__=${API_LEVEL} -I${PREFIX}/include"
export CXXFLAGS="${CFLAGS}"
#export LDFLAGS="-L${PREFIX}/lib"
export LDFLAGS="-L${PREFIX}/lib -static"

# Build libiconv
echo "Building libiconv ${LIBICONV_VERSION}..."
download_and_extract \
    "https://mirrors.kernel.org/gnu/libiconv/libiconv-${LIBICONV_VERSION}.tar.gz" \
    "${WORK_DIR}/libiconv.tar.gz" \
    "${GDB_BUILD_DIR}/libiconv-${LIBICONV_VERSION}"

cd "${GDB_BUILD_DIR}/libiconv-${LIBICONV_VERSION}"
./configure \
    --prefix="${PREFIX}" \
    --host=${TARGET_TRIPLE} \
    --enable-static \
    --disable-shared \
    --disable-nls
make -j"${NUM_JOBS}"
make install

# Build readline
echo "Building readline ${READLINE_VERSION}..."
download_and_extract \
    "https://mirrors.kernel.org/gnu/readline/readline-${READLINE_VERSION}.tar.gz" \
    "${WORK_DIR}/readline.tar.gz" \
    "${GDB_BUILD_DIR}/readline-${READLINE_VERSION}"

cd "${GDB_BUILD_DIR}/readline-${READLINE_VERSION}"
./configure \
    --prefix="${PREFIX}" \
    --host=${TARGET_TRIPLE} \
    --enable-static \
    --disable-shared \
    --with-curses \
    bash_cv_wcwidth_broken=no
make -j"${NUM_JOBS}"
make install

# Build GMP
echo "Building GMP ${GMP_VERSION}..."
download_and_extract \
    "https://gmplib.org/download/gmp/gmp-${GMP_VERSION}.tar.xz" \
    "${WORK_DIR}/gmp.tar.xz" \
    "${GDB_BUILD_DIR}/gmp-${GMP_VERSION}"

cd "${GDB_BUILD_DIR}/gmp-${GMP_VERSION}"
./configure \
    --prefix="${PREFIX}" \
    --host=${TARGET_TRIPLE} \
    --enable-static \
    --disable-shared
make -j"${NUM_JOBS}"
make install

# Build MPFR
echo "Building MPFR ${MPFR_VERSION}..."
download_and_extract \
    "https://www.mpfr.org/mpfr-current/mpfr-${MPFR_VERSION}.tar.xz" \
    "${WORK_DIR}/mpfr.tar.xz" \
    "${GDB_BUILD_DIR}/mpfr-${MPFR_VERSION}"

cd "${GDB_BUILD_DIR}/mpfr-${MPFR_VERSION}"
./configure \
    --prefix="${PREFIX}" \
    --host=${TARGET_TRIPLE} \
    --with-gmp="${PREFIX}" \
    --enable-static \
    --disable-shared
make -j"${NUM_JOBS}"
make install

# Build Expat
echo "Building Expat ${EXPAT_VERSION}..."
download_and_extract \
    "https://github.com/libexpat/libexpat/releases/download/R_${EXPAT_VERSION//./_}/expat-${EXPAT_VERSION}.tar.gz" \
    "${WORK_DIR}/expat.tar.gz" \
    "${GDB_BUILD_DIR}/expat-${EXPAT_VERSION}"

cd "${GDB_BUILD_DIR}/expat-${EXPAT_VERSION}"
./configure \
    --prefix="${PREFIX}" \
    --host=${TARGET_TRIPLE} \
    --enable-static \
    --disable-shared
make -j"${NUM_JOBS}"
make install

# Build GDB
echo "Building GDB ${GDB_VERSION}..."
download_and_extract \
    "https://sourceware.org/pub/gdb/releases/gdb-${GDB_VERSION}.tar.xz" \
    "${WORK_DIR}/gdb.tar.xz" \
    "${GDB_BUILD_DIR}/gdb-${GDB_VERSION}"

cd "${GDB_BUILD_DIR}/gdb-${GDB_VERSION}"

# Create and apply Android langinfo patch
cat > android-langinfo.patch << 'EOF'
--- a/gdbserver/linux-low.cc
+++ b/gdbserver/linux-low.cc
@@ -7012,7 +7012,11 @@ linux_process_target::thread_name (ptid_t thread)
      from the locale's encoding (we can't be sure this is the correct
      encoding, but it's as good a guess as we have) to UTF-8, but in a
      way that ignores any encoding errors.  See PR remote/30618.  */
-  const char *cset = nl_langinfo (CODESET);
+#ifdef __ANDROID__
+  const char *cset = "UTF-8";  // Android uses UTF-8 by default
+#else
+  const char *cset = nl_langinfo(CODESET);
+#endif
   iconv_t handle = iconv_open ("UTF-8//IGNORE", cset);
   if (handle == (iconv_t) -1)
     return replace_non_ascii (dest, name);
EOF
patch -p1 < android-langinfo.patch

# Verify auxv_t definitions
cat > conftest-auxv.c << 'EOF'
#include <elf.h>
#ifdef __ANDROID__
# define HAVE_ELF32_AUXV_T 1
# define HAVE_ELF64_AUXV_T 1
#endif

int main() {
    Elf32_auxv_t a32;
    Elf64_auxv_t a64;
    return 0;
}
EOF

if ! ${CC} conftest-auxv.c -c -o conftest-auxv.o; then
    echo "Failed to verify auxv_t definitions"
    exit 1
fi


export CFLAGS="${CFLAGS} -DHAVE_ELF32_AUXV_T=1 -DHAVE_ELF64_AUXV_T=1 -static"
export CXXFLAGS="${CXXFLAGS} -DHAVE_ELF32_AUXV_T=1 -DHAVE_ELF64_AUXV_T=1 -static"

# TODO : test if this compiles for Android. At least it solves the docs building error.
export CC_FOR_BUILD=gcc
export CFLAGS_FOR_BUILD=
export LDFLAGS_FOR_BUILD=

./configure \
    --host=${TARGET_TRIPLE} \
    --target=${TARGET_TRIPLE} \
    --disable-docs \
    --with-system-zlib \
    --with-gmp="${PREFIX}" \
    --with-mpfr="${PREFIX}" \
    --with-libiconv-prefix="${PREFIX}" \
    --disable-nls \
    --disable-werror \
    --disable-sim \
    --with-python=no \
    --with-system-readline \
    --with-libexpat-prefix="${PREFIX}" \
    --with-expat=yes \
    --without-guile \
    --disable-tui \
    --disable-gdbtk \
    --without-x \
    --without-included-regex \
    --without-included-gettext \
    --enable-static \
    --disable-shared \
    --enable-static-linking \
    --disable-bootstrap \
    --disable-multilib \
    --disable-install-libiberty \
    --disable-binutils \
    --disable-ld \
    --disable-gold \
    --disable-gas \
    --disable-gprof \
    --with-build-sysroot=$SYSROOT_DIR

rm -f conftest-auxv.c conftest-auxv.o

make V=1 -j"${NUM_JOBS}" all-gdb all-gdbserver


# Install binaries to output directory
cp gdb/gdb "${OUTPUT_DIR}/"
cp gdbserver/gdbserver "${OUTPUT_DIR}/"

# Strip binaries
${STRIP} "${OUTPUT_DIR}/gdb"
${STRIP} "${OUTPUT_DIR}/gdbserver"

# Create final tarball
cd "${WORK_DIR}/output"
tar -czf "${OUTPUT_TARBALL}" gdb-android

echo "Build complete. Output tarball: ${OUTPUT_TARBALL}"
