#!/usr/bin/env bash
set -euo pipefail

# This script assumes that you are running on an ARM64 GNU/Linux host.

NDK_VERSION="r27"
NDK_ZIP="android-ndk-${NDK_VERSION}-linux.zip"
NDK_URL="https://dl.google.com/android/repository/${NDK_ZIP}"
NDK_DIR="/opt/android-ndk"
TOOLCHAIN_DIR_X86="${NDK_DIR}/toolchains/llvm/prebuilt/linux-x86_64"
TOOLCHAIN_DIR_ARM64="${NDK_DIR}/toolchains/llvm/prebuilt/linux-aarch64"
LLVM_INSTALL_DIR_ARM64="/usr" # /usr/bin/clang /usr/lib/clang /usr/include/clang
TARGET_TRIPLE="aarch64-linux-android"


check_file_arch() {
    local file="$1"
    if [ -f "$file" ] && [ -x "$file" ]; then
        if file "$file" | grep -q "x86-64"; then
            echo "[!] Warning: Removing x86_64 binary: $file"
            rm -f "$file"
            return 1
        fi
    fi
    return 0
}

export -f check_file_arch

# ------------------------------------------------------ DOWNLOAD & EXTRACT NDK
mkdir -p /tmp
cd /tmp
echo "[*] Downloading Android NDK ${NDK_VERSION}..."
wget -q "${NDK_URL}"

echo "[*] Extracting NDK..."
unzip -q "${NDK_ZIP}"
rm -f "${NDK_ZIP}"

echo "[*] Installing NDK to ${NDK_DIR}..."
mv "android-ndk-${NDK_VERSION}" "${NDK_DIR}"

# ------------------------------------------------------ SETUP ARM64 TOOLCHAIN
echo "[*] Setting up ARM64 toolchain directories..."
mkdir -p "${TOOLCHAIN_DIR_ARM64}/bin"
mkdir -p "${TOOLCHAIN_DIR_ARM64}/lib/clang"

echo "[*] Copying sysroot from x86 to ARM64..."
cp -r "${TOOLCHAIN_DIR_X86}/sysroot" "${TOOLCHAIN_DIR_ARM64}/sysroot"

echo "[*] Copying resources from host to ARM64..."
cp -r "/usr/lib/clang/18" "${TOOLCHAIN_DIR_ARM64}/lib/clang/"

echo "[*] Copying resources from x86 to ARM64..."
cp -r "${TOOLCHAIN_DIR_X86}/lib/clang/18" "${TOOLCHAIN_DIR_ARM64}/lib/clang/"

echo "[*] Installing Clang for ARM64..."
cp "${LLVM_INSTALL_DIR_ARM64}/bin/clang" "${TOOLCHAIN_DIR_ARM64}/bin/clang-18"
ln -sf "${TOOLCHAIN_DIR_ARM64}/bin/clang-18" "${TOOLCHAIN_DIR_ARM64}/bin/clang"
ln -sf "${TOOLCHAIN_DIR_ARM64}/bin/clang" "${TOOLCHAIN_DIR_ARM64}/bin/clang++"

# ------------------------------------------------------ CREATE API-LEVEL WRAPPERS
echo "[*] Creating API-level clang wrappers..."
for api in $(seq 21 35); do
    cat > "${TOOLCHAIN_DIR_ARM64}/bin/aarch64-linux-android${api}-clang" <<EOF
#!/usr/bin/env bash
bin_dir=\$(dirname "\$0")
if [ "\$1" != "-cc1" ]; then
    exec "\$bin_dir/clang" --target=aarch64-linux-android${api} "\$@"
else
    exec "\$bin_dir/clang" "\$@"
fi
EOF
    chmod +x "${TOOLCHAIN_DIR_ARM64}/bin/aarch64-linux-android${api}-clang"

    cat > "${TOOLCHAIN_DIR_ARM64}/bin/aarch64-linux-android${api}-clang++" <<EOF
#!/usr/bin/env bash
bin_dir=\$(dirname "\$0")
if [ "\$1" != "-cc1" ]; then
    exec "\$bin_dir/clang++" --target=aarch64-linux-android${api} "\$@"
else
    exec "\$bin_dir/clang++" "\$@"
fi
EOF
    chmod +x "${TOOLCHAIN_DIR_ARM64}/bin/aarch64-linux-android${api}-clang++"
done

# ------------------------------------------------------ COPY LLVM TOOLS
echo "[*] Copying LLVM tools to ARM64 toolchain..."
cd "${TOOLCHAIN_DIR_ARM64}/bin"
for tool in $(ls "${LLVM_INSTALL_DIR_ARM64}/bin/" | grep -v '^clang$'); do
    if [ -f "${LLVM_INSTALL_DIR_ARM64}/bin/${tool}" ]; then
        cp "${LLVM_INSTALL_DIR_ARM64}/bin/${tool}" ./
        check_file_arch "${tool}"
    fi
done
cp "${LLVM_INSTALL_DIR_ARM64}/bin/llvm-config" "${TOOLCHAIN_DIR_ARM64}/bin/"

# ------------------------------------------------------ CREATE SYMLINKS FOR BINUTILS
echo "[*] Creating LLVM binutils symlinks..."
for tool in ar as nm objcopy objdump ranlib strip; do
    ln -sf "llvm-${tool}" "${TARGET_TRIPLE}-${tool}"
done

ln -sf lld ld.lld
ln -sf lld ld
ln -sf lld ld64.lld
ln -sf lld lld-link
ln -sf lld wasm-ld
ln -sf llvm-ar llvm-lib
ln -sf llvm-ar llvm-dlltool
ln -sf llvm-ar llvm-ranlib
ln -sf llvm-objcopy llvm-strip
ln -sf llvm-readobj llvm-readelf
ln -sf llvm-symbolizer llvm-addr2line
ln -sf llvm-rc llvm-windres



echo "[*] Checking for any remaining x86_64 binaries..."
find "${TOOLCHAIN_DIR_ARM64}/bin" -type f -executable -exec bash -c 'check_file_arch "$1"' _ {} \;

echo "[+] Android NDK ${NDK_VERSION} ARM64 toolchain setup complete."