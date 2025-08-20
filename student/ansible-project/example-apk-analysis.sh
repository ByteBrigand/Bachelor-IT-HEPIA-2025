#!/bin/bash
mkdir -p project1/{static_analysis/{jadx_output,androguard,ghidra_project},dynamic/{frida_scripts,runtime_data},fuzzing/{harness,crashes,corpus},artifacts/{libs,lib_deps,decompiled}}

# └── project1
#     ├── artifacts
#     │   ├── decompiled
#     │   ├── lib_deps
#     │   └── libs
#     ├── dynamic
#     │   ├── frida_scripts
#     │   └── runtime_data
#     ├── fuzzing
#     │   ├── corpus
#     │   ├── crashes
#     │   └── harness
#     └── static_analysis
#         ├── androguard
#         ├── ghidra_project
#         └── jadx_output


jadx -d project1/static_analysis/jadx_output \
     --show-bad-code \
     --deobf \
     --deobf-min 3 \
     --deobf-max 64 \
     --deobf-use-sourcename \
     --threads-count 4 \
     target.apk

cp project1/static_analysis/jadx_output/resources/lib/arm64-v8a/*.so project1/artifacts/libs/

copy_library_from_device() {
    local lib_name="$1"
    adb shell "find / -path '*lib*/$lib_name' 2>/dev/null" | while read -r found_lib; do
        adb pull "$found_lib" "project1/artifacts/lib_deps/"
    done
}
for so_file in project1/artifacts/libs/*.so; do
    readelf -d "$so_file" 2>/dev/null | grep '(NEEDED)' | awk -F'[][]' '{print $2}' | while read -r dep_name; do
        if [ -n "$dep_name" ]; then
            copy_library_from_device "$dep_name"
        fi
    done
done




# for flags, check https://static.grumpycoder.net/pixel/support/analyzeHeadlessREADME.html

analyzeHeadless \
  "project1/static_analysis/ghidra_project" project1 -noanalysis \
  -import "project1/artifacts/libs/*"
analyzeHeadless \
  "project1/static_analysis/ghidra_project" project1 -noanalysis \
  -import "project1/artifacts/lib_deps/*"

decompile_so() {
    local so_filename="$1"
    analyzeHeadless \
      "project1/static_analysis/ghidra_project" "project1" \
      -process "$so_filename" \
      -processor "AARCH64:LE:64:v8A" \
      -cspec default \
      -scriptPath /opt/ghidra/Ghidra/Features/Base/ghidra_scripts/ \
      -postScript DecompileScript.java "project1/artifacts/decompiled/$so_filename.decompiled.c"
}
for so_file in project1/artifacts/libs/*.so; do
    decompile_so $(basename "$so_file")
done

androguard cg -o project1/static_analysis/callgraph.gml target.apk