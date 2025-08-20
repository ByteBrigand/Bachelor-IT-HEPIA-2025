#!/bin/bash

#set -xeuo

LOG_FILE="/var/log/adb-sync.log"
touch "$LOG_FILE"

DEVICE_FILES_PATH="/sdcard/shared_files"
DEVICE_STAGING_PATH="/sdcard/staging"
HOST_FILES_PATH="/shared/shared_files"
HOST_STAGING_PATH="/shared/staging/${HOSTNAME}"
TEMP_DIR="/tmp/adb_sync"
HOSTNAME=$(hostname)
MAX_ATTEMPTS=10
WAIT_BETWEEN_PULLS=2

while true; do
    # Ensure required directories exist
    mkdir -p "${TEMP_DIR}" "${HOST_STAGING_PATH}" "${HOST_FILES_PATH}"
    echo "$(date) - adb-sync: Starting sync for ${HOSTNAME}" >> "$LOG_FILE"
    # Check if device is connected
    if ! adb get-state >/dev/null 2>&1; then
        echo "$(date) - adb-sync: Device not connected" >> "$LOG_FILE"
        sleep 10
        continue
    fi
    # Create device directories
    adb shell "mkdir -p ${DEVICE_FILES_PATH} ${DEVICE_STAGING_PATH}/shared_files"
    # Get stable state from device
    prev_crc=""
    attempts=0
    pull_success=false
    while [ $attempts -lt $MAX_ATTEMPTS ]; do
        attempts=$((attempts + 1))
        rm -rf "${TEMP_DIR}/"*
        # Pull files from the device's shared_files directory
        adb pull "${DEVICE_FILES_PATH}" "${TEMP_DIR}/" >/dev/null 2>&1
        current_crc=$(find "${TEMP_DIR}" -type f -print0 | sort -z | xargs -0 cksum | awk '{print $1}' | cksum | awk '{print $1}')
        echo "$(date) - adb-sync: Attempt $attempts - CRC32: $current_crc" >> "$LOG_FILE"
        if [ -n "$prev_crc" ] && [ "$current_crc" = "$prev_crc" ]; then
            pull_success=true
            break
        fi
        prev_crc=$current_crc
        sleep $WAIT_BETWEEN_PULLS
    done
    if [ "$pull_success" = true ]; then
        # Move files to staging area
        mv "${TEMP_DIR}"/shared_files "${HOST_STAGING_PATH}/"
        # Merge directories using absolute paths with GNU find's -printf
        if find "${HOST_STAGING_PATH}/shared_files" -type d -printf '%P\0' | xargs -0 -I {} mkdir -p "${HOST_FILES_PATH}/{}" >/dev/null 2>&1; then
            # Merge files using absolute paths with GNU find's -printf
            find "${HOST_STAGING_PATH}/shared_files" -type f -printf '%P\0' | xargs -0 -I {} mv "${HOST_STAGING_PATH}/shared_files/{}" "${HOST_FILES_PATH}/{}" >/dev/null 2>&1
            echo "$(date) - adb-sync: Successfully merged files from device to host" >> "$LOG_FILE"
        else
            echo "$(date) - adb-sync: Error merging directories" >> "$LOG_FILE"
        fi
    else
        echo "$(date) - adb-sync: Failed to get stable state from device after $MAX_ATTEMPTS attempts" >> "$LOG_FILE"
    fi
    # Push merged state back to device's staging area
    adb shell "rm -rf ${DEVICE_STAGING_PATH}/shared_files/*"
    adb push "${HOST_FILES_PATH}" "${DEVICE_STAGING_PATH}/" >/dev/null 2>&1
    echo "$(date) - adb-sync: Pushed merged state to device staged area" >> "$LOG_FILE"
    # Create directories and files to device's shared_files directory
    adb shell "find \"${DEVICE_STAGING_PATH}/shared_files\" -type d -print0 | while IFS= read -r -d '' d; do rel_path=\"\${d#${DEVICE_STAGING_PATH}/shared_files}\"; rel_path=\"\${rel_path#/}\"; target_dir=\"${DEVICE_FILES_PATH}/\${rel_path}\"; mkdir -p \"\$target_dir\"; done"
    adb shell "find \"${DEVICE_STAGING_PATH}/shared_files\" -type f -print0 | while IFS= read -r -d '' f; do rel_path=\"\${f#${DEVICE_STAGING_PATH}/shared_files}\"; rel_path=\"\${rel_path#/}\"; target_file=\"${DEVICE_FILES_PATH}/\${rel_path}\"; mv \"\$f\" \"\$target_file\"; done"

    echo "$(date) - adb-sync: Moved files from staged area to final location on device" >> "$LOG_FILE"
    # Cleanup all temporary directories
    rm -rf "${TEMP_DIR}/"* "${HOST_STAGING_PATH}/"*
    adb shell "rm -rf ${DEVICE_STAGING_PATH}/shared_files/*"
    echo "$(date) - adb-sync: Cleaned up temporary directories" >> "$LOG_FILE"
    echo "$(date) - adb-sync: Sync completed for ${HOSTNAME}" >> "$LOG_FILE"
    # Wait 2 minutes before next sync
    sleep 120
done
