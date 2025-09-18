#!/bin/bash

#set -euox

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

# AFL++ specific sync patterns
REQUIRED_DIRS="queue .synced"
OPTIONAL_DIRS="crashes hangs"

while true; do
    mkdir -p "${TEMP_DIR}" "${HOST_STAGING_PATH}" "${HOST_FILES_PATH}"
    echo "$(date) - adb-sync: Starting sync for ${HOSTNAME}" >> "$LOG_FILE"
    
    if ! adb get-state >/dev/null 2>&1; then
        echo "$(date) - adb-sync: Device not connected" >> "$LOG_FILE"
        sleep 10
        continue
    fi
    
    adb shell "mkdir -p ${DEVICE_FILES_PATH} ${DEVICE_STAGING_PATH}"
    
    prev_crc=""
    attempts=0
    pull_success=false
    while [ $attempts -lt $MAX_ATTEMPTS ]; do
        attempts=$((attempts + 1))
        rm -rf "${TEMP_DIR:?}/"*
        
        # Pull required and optional directories from each fuzzer output
        instances=$(adb shell "ls ${DEVICE_FILES_PATH}/output/")
        echo "Found instances: $instances" >> "$LOG_FILE"
        
        for instance in $instances; do
            instance=$(echo "$instance" | tr -d '\r')
            echo "Processing instance: $instance" >> "$LOG_FILE"
            
            for dir in $REQUIRED_DIRS $OPTIONAL_DIRS; do
                if adb shell "[ -d ${DEVICE_FILES_PATH}/output/${instance}/${dir} ]"; then
                    echo "Found directory: ${dir} in instance ${instance}" >> "$LOG_FILE"
                    mkdir -p "${TEMP_DIR}/${instance}"
                    pull_cmd="adb pull ${DEVICE_FILES_PATH}/output/${instance}/${dir} ${TEMP_DIR}/${instance}/"
                    echo "Pulling with: $pull_cmd" >> "$LOG_FILE"
                    $pull_cmd
                fi
            done
        done
        
        current_crc=$(find "${TEMP_DIR}" -type f -print0 2>/dev/null | sort -z | xargs -0 cksum 2>/dev/null | awk '{print $1}' | cksum | awk '{print $1}')
        echo "$(date) - adb-sync: Attempt $attempts - CRC32: $current_crc" >> "$LOG_FILE"
        
        if [ -n "$prev_crc" ] && [ "$current_crc" = "$prev_crc" ]; then
            pull_success=true
            break
        fi
        prev_crc=$current_crc
        sleep $WAIT_BETWEEN_PULLS
    done
    
    if [ "$pull_success" = true ]; then
        # Clean staging areas first
        rm -rf "${HOST_STAGING_PATH:?}/output"
        adb shell "rm -rf ${DEVICE_STAGING_PATH}/output"
        
        # Move all pulled content to staging
        mkdir -p "${HOST_STAGING_PATH}/output"
        if [ -n "$(ls -A ${TEMP_DIR} 2>/dev/null || true)" ]; then
            cp -r "${TEMP_DIR}"/* "${HOST_STAGING_PATH}/output/"
            echo "$(date) - adb-sync: Copied files to staging" >> "$LOG_FILE"
        fi
        
        # Merge directories and files to final location
        mkdir -p "${HOST_FILES_PATH}/output"
        if [ -n "$(ls -A ${HOST_STAGING_PATH}/output/ 2>/dev/null || true)" ]; then
            cp -r "${HOST_STAGING_PATH}/output/"* "${HOST_FILES_PATH}/output/"
            echo "$(date) - adb-sync: Successfully merged files from device to host" >> "$LOG_FILE"
        fi
    else
        echo "$(date) - adb-sync: Failed to get stable state from device after $MAX_ATTEMPTS attempts" >> "$LOG_FILE"
    fi
    
    # Push everything back to device
    if [ -n "$(ls -A ${HOST_FILES_PATH}/output 2>/dev/null || true)" ]; then
        # Clean device staging area first
        adb shell "rm -rf ${DEVICE_STAGING_PATH}/output"
        # Push only the output directory contents
        adb push "${HOST_FILES_PATH}/output/" "${DEVICE_STAGING_PATH}/output/"
        echo "$(date) - adb-sync: Pushed merged state to device staged area" >> "$LOG_FILE"
        
        # Move files on device (maintaining directory structure)
        adb shell "mkdir -p ${DEVICE_FILES_PATH}/output && cp -r ${DEVICE_STAGING_PATH}/output/* ${DEVICE_FILES_PATH}/output/ 2>/dev/null || true"
        echo "$(date) - adb-sync: Moved files from staged area to final location on device" >> "$LOG_FILE"
    fi
    
    # Cleanup
    rm -rf "${TEMP_DIR:?}/"* "${HOST_STAGING_PATH}/output"
    adb shell "rm -rf ${DEVICE_STAGING_PATH}/output"
    echo "$(date) - adb-sync: Cleaned up temporary directories" >> "$LOG_FILE"
    echo "$(date) - adb-sync: Sync completed for ${HOSTNAME}" >> "$LOG_FILE"
    
    sleep 120
done
