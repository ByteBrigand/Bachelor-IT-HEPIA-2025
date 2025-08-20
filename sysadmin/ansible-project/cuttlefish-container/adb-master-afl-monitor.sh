#!/bin/bash
set -o pipefail
set -u

LOG_FILE="/var/log/afl-monitor.log"
touch "$LOG_FILE" || {
    echo "Failed to create log file at $LOG_FILE, using stderr instead"
    LOG_FILE="/dev/stderr"
}


log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp - afl-monitor: $1" >> "$LOG_FILE"
    echo "$timestamp - afl-monitor: $1"  # Also print to stdout for debugging
}


kill_and_replace() {
    local pid=$1
    local new_mode=$2
    local reason=$3
    local success=1

    log "Attempting to kill and replace PID $pid as $new_mode ($reason)"

    # Get the command line of the process to replace
    local old_cmdline=$(echo "${processes[$pid]}" | cut -d: -f3-)
    if [ -z "$old_cmdline" ]; then
        log "ERROR: Could not get command line for PID $pid"
        return 1
    fi

    log "Original command line: $old_cmdline"

    # Replace the mode flag
    local new_cmdline=$(echo "$old_cmdline" | sed "s/-[MS]/-$new_mode/")
    if [ -z "$new_cmdline" ]; then
        log "ERROR: Could not generate new command line for PID $pid"
        return 1
    fi

    # Remove any existing path to afl-fuzz at the beginning
    new_cmdline=$(echo "$new_cmdline" | sed 's|^[^ ]*/afl-fuzz||' | sed 's|^afl-fuzz||')

    # Trim whitespace from the command line
    new_cmdline=$(echo "$new_cmdline" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

    # Always prepend the full path to afl-fuzz
    new_cmdline="/data/local/tmp/afl-android/bin/afl-fuzz $new_cmdline"
    new_cmdline=$(echo "$new_cmdline" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/  */ /g')

    log "New command line: $new_cmdline"

    # Kill the process
    if adb shell "kill $pid" 2>/dev/null; then
        log "$reason Killed process $pid"
        # Give the system a moment to clean up
        sleep 2

        # Start new process with updated mode
        if adb shell "$new_cmdline > /dev/null 2>&1 &"; then
            log "Started new $new_mode process (replaced PID $pid)"
            success=0
        else
            log "ERROR: Failed to start new $new_mode process (replacing PID $pid)"
            return 1
        fi
    else
        log "ERROR: Failed to kill process $pid"
        return 1
    fi

    return $success
}

while true; do
    log "Starting new monitoring cycle"

    # Check if device is connected
    if ! adb get-state >/dev/null 2>&1; then
        log "Device not connected"
        sleep 30
        continue
    fi

    log "Device connected successfully"

    # Get hostname
    HOSTNAME=$(cat /info/hostname 2>/dev/null)
    if [ -z "$HOSTNAME" ]; then
        log "Could not get hostname from device"
        sleep 30
        continue
    fi

    log "Hostname: $HOSTNAME"

    # Check if hostname exists in /shared/master
    MASTER_CONTENT=$(cat /shared/master 2>/dev/null || true)
    IS_MASTER_HOST="no"
    if echo "$MASTER_CONTENT" | grep -q "^$HOSTNAME,"; then
        IS_MASTER_HOST="yes"
    fi

    log "Master host status: $IS_MASTER_HOST"

    # Get all AFL processes
    AFL_PROCESSES=$(adb shell "ps -ef | grep '[a]fl-fuzz'" 2>/dev/null)
    if [ -z "$AFL_PROCESSES" ]; then
        log "No AFL processes running"
        sleep 120
        continue
    fi

    log "Found AFL processes:"
    echo "$AFL_PROCESSES" | while read -r line; do
        log "  $line"
    done

    # Parse AFL processes
    declare -A processes
    declare -a pids
    declare -a master_pids
    declare -a slave_pids

    # Reset arrays
    pids=()
    master_pids=()
    slave_pids=()

    while IFS= read -r line; do
        PID=$(echo "$line" | awk '{print $2}')
        CMDLINE=$(echo "$line" | awk '{for(i=8;i<=NF;i++) printf "%s ", $i}')
        MODE=$(echo "$CMDLINE" | grep -o -- "-M\|-S" | tr -d '-' | head -1)

        # Extract instance ID from pattern (hostname_ID or just ID)
        INSTANCE_ID=$(echo "$CMDLINE" | grep -o -E "[a-zA-Z0-9_-]+_[0-9]+" | head -1 | grep -o -E "[0-9]+$")
        if [ -z "$INSTANCE_ID" ]; then
            INSTANCE_ID=0
        fi

        processes["$PID"]="$MODE:$INSTANCE_ID:$CMDLINE"
        pids+=("$PID")

        if [ "$MODE" = "M" ]; then
            master_pids+=("$PID")
        else
            slave_pids+=("$PID")
        fi

        log "Parsed process: PID=$PID, Mode=$MODE, InstanceID=$INSTANCE_ID"
    done <<< "$AFL_PROCESSES"

    log "Current process state:"
    log "  Master PIDs: ${master_pids[*]}"
    log "  Slave PIDs: ${slave_pids[*]}"

    if [ "$IS_MASTER_HOST" = "yes" ]; then
        log "Host is configured as master - checking master process"

        # Case 1: No master process at all - we need to create one
        if [ ${#master_pids[@]} -eq 0 ]; then
            log "Master host missing master process - will create one"

            # Try to find a slave with instance ID 0 to convert
            TARGET_PID=""
            for pid in "${slave_pids[@]}"; do
                ID=$(echo "${processes[$pid]}" | cut -d: -f2)
                if [ "$ID" = "0" ]; then
                    TARGET_PID="$pid"
                    break
                fi
            done

            # If no slave with ID 0, pick the slave with the lowest PID
            if [ -z "$TARGET_PID" ] && [ ${#slave_pids[@]} -gt 0 ]; then
                # Sort slave PIDs numerically and take the first one
                IFS=$'\n' sorted_slaves=($(sort -n <<<"${slave_pids[*]}"))
                unset IFS
                TARGET_PID="${sorted_slaves[0]}"
                log "No slave with ID=0 found, will use PID $TARGET_PID"
            fi

            # If we found a target slave to convert
            if [ -n "$TARGET_PID" ]; then
                log "Converting slave PID $TARGET_PID to master"
                if ! kill_and_replace "$TARGET_PID" "M" "Converting slave to master"; then
                    log "Failed to convert slave to master"
                fi
            else
                log "No suitable slave process found to convert to master"
            fi

        # Case 2: Multiple master processes - keep one (preferably ID=0) and kill others
        elif [ ${#master_pids[@]} -gt 1 ]; then
            log "Found ${#master_pids[@]} master processes (should be only 1) - fixing..."

            # Find which master process to keep (preferably ID=0)
            KEEP_PID=""
            for pid in "${master_pids[@]}"; do
                ID=$(echo "${processes[$pid]}" | cut -d: -f2)
                if [ "$ID" = "0" ]; then
                    KEEP_PID="$pid"
                    break
                fi
            done

            # If no master with ID=0, just keep the first one we found
            if [ -z "$KEEP_PID" ]; then
                KEEP_PID="${master_pids[0]}"
                log "No master with ID=0 found, keeping PID $KEEP_PID"
            else
                log "Keeping master process with ID=0: PID $KEEP_PID"
            fi

            # Kill all other master processes (convert them to slaves)
            for pid in "${master_pids[@]}"; do
                if [ "$pid" != "$KEEP_PID" ]; then
                    log "Converting extra master PID $pid to slave"
                    if ! kill_and_replace "$pid" "S" "Converting extra master to slave"; then
                        log "Failed to convert extra master (PID $pid) to slave"
                    fi
                fi
            done

        # Case 3: One master process, but it's not ID=0 - we might want to fix this
        elif [ ${#master_pids[@]} -eq 1 ]; then
            MASTER_PID="${master_pids[0]}"
            MASTER_ID=$(echo "${processes[$MASTER_PID]}" | cut -d: -f2)

            if [ "$MASTER_ID" != "0" ]; then
                log "Master process has ID $MASTER_ID (should be 0) - attempting to fix"

                # Check if there's a slave with ID=0 that we can convert to master
                TARGET_PID=""
                for pid in "${slave_pids[@]}"; do
                    ID=$(echo "${processes[$pid]}" | cut -d: -f2)
                    if [ "$ID" = "0" ]; then
                        TARGET_PID="$pid"
                        break
                    fi
                done

                if [ -n "$TARGET_PID" ]; then
                    log "Found slave with ID=0 (PID $TARGET_PID) to convert to master"
                    # We found a slave with ID=0 - convert it to master and kill the old master
                    if ! kill_and_replace "$MASTER_PID" "S" "Converting misconfigured master to slave"; then
                        log "Failed to convert misconfigured master (PID $MASTER_PID) to slave"
                    fi
                    if ! kill_and_replace "$TARGET_PID" "M" "Converting slave to proper master (ID=0)"; then
                        log "Failed to convert slave (PID $TARGET_PID) to proper master"
                    fi
                else
                    log "No slave with ID=0 found to convert to proper master"
                fi
            else
                log "Master process already has correct ID=0"
            fi
        else
            log "Master process count is correct (${#master_pids[@]}), no action needed"
        fi

    else
        log "Host is configured as slave - checking for master processes"

        # We should be a slave host - ensure no master processes are running
        if [ ${#master_pids[@]} -gt 0 ]; then
            log "Found ${#master_pids[@]} master process(es) on slave host - converting to slaves"

            # Kill all master processes and replace with slaves
            for pid in "${master_pids[@]}"; do
                log "Converting master PID $pid to slave"
                if ! kill_and_replace "$pid" "S" "Converting master to slave on slave host"; then
                    log "Failed to convert master (PID $pid) to slave"
                fi
            done
        else
            log "No master processes found on slave host - correct state"
        fi
    fi

    log "Monitoring cycle complete. Sleeping for 120 seconds..."
    sleep 120
done
