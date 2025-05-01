#!/bin/bash

# Variables
SIM_DIR=$(pwd);
BINARIES_DIR=$SIM_DIR/bin;
RESULT_DIR=$SIM_DIR/results
TRACES_DIR=$SIM_DIR/traces/;
CONFIG_DIR=$SIM_DIR/sys_config;
INTERMEDIATE_LOG_DIR=$SIM_DIR/intermediate_logs;
PYTHON_SCRIPTS=$SIM_DIR/python_scripts;
MAX_PARALLEL_JOBS=17;
N_WARM=50000000;     # Warmup instructions (default: 50M if not provided)
N_SIM=200000000;      # Simulation instructions (default: 50M if not provided)

process_file() {
    local bin_file="$1"
    local trace_file="$2"
    local bin_name=$(basename "$bin_file")
    local trace_name=$(basename "$trace_file")
    tput setaf 3;
    echo "[RUNNING] Simulation for $bin_name with trace $trace_name";
    tput sgr0;
    if ($bin_file --warmup-instructions $N_WARM --simulation-instructions $N_SIM "$trace_file" --json "$RESULT_DIR/$bin_name-$trace_name.json" > "$INTERMEDIATE_LOG_DIR/$bin_name-$trace_name.txt"); then
        tput setaf 2;
        echo "[SUCCESS] Simulation completed for $bin_name with trace $trace_name";
        tput sgr0;
    else
        tput setaf 1;
        echo "[ERROR] Simulation failed for $bin_name with trace $trace_name";
        tput sgr0;
    fi
}

semaphore() {
    local num_jobs
    while true; do
        num_jobs=$(jobs -rp | wc -l)
        if [[ "$num_jobs" -lt "$MAX_PARALLEL_JOBS" ]]; then
            break
        fi
        sleep 0.1
    done
}

rm -rf $RESULT_DIR;
mkdir -p $RESULT_DIR;

rm -rf $INTERMEDIATE_LOG_DIR;
mkdir -p $INTERMEDIATE_LOG_DIR;

tput setaf 6;
echo "*** *************************** ***";
echo "*** Starting to build binaries ***";
tput sgr0;
# Build Binaries
cd $CONFIG_DIR;
for item in *; do
    if [ -d "$item" ]; then
        tput setaf 5;
        echo "*** Building binaries for: $(basename $item) ***"
        tput sgr0;
        for file in "$item"/*; do
            if [ -f "$file" ]; then
                tput setaf 3;
                echo "[BUILD] $(basename $file)"
                tput sgr0;
                if (cd $SIM_DIR && ./config.sh $CONFIG_DIR/$file --bindir bin/$(dirname $file) && make -s); then
                    tput setaf 2;
                    echo "[SUCCESS] Built $(basename $file)";
                    tput sgr0;
                else
                    tput setaf 1;
                    echo "[ERROR] Build failed for $(basename $file)";
                    tput sgr0;
                fi
            fi
        done
    fi
done;
tput setaf 6;
echo "*** Completed building binaries ***";
echo "*** *************************** ***";
echo "*** Starting simulations ***";
tput sgr0;

# Run simulations for SPEC and GAP traces
cd $BINARIES_DIR;

for bin_dir in *; do
    if [ -d "$bin_dir" ]; then
        tput setaf 5;
        echo "*** Running simulations for binaries in: $(basename $bin_dir) ***"
        tput sgr0;
        
        # Iterate through all binary files
        for bin_file in "$bin_dir"/*; do
            if [ -f "$bin_file" ]; then
                tput setaf 3;
                echo "[SIMULATE] $(basename $bin_file)"
                tput sgr0;
                
                # Iterate through all trace files in spec and gap directories
                for trace_dir in "$TRACES_DIR/spec" "$TRACES_DIR/gap"; do
                    if [ -d "$trace_dir" ]; then
                        for trace_file in $trace_dir/*; do
                            if [ -f "$trace_file" ]; then
                                # Ensure semaphore is checked before starting each simulation
                                semaphore
                                process_file "$bin_file" "$trace_file" &
                            fi
                        done
                    fi
                done
            fi
        done
    fi
done;

wait

tput setaf 6;
echo "*** *************************** ***";
echo "*** Simulations completed ***";
tput sgr0;

echo "*** *************************** ***";
echo "*** Extracting statistics ***";

# python $PYTHON_SCRIPTS/extract_data.py > $INTERMEDIATE_LOG_DIR/extract_data.txt;

echo "*** *************************** ***";
echo "*** Completed extracting statistics ***";
tput sgr0;
