#!/bin/bash

# Variables
SIM_DIR=$(pwd);
BINARIES_DIR=$SIM_DIR/bin;
RESULT_DIR=$SIM_DIR/results
TRACES_DIR="/home/obs/Datasets/dpc3/ChampSimTraces/spec";
TRACE="400.perlbench-41B.champsimtrace.xz";
CONFIG_DIR="sys_config"
N_WARM=10000000     # Warmup instructions (default: 50M if not provided)
N_SIM=10000000      # Simulation instructions (default: 50M if not provided)

tput setaf 6;
echo "*** *************************** ***";
echo "*** Starting to build binaries ***";
tput sgr0;
#Build Binaries
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
                    tput setaf 2;
                    echo "${red}[ERROR] Build failed for $(basename $file)";
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
# Run Simulations
mkdir -p $RESULT_DIR
cd $BINARIES_DIR;
for item in *; do
    if [ -d "$item" ]; then
        tput setaf 5;
        echo "*** Running simulations for: $(basename $item) ***"
        tput sgr0;
        mkdir -p $RESULT_DIR/$item 
        for file in "$item"/*; do
            if [ -f "$file" ]; then
                tput setaf 3;
                echo "[RUN] $(basename $file)"
                # echo "$RESULT_DIR/$file.json";
                tput sgr0;
                if ($file --warmup_instructions $N_WARM --simulation_instructions $N_SIM $TRACES_DIR/$TRACE --json "$RESULT_DIR/$file.json"); then
                    tput setaf 2;
                    echo "[SUCCESS] Simulation completed for $(basename $file)";
                    tput sgr0;
                else
                    tput setaf 2;
                    echo "${red}[ERROR] Simulation failed for $(basename $file)";
                    tput sgr0;
                fi
            fi
        done
    fi
done;