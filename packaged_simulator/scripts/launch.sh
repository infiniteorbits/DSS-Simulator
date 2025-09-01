#!/bin/bash

set -euo pipefail

TC_PID=""
TM_PID=""
SIM_PID=""
SYSTEM_RUNNING=false

SIM_BIN="/app/renode/renode"
CONFIG_FILE="/app/src/renode-config/Rescfile.resc"
INTERFACE="vcan1"

setup_network() {
    modprobe vcan >/dev/null 2>&1 || true
    ip link add dev vcan0 type vcan >/dev/null 2>&1 || true
    ip link set up vcan0 >/dev/null 2>&1 || true
    ip link add dev vcan1 type vcan >/dev/null 2>&1 || true
    ip link set up vcan1 >/dev/null 2>&1 || true
}

run_service1() {
    (
        cd /app/src
        while true; do
            if [ -f "tc_converter.py" ]; then
                python3 tc_converter.py --iface "${INTERFACE}" --console >/dev/null 2>&1 || true
            fi
            sleep 5
        done
    ) &
    TC_PID=$!
}

run_service2() {
    "$SIM_BIN" --disable-xwt -e "i @$CONFIG_FILE; start" >/dev/null 2>&1 &
    SIM_PID=$!
}

run_service3() {
    (
        cd /app/src
        while true; do
            if [ -f "tm_converter.py" ]; then
                python3 tm_converter.py --iface "${INTERFACE}" --console >/dev/null 2>&1 || true
            fi
            sleep 5
        done
    ) &
    TM_PID=$!
}

start_services() {
    if [ "$SYSTEM_RUNNING" = false ]; then
        setup_network
        
        run_service1 &
        run_service2 &
        run_service3 &
        
        SYSTEM_RUNNING=true
        echo "System started" >/proc/1/fd/1 2>&1
    fi
}

stop_services() {
    if [ "$SYSTEM_RUNNING" = true ]; then
        [ -n "$TC_PID" ] && kill $TC_PID >/dev/null 2>&1 || true &
        [ -n "$TM_PID" ] && kill $TM_PID >/dev/null 2>&1 || true &
        [ -n "$SIM_PID" ] && kill $SIM_PID >/dev/null 2>&1 || true &
        
        pkill -f "tc_converter.py" >/dev/null 2>&1 || true &
        pkill -f "tm_converter.py" >/dev/null 2>&1 || true &
        pkill -f "Renode" >/dev/null 2>&1 || true &
        
        wait
        
        SYSTEM_RUNNING=false
        echo "System stopped" >/proc/1/fd/1 2>&1
    fi
}

cleanup() {
    stop_services
    exit 0
}

trap cleanup SIGINT SIGTERM

show_menu() {
    clear
    echo "Application Control"
    echo "=================="
    echo ""
    
    if [ "$SYSTEM_RUNNING" = true ]; then
        echo "Status: Running"
    else
        echo "Status: Stopped"
    fi
    
    echo ""
    echo "1) Start System"
    echo "2) Stop System"  
    echo "3) Exit"
    echo ""
    read -rp "Choice: " choice
}

main() {
    start_services
    
    while true; do
        show_menu
        case "${choice}" in
            1) 
                start_services
                echo "System starting..."
                sleep 1
                ;;
            2) 
                stop_services
                echo "System stopping..."
                sleep 1
                ;;
            3) 
                cleanup
                ;;
            *) 
                echo "Invalid choice"
                sleep 1
                ;;
        esac
        
        if [ "$SYSTEM_RUNNING" = true ]; then
            local restart_needed=false
            
            [ -n "$TC_PID" ] && ! kill -0 $TC_PID 2>/dev/null && restart_needed=true
            [ -n "$TM_PID" ] && ! kill -0 $TM_PID 2>/dev/null && restart_needed=true
            [ -n "$SIM_PID" ] && ! kill -0 $SIM_PID 2>/dev/null && restart_needed=true
            
            if [ "$restart_needed" = true ]; then
                echo "Service died, restarting..." >/proc/1/fd/1 2>&1
                stop_services
                start_services
            fi
        fi
    done
}

main
