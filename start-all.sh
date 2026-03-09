#!/bin/bash
# Master startup script for all SAST scanners
# Usage: ./start-all.sh [start|stop|status|restart]

SCANNER_DIR="/home/dev/offline-scanner/scanners"
PID_DIR="/home/dev/offline-scanner/pids"
LOG_DIR="/home/dev/offline-scanner/logs"
mkdir -p "$PID_DIR" "$LOG_DIR"

declare -A SCANNERS
SCANNERS=(
    ["python"]="9001:python3 scanner.py"
    ["javascript"]="9002:node scanner.js"
    ["csharp"]="9003:dotnet publish/CSharpScanner.dll --urls=http://0.0.0.0:9003"
    ["java"]="9004:java -jar target/java-sast-scanner-1.0.0.jar"
    ["go"]="9005:./gosastscanner"
    ["php"]="9006:php -S 0.0.0.0:9006 scanner.php"
    ["ruby"]="9007:ruby scanner.rb"
    ["cpp"]="9008:python3 scanner.py"
    ["rust"]="9009:python3 scanner.py"
    ["swift"]="9010:python3 scanner.py"
    ["objc"]="9011:python3 scanner.py"
    ["kotlin"]="9012:python3 scanner.py"
    ["dart"]="9013:python3 scanner.py"
    ["scala"]="9014:python3 scanner.py"
    ["fsharp"]="9015:python3 scanner.py"
    ["vb"]="9016:python3 scanner.py"
    ["perl"]="9017:python3 scanner.py"
    ["plsql"]="9018:python3 scanner.py"
    ["iac"]="9019:python3 scanner.py"
    ["oracle-forms"]="9020:python3 scanner.py"
    ["ai-llm"]="9021:python3 scanner.py"
)

start_scanner() {
    local name=$1
    local info=${SCANNERS[$name]}
    local port=${info%%:*}
    local cmd=${info#*:}
    local pid_file="$PID_DIR/$name.pid"
    local log_file="$LOG_DIR/$name.log"
    
    # Check if already running
    if [ -f "$pid_file" ] && kill -0 $(cat "$pid_file") 2>/dev/null; then
        echo "  $name (port $port): already running (PID $(cat $pid_file))"
        return
    fi
    
    cd "$SCANNER_DIR/$name"
    nohup $cmd > "$log_file" 2>&1 &
    local pid=$!
    echo $pid > "$pid_file"
    echo "  $name (port $port): started (PID $pid)"
}

stop_scanner() {
    local name=$1
    local info=${SCANNERS[$name]}
    local port=${info%%:*}
    local pid_file="$PID_DIR/$name.pid"
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if kill -0 $pid 2>/dev/null; then
            kill $pid
            echo "  $name (port $port): stopped (PID $pid)"
        else
            echo "  $name (port $port): not running (stale PID)"
        fi
        rm -f "$pid_file"
    else
        # Try to kill by port
        local pid=$(lsof -ti tcp:$port 2>/dev/null)
        if [ -n "$pid" ]; then
            kill $pid
            echo "  $name (port $port): stopped (PID $pid)"
        else
            echo "  $name (port $port): not running"
        fi
    fi
}

check_scanner() {
    local name=$1
    local info=${SCANNERS[$name]}
    local port=${info%%:*}
    
    local status=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:$port/health 2>/dev/null)
    if [ "$status" = "200" ]; then
        echo "  $name (port $port): ONLINE ✓"
    else
        echo "  $name (port $port): OFFLINE ✗"
    fi
}

case "${1:-status}" in
    start)
        echo "Starting all SAST scanners..."
        # Start gateway first
        cd /home/dev/offline-scanner/gateway
        nohup python3 main.py > "$LOG_DIR/gateway.log" 2>&1 &
        echo $! > "$PID_DIR/gateway.pid"
        echo "  gateway (port 9000): started"
        
        for name in "${!SCANNERS[@]}"; do
            start_scanner "$name"
        done
        
        echo ""
        echo "Waiting 5 seconds for services to start..."
        sleep 5
        echo ""
        echo "=== Status ==="
        echo "Gateway (9000):"
        check_scanner_port 9000
        for name in "${!SCANNERS[@]}"; do
            check_scanner "$name"
        done
        ;;
    stop)
        echo "Stopping all SAST scanners..."
        for name in "${!SCANNERS[@]}"; do
            stop_scanner "$name"
        done
        # Stop gateway
        if [ -f "$PID_DIR/gateway.pid" ]; then
            kill $(cat "$PID_DIR/gateway.pid") 2>/dev/null
            rm -f "$PID_DIR/gateway.pid"
        fi
        echo "  gateway: stopped"
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        echo "=== SAST Scanner Status ==="
        echo -n "Gateway (9000): "
        curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:9000/health 2>/dev/null | grep -q 200 && echo "ONLINE ✓" || echo "OFFLINE ✗"
        for name in $(echo "${!SCANNERS[@]}" | tr ' ' '\n' | sort); do
            check_scanner "$name"
        done
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
