#!/bin/bash
# PHP SAST Scanner - Start Script
# Runs on port 9006

SCANNER_DIR="/home/dev/offline-scanner/scanners/php"
LOG_FILE="$SCANNER_DIR/scanner.log"
PID_FILE="$SCANNER_DIR/scanner.pid"
PORT=9006

case "${1:-start}" in
    start)
        # Kill existing if running
        if [ -f "$PID_FILE" ]; then
            OLD_PID=$(cat "$PID_FILE")
            if kill -0 "$OLD_PID" 2>/dev/null; then
                echo "Stopping existing scanner (PID: $OLD_PID)"
                kill "$OLD_PID"
                sleep 1
            fi
            rm -f "$PID_FILE"
        fi

        # Also kill anything on the port
        EXISTING_PID=$(lsof -ti :$PORT 2>/dev/null)
        if [ -n "$EXISTING_PID" ]; then
            kill $EXISTING_PID 2>/dev/null
            sleep 1
        fi

        echo "Starting PHP SAST Scanner on port $PORT..."
        cd "$SCANNER_DIR"
        nohup php -S 0.0.0.0:$PORT scanner.php >> "$LOG_FILE" 2>&1 &
        echo $! > "$PID_FILE"
        sleep 1

        if kill -0 $(cat "$PID_FILE") 2>/dev/null; then
            echo "Scanner started (PID: $(cat $PID_FILE))"
            echo "Health: http://localhost:$PORT/health"
            echo "Scan:   POST http://localhost:$PORT/scan"
            echo "Log:    $LOG_FILE"
        else
            echo "Failed to start scanner. Check $LOG_FILE"
            exit 1
        fi
        ;;
    stop)
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            if kill -0 "$PID" 2>/dev/null; then
                echo "Stopping scanner (PID: $PID)"
                kill "$PID"
                rm -f "$PID_FILE"
                echo "Stopped."
            else
                echo "Scanner not running (stale PID file)"
                rm -f "$PID_FILE"
            fi
        else
            echo "No PID file found. Checking port..."
            PID=$(lsof -ti :$PORT 2>/dev/null)
            if [ -n "$PID" ]; then
                echo "Killing process on port $PORT (PID: $PID)"
                kill $PID
            else
                echo "Scanner not running."
            fi
        fi
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
    status)
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            if kill -0 "$PID" 2>/dev/null; then
                echo "Scanner is running (PID: $PID)"
                curl -s http://localhost:$PORT/health | python3 -m json.tool
            else
                echo "Scanner is NOT running (stale PID file)"
            fi
        else
            echo "No PID file. Scanner may not be running."
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
