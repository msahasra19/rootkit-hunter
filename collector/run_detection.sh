#!/bin/bash

# Rootkit Detection Runner Script
# This script orchestrates the complete rootkit detection process

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
SNAPSHOT_DIR="$PROJECT_ROOT/snapshots"
BASELINE_DIR="$PROJECT_ROOT/baselines"
ALERT_DIR="$PROJECT_ROOT/alerts"

# Create directories if they don't exist
mkdir -p "$LOG_DIR" "$SNAPSHOT_DIR" "$BASELINE_DIR" "$ALERT_DIR"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/detection.log"
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Check if baseline exists
check_baseline() {
    local baseline_name="$1"
    if [ -z "$baseline_name" ]; then
        # Find the most recent baseline
        baseline_name=$(ls -t "$BASELINE_DIR"/*.json 2>/dev/null | head -n1 | xargs basename -s .json)
    fi
    
    if [ -z "$baseline_name" ] || [ ! -f "$BASELINE_DIR/$baseline_name.json" ]; then
        error_exit "No baseline found. Please create a baseline first with: python create_baseline.py"
    fi
    
    echo "$baseline_name"
}

# Create system snapshot
create_snapshot() {
    log "Creating system snapshot..."
    cd "$SCRIPT_DIR"
    
    python3 snapshot.py || error_exit "Failed to create snapshot"
    
    # Get the latest snapshot file
    local snapshot_file=$(ls -t "$SNAPSHOT_DIR"/*.json 2>/dev/null | head -n1)
    if [ -z "$snapshot_file" ]; then
        error_exit "Failed to find created snapshot"
    fi
    
    log "Snapshot created: $snapshot_file"
    echo "$snapshot_file"
}

# Run rule-based detection
run_rules_detection() {
    local snapshot_file="$1"
    log "Running rule-based detection..."
    
    cd "$SCRIPT_DIR"
    python3 rules.py --snapshot "$snapshot_file" > "$ALERT_DIR/rules_detection_$(date +%Y%m%d_%H%M%S).json" 2>&1 || {
        log "Warning: Rule-based detection encountered issues"
    }
    
    log "Rule-based detection completed"
}

# Run baseline comparison
run_baseline_comparison() {
    local baseline_name="$1"
    log "Running baseline comparison with: $baseline_name"
    
    cd "$SCRIPT_DIR"
    python3 create_baseline.py compare --baseline "$baseline_name" > "$ALERT_DIR/baseline_comparison_$(date +%Y%m%d_%H%M%S).json" 2>&1 || {
        log "Warning: Baseline comparison encountered issues"
    }
    
    log "Baseline comparison completed"
}

# Run ML-based detection
run_ml_detection() {
    local snapshot_file="$1"
    log "Running ML-based detection..."
    
    cd "$PROJECT_ROOT/ml"
    python3 score.py --snapshot "$snapshot_file" > "$ALERT_DIR/ml_detection_$(date +%Y%m%d_%H%M%S).json" 2>&1 || {
        log "Warning: ML-based detection encountered issues"
    }
    
    log "ML-based detection completed"
}

# Forward alerts
forward_alerts() {
    log "Forwarding alerts..."
    
    cd "$SCRIPT_DIR"
    python3 forwarder.py --alert-file "$ALERT_DIR" || {
        log "Warning: Alert forwarding encountered issues"
    }
    
    log "Alert forwarding completed"
}

# Generate summary report
generate_report() {
    local start_time="$1"
    local end_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    log "Generating detection summary..."
    
    cat > "$ALERT_DIR/detection_summary_$(date +%Y%m%d_%H%M%S).txt" << EOF
Rootkit Detection Summary
========================

Detection Time: $start_time to $end_time
Baseline Used: ${BASELINE_NAME:-"auto-selected"}

Detection Methods:
- System Snapshot: ✓
- Rule-based Detection: ✓
- Baseline Comparison: ✓
- ML-based Detection: ✓
- Alert Forwarding: ✓

Log Files:
- Detection Log: $LOG_DIR/detection.log
- Alert Files: $ALERT_DIR/

Next Steps:
1. Review alert files for any suspicious activities
2. Investigate high-severity alerts immediately
3. Update baseline if system state is confirmed clean
4. Consider tuning detection rules based on results

EOF

    log "Summary report generated"
}

# Cleanup old files (optional)
cleanup_old_files() {
    local days_to_keep="${CLEANUP_DAYS:-7}"
    
    log "Cleaning up files older than $days_to_keep days..."
    
    find "$SNAPSHOT_DIR" -name "*.json" -mtime +$days_to_keep -delete 2>/dev/null || true
    find "$LOG_DIR" -name "*.log" -mtime +$days_to_keep -delete 2>/dev/null || true
    
    log "Cleanup completed"
}

# Main detection function
main() {
    local start_time=$(date '+%Y-%m-%d %H:%M:%S')
    local baseline_name=""
    local snapshot_file=""
    
    log "Starting rootkit detection process..."
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --baseline)
                baseline_name="$2"
                shift 2
                ;;
            --cleanup-days)
                CLEANUP_DAYS="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [--baseline BASELINE_NAME] [--cleanup-days DAYS]"
                echo ""
                echo "Options:"
                echo "  --baseline BASELINE_NAME    Use specific baseline for comparison"
                echo "  --cleanup-days DAYS         Clean up files older than DAYS (default: 7)"
                echo "  --help                     Show this help message"
                exit 0
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
    
    # Check baseline
    BASELINE_NAME=$(check_baseline "$baseline_name")
    log "Using baseline: $BASELINE_NAME"
    
    # Create snapshot
    snapshot_file=$(create_snapshot)
    
    # Run detection methods in parallel where possible
    log "Running detection methods..."
    
    # Run rule-based detection
    run_rules_detection "$snapshot_file" &
    RULES_PID=$!
    
    # Run baseline comparison
    run_baseline_comparison "$BASELINE_NAME" &
    BASELINE_PID=$!
    
    # Run ML-based detection
    run_ml_detection "$snapshot_file" &
    ML_PID=$!
    
    # Wait for all detection methods to complete
    wait $RULES_PID
    wait $BASELINE_PID
    wait $ML_PID
    
    # Forward alerts
    forward_alerts
    
    # Generate summary
    generate_report "$start_time"
    
    # Cleanup (optional)
    if [ "${CLEANUP_DAYS:-}" ]; then
        cleanup_old_files
    fi
    
    log "Rootkit detection process completed successfully"
}

# Run main function
main "$@"
