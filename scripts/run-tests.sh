#!/bin/bash
#
# Prancer Compliance Test - Comprehensive Test Runner
#
# Usage:
#   ./scripts/run-tests.sh [OPTIONS]
#
# Options:
#   --all           Run all tests
#   --azure         Run Azure tests only
#   --aws           Run AWS tests only
#   --gcp           Run GCP tests only
#   --baseline      Run baseline tests (before fixes)
#   --compare FILE  Compare against baseline file
#   --verbose       Show detailed output
#   --help          Show this help message

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TESTS_DIR="$PROJECT_ROOT/tests"
LIB_DIR="$PROJECT_ROOT/lib"
REPORTS_DIR="$PROJECT_ROOT/reports"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Create reports directory
mkdir -p "$REPORTS_DIR"

# Timestamp for report
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="$REPORTS_DIR/test-report-$TIMESTAMP.json"

usage() {
    head -20 "$0" | tail -18 | sed 's/^# //'
    exit 0
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
}

# Check if OPA is installed
check_opa() {
    if ! command -v opa &> /dev/null; then
        echo -e "${RED}ERROR: OPA is not installed${NC}"
        echo "Install OPA from: https://www.openpolicyagent.org/docs/latest/#running-opa"
        echo ""
        echo "Quick install (Linux):"
        echo "  curl -L -o opa https://openpolicyagent.org/downloads/v0.60.0/opa_linux_amd64_static"
        echo "  chmod 755 ./opa"
        echo "  sudo mv opa /usr/local/bin/"
        exit 1
    fi
    log_info "OPA version: $(opa version | head -1)"
}

# Run a single test
run_test() {
    local rego_file="$1"
    local input_file="$2"
    local rule="$3"
    local expected="$4"
    local use_lib="$5"

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    local data_args=""
    if [ "$use_lib" = "true" ]; then
        data_args="--data $LIB_DIR"
    fi

    local result
    result=$(opa eval \
        --input "$input_file" \
        $data_args \
        --data "$rego_file" \
        --format raw \
        "data.rule.$rule" 2>/dev/null || echo "error")

    # Clean up result
    result=$(echo "$result" | tr -d '[:space:]')

    local test_name="${rego_file##*/}:$rule with ${input_file##*/}"

    if [ "$result" = "$expected" ]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        if [ "$VERBOSE" = "true" ]; then
            log_success "$test_name = $result"
        fi
        echo "pass"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        log_fail "$test_name: got '$result', expected '$expected'"
        echo "fail"
    fi
}

# Test Azure NSG rules
test_azure_nsg() {
    log_info "Testing Azure NSG rules..."

    local rego="$PROJECT_ROOT/azure/cloud/nsg.rego"
    local test_dir="$TESTS_DIR/azure/nsg"
    local use_lib="${1:-false}"

    # Test nsg_in_tcp_all_src rule
    run_test "$rego" "$test_dir/input_compliant.json" "nsg_in_tcp_all_src" "true" "$use_lib"
    run_test "$rego" "$test_dir/input_non_compliant.json" "nsg_in_tcp_all_src" "false" "$use_lib"
    run_test "$rego" "$test_dir/input_no_resource.json" "nsg_in_tcp_all_src" "null" "$use_lib"
    run_test "$rego" "$test_dir/input_empty.json" "nsg_in_tcp_all_src" "null" "$use_lib"
}

# Test AWS Security Group rules
test_aws_sg() {
    log_info "Testing AWS Security Group rules..."

    local rego="$PROJECT_ROOT/aws/cloud/securitygroup.rego"
    local test_dir="$TESTS_DIR/aws/securitygroup"
    local use_lib="${1:-false}"

    # Test port_22 (SSH) rule
    run_test "$rego" "$test_dir/input_compliant.json" "port_22" "true" "$use_lib"
    run_test "$rego" "$test_dir/input_non_compliant.json" "port_22" "false" "$use_lib"

    # These tests show the FALSE POSITIVE problem
    # When no SecurityGroups exist, the rule returns TRUE (default) instead of null
    run_test "$rego" "$test_dir/input_no_resource.json" "port_22" "true" "$use_lib"
    run_test "$rego" "$test_dir/input_empty.json" "port_22" "true" "$use_lib"

    # Test port_3389 (RDP) rule
    run_test "$rego" "$test_dir/input_compliant.json" "port_3389" "true" "$use_lib"
    run_test "$rego" "$test_dir/input_non_compliant.json" "port_3389" "false" "$use_lib"
}

# Test GCP Firewall rules
test_gcp_firewall() {
    log_info "Testing GCP Firewall rules..."

    local rego="$PROJECT_ROOT/google/cloud/compute.rego"
    local test_dir="$TESTS_DIR/google/compute"
    local use_lib="${1:-false}"

    # Test firewall_port_22 rule
    run_test "$rego" "$test_dir/input_compliant.json" "firewall_port_22" "true" "$use_lib"
    run_test "$rego" "$test_dir/input_non_compliant.json" "firewall_port_22" "false" "$use_lib"
    run_test "$rego" "$test_dir/input_no_resource.json" "firewall_port_22" "null" "$use_lib"
    run_test "$rego" "$test_dir/input_empty.json" "firewall_port_22" "null" "$use_lib"

    # Test firewall_port_21 (FTP) rule
    run_test "$rego" "$test_dir/input_compliant.json" "firewall_port_21" "true" "$use_lib"
    run_test "$rego" "$test_dir/input_non_compliant.json" "firewall_port_21" "false" "$use_lib"
}

# Generate JSON report
generate_report() {
    local report_type="${1:-full}"

    cat > "$REPORT_FILE" << EOF
{
    "report_type": "$report_type",
    "timestamp": "$(date -Iseconds)",
    "summary": {
        "total_tests": $TOTAL_TESTS,
        "passed": $PASSED_TESTS,
        "failed": $FAILED_TESTS,
        "skipped": $SKIPPED_TESTS,
        "pass_rate": $(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc)
    },
    "opa_version": "$(opa version 2>/dev/null | head -1 || echo 'not installed')"
}
EOF

    log_info "Report saved to: $REPORT_FILE"
}

# Print summary
print_summary() {
    echo ""
    echo "=========================================="
    echo "           TEST SUMMARY"
    echo "=========================================="
    echo -e "Total Tests:  $TOTAL_TESTS"
    echo -e "Passed:       ${GREEN}$PASSED_TESTS${NC}"
    echo -e "Failed:       ${RED}$FAILED_TESTS${NC}"
    echo -e "Skipped:      ${YELLOW}$SKIPPED_TESTS${NC}"
    echo ""

    if [ $FAILED_TESTS -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        echo "Review the output above for details."
    else
        echo -e "${GREEN}All tests passed!${NC}"
    fi
    echo "=========================================="
}

# Main execution
main() {
    local RUN_AZURE=false
    local RUN_AWS=false
    local RUN_GCP=false
    local BASELINE=false
    local USE_LIB=false
    VERBOSE=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --all)
                RUN_AZURE=true
                RUN_AWS=true
                RUN_GCP=true
                shift
                ;;
            --azure)
                RUN_AZURE=true
                shift
                ;;
            --aws)
                RUN_AWS=true
                shift
                ;;
            --gcp)
                RUN_GCP=true
                shift
                ;;
            --baseline)
                BASELINE=true
                shift
                ;;
            --with-lib)
                USE_LIB=true
                shift
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                usage
                ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
    done

    # Default to all if nothing specified
    if [ "$RUN_AZURE" = "false" ] && [ "$RUN_AWS" = "false" ] && [ "$RUN_GCP" = "false" ]; then
        RUN_AZURE=true
        RUN_AWS=true
        RUN_GCP=true
    fi

    check_opa

    echo ""
    echo "=========================================="
    echo "    PRANCER COMPLIANCE TEST RUNNER"
    echo "=========================================="
    echo ""

    if [ "$BASELINE" = "true" ]; then
        log_info "Running BASELINE tests (before existence check fixes)"
    fi

    if [ "$USE_LIB" = "true" ]; then
        log_info "Using lib/ for existence checks"
    fi

    # Run tests
    [ "$RUN_AZURE" = "true" ] && test_azure_nsg "$USE_LIB"
    [ "$RUN_AWS" = "true" ] && test_aws_sg "$USE_LIB"
    [ "$RUN_GCP" = "true" ] && test_gcp_firewall "$USE_LIB"

    # Generate report and summary
    local report_type="full"
    [ "$BASELINE" = "true" ] && report_type="baseline"

    generate_report "$report_type"
    print_summary

    # Exit with error if tests failed
    [ $FAILED_TESTS -gt 0 ] && exit 1
    exit 0
}

main "$@"
