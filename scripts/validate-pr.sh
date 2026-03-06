#!/bin/bash
#
# Local PR Validation Script
#
# Run this script before pushing to validate your changes locally.
# This mimics the GitHub Actions workflow checks.
#
# Usage: ./scripts/validate-pr.sh
#
# Requirements:
#   - OPA (Open Policy Agent) CLI: https://www.openpolicyagent.org/docs/latest/#running-opa
#   - Node.js 18+
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   PR Validation Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

ERRORS=0
WARNINGS=0

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! command_exists node; then
    echo -e "${RED}Error: Node.js is not installed${NC}"
    exit 1
fi

OPA_AVAILABLE=false
if command_exists opa; then
    OPA_AVAILABLE=true
    echo -e "${GREEN}✓ OPA is available${NC}"
else
    echo -e "${YELLOW}⚠ OPA not found. Rego syntax checks will be skipped.${NC}"
    echo "  Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""

# Step 1: JSON Validation
echo -e "${BLUE}Step 1: Validating JSON files...${NC}"
json_errors=0

for file in $(find . -name "*.json" -not -path "./node_modules/*" -not -path "./backup/*" -not -path "./reports/*" -not -path "./.git/*" -not -name "*.backup.json"); do
    if ! node -e "JSON.parse(require('fs').readFileSync('$file', 'utf8'))" 2>/dev/null; then
        echo -e "${RED}  ✗ Invalid JSON: $file${NC}"
        json_errors=$((json_errors + 1))
    fi
done

if [ $json_errors -eq 0 ]; then
    echo -e "${GREEN}  ✓ All JSON files are valid${NC}"
else
    echo -e "${RED}  ✗ Found $json_errors invalid JSON files${NC}"
    ERRORS=$((ERRORS + json_errors))
fi

echo ""

# Step 2: Rego Syntax Validation
if [ "$OPA_AVAILABLE" = true ]; then
    echo -e "${BLUE}Step 2: Validating Rego syntax...${NC}"
    rego_errors=0

    for subdir in aws/cloud aws/iac aws/terraform aws/ack azure/cloud azure/iac azure/terraform azure/aso google/cloud google/iac google/terraform google/kcc kubernetes/cloud kubernetes/iac; do
        if [ -d "$subdir" ] && ls "$subdir"/*.rego 1>/dev/null 2>&1; then
            if ! opa check "$subdir"/*.rego utils/common.rego 2>/dev/null; then
                echo -e "${RED}  ✗ Syntax error in $subdir${NC}"
                rego_errors=$((rego_errors + 1))
            fi
        fi
    done
    # Also check shared libraries
    if [ -d "utils" ]; then
        if ! opa check utils/*.rego 2>/dev/null; then
            echo -e "${RED}  ✗ Syntax error in utils/${NC}"
            rego_errors=$((rego_errors + 1))
        fi
    fi

    if [ $rego_errors -eq 0 ]; then
        echo -e "${GREEN}  ✓ All Rego files have valid syntax${NC}"
    else
        echo -e "${RED}  ✗ Found $rego_errors Rego syntax errors${NC}"
        ERRORS=$((ERRORS + rego_errors))
    fi
else
    echo -e "${YELLOW}Step 2: Skipping Rego syntax validation (OPA not available)${NC}"
fi

echo ""

# Step 3: Compliance Test Metadata Validation
echo -e "${BLUE}Step 3: Validating compliance test metadata...${NC}"

if [ -f "scripts/validate-json.js" ]; then
    if node scripts/validate-json.js 2>/dev/null; then
        echo -e "${GREEN}  ✓ Compliance test metadata is valid${NC}"
    else
        echo -e "${RED}  ✗ Compliance test metadata validation failed${NC}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${YELLOW}  ⚠ Validation script not found, skipping...${NC}"
fi

echo ""

# Step 4: Reference Integrity Check
echo -e "${BLUE}Step 4: Checking file references...${NC}"

node << 'EOF'
const fs = require('fs');
const path = require('path');

function findJsonFiles(dir) {
    const results = [];
    try {
        const items = fs.readdirSync(dir, { withFileTypes: true });
        for (const item of items) {
            const fullPath = path.join(dir, item.name);
            if (item.name.startsWith('.') || item.name === 'node_modules' || item.name === 'backup') continue;
            if (item.isDirectory()) {
                results.push(...findJsonFiles(fullPath));
            } else if (item.name === 'master-compliance-test.json') {
                results.push(fullPath);
            }
        }
    } catch (e) {}
    return results;
}

let errors = 0;
const jsonFiles = findJsonFiles('.');

for (const jsonFile of jsonFiles) {
    const dir = path.dirname(jsonFile);
    try {
        const content = JSON.parse(fs.readFileSync(jsonFile, 'utf8'));
        if (!content.testSet) continue;

        for (const testGroup of content.testSet) {
            if (!testGroup.cases) continue;
            for (const testCase of testGroup.cases) {
                if (testCase.rule && testCase.rule.startsWith('file(')) {
                    const regoFile = testCase.rule.match(/file\(([^)]+)\)/)?.[1];
                    if (regoFile) {
                        const regoPath = path.join(dir, regoFile);
                        if (!fs.existsSync(regoPath)) {
                            console.log(`  ✗ Broken reference in ${jsonFile}: ${regoFile}`);
                            errors++;
                        }
                    }
                }
            }
        }
    } catch (e) {}
}

if (errors === 0) {
    console.log('  ✓ All file references are valid');
} else {
    process.exit(1);
}
EOF

if [ $? -ne 0 ]; then
    ERRORS=$((ERRORS + 1))
fi

echo ""

# Step 5: Run OPA Tests (if available)
if [ "$OPA_AVAILABLE" = true ]; then
    echo -e "${BLUE}Step 5: Running OPA tests...${NC}"

    test_files=$(find . -name "*_test.rego" -o -name "*.test.rego" 2>/dev/null)

    if [ -n "$test_files" ]; then
        test_errors=0
        for test in $test_files; do
            dir=$(dirname "$test")
            if ! opa test "$dir" 2>/dev/null; then
                echo -e "${RED}  ✗ Test failed: $test${NC}"
                test_errors=$((test_errors + 1))
            fi
        done

        if [ $test_errors -eq 0 ]; then
            echo -e "${GREEN}  ✓ All OPA tests passed${NC}"
        else
            echo -e "${RED}  ✗ $test_errors test(s) failed${NC}"
            ERRORS=$((ERRORS + test_errors))
        fi
    else
        echo -e "${YELLOW}  ⚠ No OPA test files found${NC}"
    fi
else
    echo -e "${YELLOW}Step 5: Skipping OPA tests (OPA not available)${NC}"
fi

echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Validation Summary${NC}"
echo -e "${BLUE}========================================${NC}"

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ All validations passed!${NC}"
    echo ""
    echo "Your changes are ready to push."
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ Passed with $WARNINGS warning(s)${NC}"
    echo ""
    echo "Your changes can be pushed, but consider addressing warnings."
    exit 0
else
    echo -e "${RED}✗ Found $ERRORS error(s) and $WARNINGS warning(s)${NC}"
    echo ""
    echo "Please fix the errors before pushing."
    exit 1
fi
