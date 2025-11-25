#!/usr/bin/env node
const fs = require('fs');

const files = [
    'aws/cloud/master-compliance-test.json',
    'azure/cloud/master-compliance-test.json',
    'google/cloud/master-compliance-test.json'
];

console.log('=== Validating JSON Structure ===\n');

let valid = true;
let severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };

for (const file of files) {
    try {
        const content = fs.readFileSync(file, 'utf8');
        const data = JSON.parse(content);
        const cases = data.testSet.flatMap(ts => ts.cases);
        console.log(file + ': Valid JSON, ' + cases.length + ' test cases');

        // Check all required fields preserved
        let missingFields = 0;
        for (const tc of cases) {
            if (tc.masterTestId === undefined || tc.type === undefined || tc.rule === undefined) {
                missingFields++;
            }
            // Count severity distribution
            if (tc.severity) {
                severityCounts[tc.severity] = (severityCounts[tc.severity] || 0) + 1;
            }
        }
        if (missingFields > 0) {
            console.log('  WARNING: ' + missingFields + ' cases missing required fields');
            valid = false;
        }
    } catch (e) {
        console.log(file + ': INVALID - ' + e.message);
        valid = false;
    }
}

console.log('\n=== Severity Distribution ===');
for (const [severity, count] of Object.entries(severityCounts)) {
    console.log(`  ${severity}: ${count}`);
}

console.log('\n' + (valid ? 'All files validated successfully!' : 'Some validation issues found'));
