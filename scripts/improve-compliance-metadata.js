#!/usr/bin/env node
/**
 * Improve Compliance Test Metadata
 *
 * Enhances title, description, and severity for all test cases
 * based on cloud security best practices.
 */

const fs = require('fs');
const path = require('path');

// Severity determination based on security impact
const severityRules = {
    // CRITICAL - Data exposure, complete system compromise, public access
    critical: [
        /public.*(access|bucket|storage|blob)/i,
        /0\.0\.0\.0\/0.*(?:all|any).*(?:port|traffic)/i,
        /anonymous.*access/i,
        /world.*(readable|writable)/i,
        /no.*(authentication|encryption).*(?:public|internet)/i,
        /disabled?.*encryption.*rest/i,
        /secrets?.*exposed/i,
        /credentials?.*plain/i,
        /privilege.?escalation/i,
        /all.*traffic.*allowed/i
    ],
    // HIGH - Significant security risks
    high: [
        /ssh.*(?:open|public|0\.0\.0\.0)/i,
        /rdp.*(?:open|public|0\.0\.0\.0)/i,
        /port\s*22.*(?:open|unrestricted)/i,
        /port\s*3389.*(?:open|unrestricted)/i,
        /database.*(?:public|exposed)/i,
        /missing.*encryption/i,
        /not.*enabled.*(?:encryption|ssl|tls)/i,
        /disabled.*(?:logging|audit)/i,
        /without.*(?:ssl|tls)/i,
        /weak.*(?:cipher|password)/i,
        /overly.?permissive/i,
        /publicly.?accessible/i,
        /security.?group.*allow.*all/i,
        /unrestricted.*(?:ingress|egress)/i,
        /rotation.*(?:not|disabled)/i,
        /key.*not.*(?:enabled|in.use|usable)/i
    ],
    // MEDIUM - Important security configurations
    medium: [
        /backup.*(?:not|disabled)/i,
        /recovery.*(?:not|disabled)/i,
        /logging.*(?:not|disabled)/i,
        /monitoring.*(?:not|disabled)/i,
        /versioning.*(?:not|disabled)/i,
        /mfa.*(?:not|disabled)/i,
        /expir/i,
        /retention/i,
        /soft.?delete/i,
        /purge.?protection/i,
        /network.?policy/i,
        /default.*service.?account/i,
        /basic.*auth/i
    ],
    // LOW - Best practices, informational
    low: [
        /best.?practice/i,
        /recommend/i,
        /label/i,
        /description.*(?:missing|empty)/i,
        /tag(?:s|ging)?.*(?:missing|not)/i,
        /naming/i,
        /principal.*access/i
    ]
};

// Title improvement patterns - keep titles concise
const titleImprovements = {
    // Direct replacements for known problematic titles
    'AWS Customer Master Key (CMK) rotation is not enabled': 'AWS KMS key rotation must be enabled',
    'AWS KMS Customer Managed Key not in use': 'AWS KMS Customer Managed Key is disabled or unusable',
    'Ensure at least one principal has access to Keyvault': 'Azure Key Vault must have at least one access policy configured',
    'Ensure GCP Kubernetes Engine Clusters Basic Authentication is not set to Disabled': 'GCP Kubernetes Engine clusters must have basic authentication disabled',

    // Pattern-based fixes
    patterns: [
        // Fix grammar issues
        { find: /is not set to Disabled/gi, replace: 'must be disabled' },
        { find: /is not set to Enabled/gi, replace: 'must be enabled' },
        { find: /not have Alias IP enabled/gi, replace: 'have Alias IP ranges enabled' },
        // Remove redundant "Ensure" at start when followed by specific cloud name
        { find: /^Ensure\s+(AWS|Azure|GCP|Google)\s+/i, replace: '$1 ' },
        // Fix double negatives
        { find: /not.*not\s+/gi, replace: '' },
        // Standardize phrasing
        { find: /\s+is\s+not\s+enabled$/i, replace: ' must be enabled' },
        { find: /\s+is\s+not\s+disabled$/i, replace: ' must be disabled' },
        { find: /\s+not\s+enabled$/i, replace: ' must be enabled' },
        // Capitalize properly
        { find: /\baws\b/g, replace: 'AWS' },
        { find: /\bazure\b/g, replace: 'Azure' },
        { find: /\bgcp\b/g, replace: 'GCP' },
        { find: /\bgke\b/g, replace: 'GKE' },
        { find: /\baks\b/g, replace: 'AKS' },
        { find: /\beks\b/g, replace: 'EKS' },
        { find: /\bec2\b/g, replace: 'EC2' },
        { find: /\bs3\b/g, replace: 'S3' },
        { find: /\brds\b/g, replace: 'RDS' },
        { find: /\biam\b/g, replace: 'IAM' },
        { find: /\bkms\b/g, replace: 'KMS' },
        { find: /\bssl\b/g, replace: 'SSL' },
        { find: /\btls\b/g, replace: 'TLS' },
        { find: /\bvpc\b/g, replace: 'VPC' },
        { find: /\bwaf\b/g, replace: 'WAF' },
        { find: /\bmfa\b/g, replace: 'MFA' },
        { find: /\bnsg\b/g, replace: 'NSG' }
    ]
};

// Description enhancement - expand abbreviations here
const abbreviationExpansions = [
    { short: /\bCMK\b/g, long: 'Customer Master Key (CMK)' },
    { short: /\bNSG\b/g, long: 'Network Security Group (NSG)' },
    { short: /\bACL\b/g, long: 'Access Control List (ACL)' },
    { short: /\bWAF\b/g, long: 'Web Application Firewall (WAF)' },
    { short: /\bRBAC\b/g, long: 'Role-Based Access Control (RBAC)' },
    { short: /\bCIDR\b/g, long: 'Classless Inter-Domain Routing (CIDR)' }
];

function determineSeverity(title, description, currentSeverity) {
    const text = `${title} ${description}`.toLowerCase();

    // Check for critical indicators - be conservative
    for (const pattern of severityRules.critical) {
        if (pattern.test(text)) {
            return 'Critical';
        }
    }

    // Check for high indicators
    for (const pattern of severityRules.high) {
        if (pattern.test(text)) {
            return 'High';
        }
    }

    // Check for low indicators first (before medium, to be conservative)
    for (const pattern of severityRules.low) {
        if (pattern.test(text)) {
            return 'Low';
        }
    }

    // Check for medium indicators
    for (const pattern of severityRules.medium) {
        if (pattern.test(text)) {
            return 'Medium';
        }
    }

    // Keep current severity if no patterns matched
    return currentSeverity || 'Medium';
}

function improveTitle(title) {
    if (!title) return title;

    let improved = title;

    // Check for exact matches first
    if (titleImprovements[title]) {
        return titleImprovements[title];
    }

    // Apply pattern-based improvements
    for (const pattern of titleImprovements.patterns) {
        improved = improved.replace(pattern.find, pattern.replace);
    }

    // Capitalize first letter
    improved = improved.charAt(0).toUpperCase() + improved.slice(1);

    // Remove double spaces
    improved = improved.replace(/\s+/g, ' ').trim();

    // Remove trailing period from titles
    improved = improved.replace(/\.$/, '');

    return improved;
}

function improveDescription(description, title) {
    if (!description) return description;

    let improved = description;

    // Fix common grammar issues
    improved = improved.replace(/\s+/g, ' ');

    // Expand abbreviations in description (first occurrence only)
    for (const abbr of abbreviationExpansions) {
        if (!new RegExp(abbr.long.replace(/[()]/g, '\\$&'), 'i').test(improved)) {
            let replaced = false;
            improved = improved.replace(abbr.short, (match) => {
                if (!replaced) {
                    replaced = true;
                    return abbr.long;
                }
                return match;
            });
        }
    }

    // Ensure description ends with a period
    improved = improved.trim();
    if (improved && !/[.!?]$/.test(improved)) {
        improved += '.';
    }

    return improved;
}

function processTestCase(testCase) {
    const original = {
        title: testCase.title,
        description: testCase.description,
        severity: testCase.severity
    };

    // Improve title
    if (testCase.title) {
        testCase.title = improveTitle(testCase.title);
    }

    // Improve description
    if (testCase.description) {
        testCase.description = improveDescription(testCase.description, testCase.title || '');
    }

    // Revise severity based on content
    if (testCase.title || testCase.description) {
        testCase.severity = determineSeverity(
            testCase.title || '',
            testCase.description || '',
            testCase.severity
        );
    }

    return {
        changed: original.title !== testCase.title ||
                 original.description !== testCase.description ||
                 original.severity !== testCase.severity,
        original,
        updated: {
            title: testCase.title,
            description: testCase.description,
            severity: testCase.severity
        }
    };
}

function processFile(filePath, backupPath) {
    console.log(`\nProcessing: ${filePath}`);

    // Read from backup (original) file
    const content = fs.readFileSync(backupPath, 'utf8');
    let data;

    try {
        data = JSON.parse(content);
    } catch (e) {
        console.error(`  Error parsing JSON: ${e.message}`);
        return { processed: 0, changed: 0, errors: 1 };
    }

    let processed = 0;
    let changed = 0;
    const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };

    // Navigate to test cases
    if (data.testSet) {
        for (const testGroup of data.testSet) {
            if (testGroup.cases) {
                for (const testCase of testGroup.cases) {
                    processed++;
                    const result = processTestCase(testCase);
                    if (result.changed) {
                        changed++;
                    }
                    severityCounts[testCase.severity] = (severityCounts[testCase.severity] || 0) + 1;
                }
            }
        }
    }

    // Write updated file
    fs.writeFileSync(filePath, JSON.stringify(data, null, 4));
    console.log(`  Processed: ${processed}, Changed: ${changed}`);
    console.log(`  Severity distribution: Critical=${severityCounts.Critical}, High=${severityCounts.High}, Medium=${severityCounts.Medium}, Low=${severityCounts.Low}`);

    return { processed, changed, errors: 0, severityCounts };
}

// Main execution
const cloudFolders = [
    { file: 'aws/cloud/master-compliance-test.json', backup: 'aws/cloud/master-compliance-test.backup.json' },
    { file: 'azure/cloud/master-compliance-test.json', backup: 'azure/cloud/master-compliance-test.backup.json' },
    { file: 'google/cloud/master-compliance-test.json', backup: 'google/cloud/master-compliance-test.backup.json' }
];

console.log('='.repeat(60));
console.log('   COMPLIANCE TEST METADATA IMPROVEMENT (v2)');
console.log('='.repeat(60));

const stats = {
    totalProcessed: 0,
    totalChanged: 0,
    totalErrors: 0,
    severityCounts: { Critical: 0, High: 0, Medium: 0, Low: 0 }
};

for (const { file, backup } of cloudFolders) {
    const fullPath = path.join(process.cwd(), file);
    const backupPath = path.join(process.cwd(), backup);

    if (fs.existsSync(backupPath)) {
        const result = processFile(fullPath, backupPath);
        stats.totalProcessed += result.processed;
        stats.totalChanged += result.changed;
        stats.totalErrors += result.errors;
        if (result.severityCounts) {
            for (const [sev, count] of Object.entries(result.severityCounts)) {
                stats.severityCounts[sev] = (stats.severityCounts[sev] || 0) + count;
            }
        }
    } else {
        console.log(`\nSkipping (backup not found): ${backup}`);
    }
}

console.log('\n' + '='.repeat(60));
console.log('   SUMMARY');
console.log('='.repeat(60));
console.log(`Total test cases processed: ${stats.totalProcessed}`);
console.log(`Total test cases changed:   ${stats.totalChanged}`);
console.log(`\nSeverity Distribution:`);
console.log(`  Critical: ${stats.severityCounts.Critical}`);
console.log(`  High:     ${stats.severityCounts.High}`);
console.log(`  Medium:   ${stats.severityCounts.Medium}`);
console.log(`  Low:      ${stats.severityCounts.Low}`);
console.log('='.repeat(60));
