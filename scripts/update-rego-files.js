#!/usr/bin/env node
/**
 * Prancer Compliance Test - Rego Existence Check Updater
 *
 * This script automatically adds resource existence checks to Rego policy files.
 * It handles different patterns for Azure, AWS, GCP, and Kubernetes.
 *
 * Usage:
 *   node scripts/update-rego-files.js [--dry-run] [--verbose] [--provider azure|aws|google|kubernetes]
 */

const fs = require('fs');
const path = require('path');

const PROJECT_ROOT = path.dirname(__dirname);
const BACKUP_DIR = path.join(PROJECT_ROOT, 'backup');

// Configuration
let DRY_RUN = false;
let VERBOSE = false;
let PROVIDER_FILTER = null;

// Statistics
const stats = {
    filesProcessed: 0,
    filesModified: 0,
    filesSkipped: 0,
    filesErrored: 0,
    rulesUpdated: 0,
    errors: []
};

// Parse command line arguments
process.argv.slice(2).forEach(arg => {
    if (arg === '--dry-run') DRY_RUN = true;
    if (arg === '--verbose') VERBOSE = true;
    if (arg.startsWith('--provider=')) PROVIDER_FILTER = arg.split('=')[1];
});

/**
 * Log messages based on verbosity
 */
function log(msg, level = 'info') {
    const colors = {
        info: '\x1b[34m',
        success: '\x1b[32m',
        warning: '\x1b[33m',
        error: '\x1b[31m',
        reset: '\x1b[0m'
    };

    if (level === 'verbose' && !VERBOSE) return;

    const color = colors[level] || colors.info;
    console.log(`${color}[${level.toUpperCase()}]${colors.reset} ${msg}`);
}

/**
 * Detect the cloud provider from file path
 */
function detectProvider(filePath) {
    if (filePath.includes('/aws/')) return 'aws';
    if (filePath.includes('/azure/')) return 'azure';
    if (filePath.includes('/google/')) return 'google';
    if (filePath.includes('/kubernetes/')) return 'kubernetes';
    return 'unknown';
}

/**
 * Detect the type (cloud, iac, terraform)
 */
function detectType(filePath) {
    if (filePath.includes('/cloud/')) return 'cloud';
    if (filePath.includes('/iac/')) return 'iac';
    if (filePath.includes('/terraform/')) return 'terraform';
    if (filePath.includes('/ack/')) return 'ack';
    if (filePath.includes('/aso/')) return 'aso';
    if (filePath.includes('/kcc/')) return 'kcc';
    return 'unknown';
}

/**
 * Extract resource types from Azure Rego files
 */
function extractAzureResourceTypes(content) {
    const types = new Set();

    // Pattern: lower(resource.type) == "microsoft.xxx/yyy"
    const matches = content.matchAll(/lower\(resource\.type\)\s*==\s*"([^"]+)"/gi);
    for (const match of matches) {
        types.add(match[1].toLowerCase());
    }

    // Pattern: lower(input.resources[_].type) == "microsoft.xxx/yyy"
    const matches2 = content.matchAll(/lower\(input\.resources\[_\]\.type\)\s*==\s*"([^"]+)"/gi);
    for (const match of matches2) {
        types.add(match[1].toLowerCase());
    }

    return Array.from(types);
}

/**
 * Extract resource keys from AWS Rego files
 */
function extractAwsResourceKeys(content) {
    const keys = new Set();

    // Pattern: input.SecurityGroups[_]
    const matches = content.matchAll(/input\.([A-Z][a-zA-Z]+)\[/g);
    for (const match of matches) {
        keys.add(match[1]);
    }

    return Array.from(keys);
}

/**
 * Extract rule names from Rego content
 */
function extractRuleNames(content) {
    const rules = [];

    // Pattern: default rule_name = null|true|false
    const matches = content.matchAll(/^default\s+(\w+)\s*=\s*(null|true|false)/gm);
    for (const match of matches) {
        rules.push({
            name: match[1],
            defaultValue: match[2]
        });
    }

    return rules;
}

/**
 * Check if file already has existence checks
 */
function hasExistenceChecks(content) {
    return content.includes('import data.lib.existence') ||
           content.includes('_resource_exists') ||
           content.includes('resource_exists(');
}

/**
 * Generate existence check import and helpers for Azure
 */
function generateAzureExistenceChecks(resourceTypes) {
    if (resourceTypes.length === 0) return '';

    let code = `
##############################################################################
# EXISTENCE CHECKS - Auto-generated
##############################################################################

import data.lib.existence

`;

    for (const type of resourceTypes) {
        const safeName = type.replace(/[^a-z0-9]/gi, '_').replace(/_+/g, '_');
        code += `# Check if ${type} resources exist
${safeName}_exists {
    existence.azure_resource_exists("${type}")
}

`;
    }

    return code;
}

/**
 * Generate existence check import and helpers for AWS
 */
function generateAwsExistenceChecks(resourceKeys) {
    if (resourceKeys.length === 0) return '';

    let code = `
##############################################################################
# EXISTENCE CHECKS - Auto-generated
##############################################################################

import data.lib.existence

`;

    for (const key of resourceKeys) {
        const safeName = key.toLowerCase();
        code += `# Check if ${key} resources exist
${safeName}_exists {
    existence.aws_resource_exists("${key}")
}

`;
    }

    return code;
}

/**
 * Generate existence check import and helpers for GCP
 */
function generateGcpExistenceChecks(content) {
    return `
##############################################################################
# EXISTENCE CHECKS - Auto-generated
##############################################################################

import data.lib.existence

# Check if this is a valid GCP resource
gcp_resource_valid {
    existence.gcp_resource_exists
}

`;
}

/**
 * Update rule to include existence check
 * Changes "default rule = true" to "default rule = null"
 * Adds existence check to rule body
 */
function updateRuleWithExistenceCheck(content, ruleName, existenceCheckName) {
    let modified = content;

    // Change default = true to default = null
    const defaultPattern = new RegExp(`(default\\s+${ruleName}\\s*=\\s*)true`, 'g');
    if (defaultPattern.test(modified)) {
        modified = modified.replace(defaultPattern, '$1null');
        stats.rulesUpdated++;
    }

    return modified;
}

/**
 * Process a single Rego file
 */
function processFile(filePath) {
    stats.filesProcessed++;

    const relativePath = filePath.replace(PROJECT_ROOT + '/', '');

    try {
        let content = fs.readFileSync(filePath, 'utf8');
        const provider = detectProvider(filePath);
        const type = detectType(filePath);

        // Skip if already has existence checks
        if (hasExistenceChecks(content)) {
            log(`Skipping ${relativePath} - already has existence checks`, 'verbose');
            stats.filesSkipped++;
            return;
        }

        // Skip fixed directory
        if (filePath.includes('/fixed/')) {
            log(`Skipping ${relativePath} - in fixed directory`, 'verbose');
            stats.filesSkipped++;
            return;
        }

        // Skip lib directory
        if (filePath.includes('/lib/')) {
            log(`Skipping ${relativePath} - library file`, 'verbose');
            stats.filesSkipped++;
            return;
        }

        let existenceCode = '';
        let modified = content;

        // Generate existence checks based on provider
        if (provider === 'azure') {
            const resourceTypes = extractAzureResourceTypes(content);
            if (resourceTypes.length > 0) {
                existenceCode = generateAzureExistenceChecks(resourceTypes);
            }
        } else if (provider === 'aws') {
            const resourceKeys = extractAwsResourceKeys(content);
            if (resourceKeys.length > 0) {
                existenceCode = generateAwsExistenceChecks(resourceKeys);
            }
        } else if (provider === 'google') {
            existenceCode = generateGcpExistenceChecks(content);
        } else if (provider === 'kubernetes') {
            // Kubernetes has different patterns, skip for now
            log(`Skipping ${relativePath} - Kubernetes requires manual review`, 'verbose');
            stats.filesSkipped++;
            return;
        }

        // Extract rules and update them
        const rules = extractRuleNames(content);
        for (const rule of rules) {
            if (rule.defaultValue === 'true') {
                // This is a high-risk rule that returns true by default
                // Change to null
                const pattern = new RegExp(`(default\\s+${rule.name}\\s*=\\s*)true`, 'g');
                modified = modified.replace(pattern, '$1null');
                stats.rulesUpdated++;
                log(`Changed default=${rule.defaultValue} to null for ${rule.name} in ${relativePath}`, 'verbose');
            }
        }

        // Insert existence checks after package declaration
        if (existenceCode) {
            // Find the best place to insert (after package and any existing imports)
            const packageMatch = modified.match(/^package\s+\w+\s*\n/m);
            if (packageMatch) {
                const insertPos = packageMatch.index + packageMatch[0].length;

                // Skip past any existing imports
                let importEndPos = insertPos;
                const importMatches = modified.slice(insertPos).matchAll(/^import\s+[^\n]+\n/gm);
                for (const match of importMatches) {
                    importEndPos = insertPos + match.index + match[0].length;
                }

                // Skip past any has_property functions that might already exist
                const hasPropertyMatch = modified.slice(importEndPos).match(/has_property\([^)]+\)\s*\{[^}]+\}\s*\n/);
                if (hasPropertyMatch) {
                    importEndPos += hasPropertyMatch.index + hasPropertyMatch[0].length;
                }

                modified = modified.slice(0, importEndPos) + existenceCode + modified.slice(importEndPos);
            }
        }

        // Check if any changes were made
        if (modified !== content) {
            if (DRY_RUN) {
                log(`Would modify ${relativePath}`, 'info');
            } else {
                // Create backup
                const backupPath = path.join(BACKUP_DIR, relativePath);
                const backupDir = path.dirname(backupPath);
                if (!fs.existsSync(backupDir)) {
                    fs.mkdirSync(backupDir, { recursive: true });
                }
                fs.writeFileSync(backupPath, content);

                // Write modified file
                fs.writeFileSync(filePath, modified);
                log(`Modified ${relativePath}`, 'success');
            }
            stats.filesModified++;
        } else {
            log(`No changes needed for ${relativePath}`, 'verbose');
            stats.filesSkipped++;
        }

    } catch (err) {
        log(`Error processing ${relativePath}: ${err.message}`, 'error');
        stats.filesErrored++;
        stats.errors.push({ file: relativePath, error: err.message });
    }
}

/**
 * Find all Rego files
 */
function findRegoFiles(dir) {
    const files = [];

    const items = fs.readdirSync(dir, { withFileTypes: true });
    for (const item of items) {
        const fullPath = path.join(dir, item.name);

        if (item.isDirectory()) {
            // Skip node_modules, .git, etc.
            if (!item.name.startsWith('.') && item.name !== 'node_modules') {
                files.push(...findRegoFiles(fullPath));
            }
        } else if (item.name.endsWith('.rego')) {
            // Apply provider filter if specified
            if (PROVIDER_FILTER) {
                if (fullPath.includes(`/${PROVIDER_FILTER}/`)) {
                    files.push(fullPath);
                }
            } else {
                files.push(fullPath);
            }
        }
    }

    return files;
}

/**
 * Main function
 */
function main() {
    console.log('='.repeat(60));
    console.log('   REGO EXISTENCE CHECK UPDATER');
    console.log('='.repeat(60));
    console.log('');

    if (DRY_RUN) {
        log('Running in DRY-RUN mode - no files will be modified', 'warning');
    }

    if (PROVIDER_FILTER) {
        log(`Filtering to provider: ${PROVIDER_FILTER}`, 'info');
    }

    // Create backup directory
    if (!DRY_RUN && !fs.existsSync(BACKUP_DIR)) {
        fs.mkdirSync(BACKUP_DIR, { recursive: true });
        log(`Created backup directory: ${BACKUP_DIR}`, 'info');
    }

    // Find all Rego files
    const regoFiles = findRegoFiles(PROJECT_ROOT);
    log(`Found ${regoFiles.length} Rego files to process`, 'info');
    console.log('');

    // Process each file
    for (const file of regoFiles) {
        processFile(file);
    }

    // Print summary
    console.log('');
    console.log('='.repeat(60));
    console.log('   SUMMARY');
    console.log('='.repeat(60));
    console.log(`Files processed:  ${stats.filesProcessed}`);
    console.log(`Files modified:   ${stats.filesModified}`);
    console.log(`Files skipped:    ${stats.filesSkipped}`);
    console.log(`Files errored:    ${stats.filesErrored}`);
    console.log(`Rules updated:    ${stats.rulesUpdated}`);
    console.log('');

    if (stats.errors.length > 0) {
        console.log('Errors:');
        for (const err of stats.errors) {
            console.log(`  - ${err.file}: ${err.error}`);
        }
        console.log('');
    }

    if (DRY_RUN) {
        log('This was a dry run. Run without --dry-run to apply changes.', 'warning');
    } else {
        log(`Backup files saved to: ${BACKUP_DIR}`, 'info');
    }

    // Save stats to file
    const statsFile = path.join(PROJECT_ROOT, 'reports', `update-stats-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
    fs.writeFileSync(statsFile, JSON.stringify({ ...stats, timestamp: new Date().toISOString() }, null, 2));
    log(`Stats saved to: ${statsFile}`, 'info');
}

main();
