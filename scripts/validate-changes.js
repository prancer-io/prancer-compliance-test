#!/usr/bin/env node
/**
 * Validate all Rego file changes
 */

const fs = require('fs');
const path = require('path');

function findRegoFiles(dir) {
    const files = [];
    const items = fs.readdirSync(dir, { withFileTypes: true });
    for (const item of items) {
        const fullPath = path.join(dir, item.name);
        if (item.isDirectory() && !item.name.startsWith('.') && item.name !== 'node_modules' && item.name !== 'backup') {
            files.push(...findRegoFiles(fullPath));
        } else if (item.name.endsWith('.rego')) {
            files.push(fullPath);
        }
    }
    return files;
}

// Validation checks
let stats = {
    total: 0,
    withExistence: 0,
    nullDefaults: 0,
    trueDefaults: 0,
    syntaxIssues: [],
    missingPackage: [],
    byProvider: {
        aws: { files: 0, existence: 0 },
        azure: { files: 0, existence: 0 },
        google: { files: 0, existence: 0 },
        kubernetes: { files: 0, existence: 0 },
        other: { files: 0, existence: 0 }
    }
};

const projectRoot = path.dirname(__dirname);
const files = findRegoFiles(projectRoot);

for (const file of files) {
    if (file.includes('/backup/') || file.includes('/fixed/')) continue;

    stats.total++;
    const content = fs.readFileSync(file, 'utf8');
    const relativePath = file.replace(projectRoot + '/', '');

    // Detect provider
    let provider = 'other';
    if (relativePath.includes('aws/')) provider = 'aws';
    else if (relativePath.includes('azure/')) provider = 'azure';
    else if (relativePath.includes('google/')) provider = 'google';
    else if (relativePath.includes('kubernetes/')) provider = 'kubernetes';

    stats.byProvider[provider].files++;

    if (content.includes('import data.lib.existence')) {
        stats.withExistence++;
        stats.byProvider[provider].existence++;
    }

    const nullDefaultMatches = content.match(/default\s+\w+\s*=\s*null/g) || [];
    const trueDefaultMatches = content.match(/default\s+\w+\s*=\s*true/g) || [];

    stats.nullDefaults += nullDefaultMatches.length;
    stats.trueDefaults += trueDefaultMatches.length;

    // Check for remaining default=true (potential issues)
    if (trueDefaultMatches.length > 0) {
        stats.syntaxIssues.push({
            file: relativePath,
            issue: `Still has ${trueDefaultMatches.length} default=true rules`,
            matches: trueDefaultMatches.slice(0, 3)
        });
    }

    // Check for syntax issues
    if (!content.includes('package ')) {
        stats.missingPackage.push(relativePath);
    }

    // Check for unbalanced braces
    const openBraces = (content.match(/\{/g) || []).length;
    const closeBraces = (content.match(/\}/g) || []).length;
    if (openBraces !== closeBraces) {
        stats.syntaxIssues.push({
            file: relativePath,
            issue: `Unbalanced braces: ${openBraces} open, ${closeBraces} close`
        });
    }
}

console.log('========================================');
console.log('     VALIDATION REPORT');
console.log('========================================');
console.log('');
console.log('OVERVIEW:');
console.log(`  Total Rego files (excl backup/fixed): ${stats.total}`);
console.log(`  Files with existence imports: ${stats.withExistence}`);
console.log(`  Rules with default=null: ${stats.nullDefaults}`);
console.log(`  Rules with default=true (remaining): ${stats.trueDefaults}`);
console.log('');
console.log('BY PROVIDER:');
for (const [provider, data] of Object.entries(stats.byProvider)) {
    if (data.files > 0) {
        const pct = ((data.existence / data.files) * 100).toFixed(1);
        console.log(`  ${provider.toUpperCase()}: ${data.files} files, ${data.existence} with existence (${pct}%)`);
    }
}
console.log('');

if (stats.syntaxIssues.length > 0) {
    console.log('POTENTIAL ISSUES:');
    for (const issue of stats.syntaxIssues.slice(0, 10)) {
        console.log(`  - ${issue.file}: ${issue.issue}`);
        if (issue.matches) {
            issue.matches.forEach(m => console.log(`      "${m.trim()}"`));
        }
    }
    if (stats.syntaxIssues.length > 10) {
        console.log(`  ... and ${stats.syntaxIssues.length - 10} more`);
    }
    console.log('');
}

if (stats.missingPackage.length > 0) {
    console.log('MISSING PACKAGE DECLARATIONS:');
    stats.missingPackage.forEach(f => console.log(`  - ${f}`));
    console.log('');
}

const successRate = ((stats.withExistence / stats.total) * 100).toFixed(1);
console.log('========================================');
console.log(`SUCCESS RATE: ${successRate}%`);
console.log(`(${stats.withExistence}/${stats.total} files updated)`);
console.log('========================================');

// Save report
const report = {
    timestamp: new Date().toISOString(),
    summary: {
        totalFiles: stats.total,
        filesWithExistence: stats.withExistence,
        nullDefaults: stats.nullDefaults,
        trueDefaults: stats.trueDefaults,
        successRate: successRate + '%'
    },
    byProvider: stats.byProvider,
    issues: stats.syntaxIssues.slice(0, 20),
    missingPackage: stats.missingPackage
};

const reportPath = path.join(projectRoot, 'reports', `validation-report-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
console.log(`\nReport saved to: ${reportPath}`);
