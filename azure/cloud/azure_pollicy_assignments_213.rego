#
# PR-AZR-0004
#

package rule
default rulepass = false

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
   contains(input.id, "ArcLinuxMonitoring")
}

rulepass {
   contains(input.id, "ArcWindowsMonitoring")
}
