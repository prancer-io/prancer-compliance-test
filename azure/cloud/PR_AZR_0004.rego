#
# PR-AZR-0004
#

package rule
default rulepass = false

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "ArcLinuxMonitoring")
}

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "ArcWindowsMonitoring")
}
