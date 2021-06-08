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

metadata := {
    "Policy Code": "PR-AZR-0004",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Automatic provisioning of monitoring agent is set to Off in Security Center",
    "Policy Description": "Turning on Automatic provisioning of monitoring agent will provision the Microsoft Monitoring Agent on all the supported Azure virtual machines and any new ones. The Microsoft Monitoring agent scans for different security-related setups and events such as system updates, operating system weaknesses, endpoint protection, and provides alerts.",
    "Compliance": ["CIS","HIPAA","ISO 27001","NIST 800"],
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
