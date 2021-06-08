#
# PR-AZR-0002
#

package rule
default rulepass = false

# Adaptive Application Controls is set to OFF in Security Center
# If Adaptive Application Controls is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "adaptiveApplicationControlsMonitoring")
}

metadata := {
    "Policy Code": "PR-AZR-0002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Adaptive Application Controls is set to OFF in Security Center",
    "Policy Description": "Turning on Adaptive Application Controls will make sure that only certain applications can run on your VMs in Microsoft Azure. This will prevent any malicious, unwanted, or unsupported software on the VMs.",
    "Compliance": ["CIS","CSA-CCM","ISO 27001","NIST 800"],
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
