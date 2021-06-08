#
# PR-AZR-0099
#

package rule
default rulepass = false

# Vulnerability assessment is set to OFF in Security Center
# If Vulnerability assessment is set to ON in Security Center test will pass
# Vulnerabilities should be remediated by a Vulnerability Assessment solution

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "vulnerabilityAssesmentMonitoring")
}

metadata := {
    "Policy Code": "PR-AZR-0099",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Vulnerability assessment is set to OFF in Security Center",
    "Policy Description": "Turning on Vulnerability assessment will recommend that you install a vulnerability assessment solution on your VM. A partner agent, after deployment, will report any vulnerability data for the VM.",
    "Compliance": ["CIS","CSA-CCM","HIPAA","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
