#
# PR-AZR-0086
#

package rule
default rulepass = false

# Security Configurations is set to OFF in Security Center
# If Security Configurations is set to ON in Security Center test will pass
# Vulnerabilities in container security configurations should be remediated

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "containerBenchmarkMonitoring")
}

metadata := {
    "Policy Code": "PR-AZR-0086",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Security Configurations is set to OFF in Security Center",
    "Policy Description": "Turning on the Security configurations will enable the daily analysis of operating system configurations. The rules for hardening the operating system like firewall rules, password and audit policies are reviewed. Recommendations are made for setting the right level of security controls.",
    "Compliance": ["CIS","CSA-CCM","HIPAA","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
