#
# PR-AZR-0078
#

package rule
default rulepass = false

# JIT Network Access is set to OFF in Security Center
# If JIT Network Access is set to ON in Security Center

# https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0

rulepass {
    lower(input.type) == "microsoft.authorization/policyassignments"
    contains(input.id, "jitNetworkAccessMonitoring")
}

metadata := {
    "Policy Code": "PR-AZR-0078",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "JIT Network Access is set to OFF in Security Center",
    "Policy Description": "Turning on JIT Network Access will enhance the protection of VMs by creating a Just in Time VM. The JIT VM with NSG rule will restrict the availability of access to the ports to connect to the VM for a pre-set time and only after checking the Role Based Access Control permissions of the user. This feature will control the brute force attacks on the VMs.",
    "Resource Type": "microsoft.authorization/policyassignments",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/resources/policyassignments/list#code-try-0"
}
