#
# PR-AZR-0310
#

package rule

default rulepass = false

# Policy rule definition
# https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/SQL/SqlManagedInstance_AdvancedDataSecurity_Audit.json
# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies

rulepass {
    input.type == "Microsoft.Sql/managedInstances/securityAlertPolicies"
    input.properties.state == "Enabled"
}
