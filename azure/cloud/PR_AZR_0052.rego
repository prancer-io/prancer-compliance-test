#
# PR-AZR-0052
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.authorization/2016-09-01/locks

rulepass {
    input.type == "Microsoft.Authorization/locks"
    contains(input.id, "resourceGroups")
    input.properties.level == "CanNotDelete"
}
