#
# PR-AZR-0052
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.authorization/2016-09-01/locks

rulepass {
    lower(input.type) == "microsoft.authorization/locks"
    contains(input.id, "resourceGroups")
    input.properties.level == "CanNotDelete"
}
