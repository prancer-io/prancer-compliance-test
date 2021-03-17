#
# PR-AZR-0064
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines/extensions

rulepass {
   lower(input.type) == "microsoft.compute/virtualmachines/extensions"
   input.properties.type == "IaaSAntimalware"
}
