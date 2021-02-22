#
# PR-AZR-0064
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines/extensions

rulepass {
   input.type == "Microsoft.Compute/virtualMachines/extensions"
   input.properties.type == "IaaSAntimalware"
}
