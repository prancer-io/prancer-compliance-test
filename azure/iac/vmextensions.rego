package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines/extensions

#
# Azure Virtual Machine does not have endpoint protection installed (273)
#

default vm_protection = null

vm_protection {
    lower(input.type) == "microsoft.compute/virtualmachines/extensions"
    input.properties.type == "IaaSAntimalware"
}

vm_protection = false {
    lower(input.type) == "microsoft.compute/virtualmachines/extensions"
    input.properties.type != "IaaSAntimalware"
}

vm_protection_err = "Azure Virtual Machine does not have endpoint protection installed" {
    vm_protection == false
}
