package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachinescalesets/virtualmachines

#
# Azure Virtual Machine is not assigned to an availability set (274)
#

default vm_aset = null

vm_aset {
    lower(input.type) == "microsoft.compute/virtualmachinescalesets/virtualmachines"
    input.properties.availabilitySet
}

vm_aset = false {
    lower(input.type) == "microsoft.compute/virtualmachinescalesets/virtualmachines"
    not input.properties.availabilitySet
}

vm_aset_err = "Azure Virtual Machine is not assigned to an availability set" {
    vm_aset == false
}
