package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines/extensions

#
# PR-AZR-0064-ARM
#

default vm_protection = null

azure_attribute_absence["vm_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachines/extensions"
    not resource.properties.type
}

azure_issue["vm_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachines/extensions"
    lower(resource.properties.type) != "iaasantimalware"
}

vm_protection {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines/extensions"
    not azure_issue["vm_protection"]
    not azure_attribute_absence["vm_protection"]
}

vm_protection = false {
    azure_issue["vm_protection"]
}

vm_protection = false {
    azure_attribute_absence["vm_protection"]
}

vm_protection_err = "Azure Virtual Machine does not have endpoint protection installed" {
    azure_issue["vm_protection"]
}

vm_protection_miss_err = "VM extension attribute type missing in the resource" {
    azure_attribute_absence["vm_protection"]
}
