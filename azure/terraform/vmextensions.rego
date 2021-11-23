package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine_extension

#
# PR-AZR-TRF-VM-003
#

default vm_protection = null

azure_attribute_absence["vm_protection"] {
    count([c | input.resources[_].type == "azurerm_virtual_machine_extension"; c := 1]) == 0
}

azure_attribute_absence["vm_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine_extension"
    not resource.properties.type
}

azure_issue["vm_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_virtual_machine_extension"
    lower(resource.properties.type) != "iaasantimalware"
}

vm_protection {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    not azure_attribute_absence["vm_protection"]
    not azure_issue["vm_protection"]
}

vm_protection = false {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    azure_issue["vm_protection"]
}

vm_protection = false {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    azure_attribute_absence["vm_protection"]
}

vm_protection_err = "azurerm_virtual_machine_extension property 'type' need to be exist. Its missing from the resource. Please set value to 'iaasantimalware' after property addition." {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    azure_attribute_absence["vm_protection"]
} else = "Azure Virtual Machine does not have endpoint protection installed" {
    lower(input.resources[_].type) == "azurerm_virtual_machine"
    azure_issue["vm_protection"]
}

vm_protection_metadata := {
    "Policy Code": "PR-AZR-TRF-VM-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Virtual Machine should have endpoint protection installed",
    "Policy Description": "This policy identifies Azure Virtual Machines (VMs) that do not have endpoint protection installed. Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. As a best practice, install endpoint protection on all VMs and computers to help identify and remove viruses, spyware, and other malicious software.",
    "Resource Type": "azurerm_virtual_machine_extension",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine_extension"
}
