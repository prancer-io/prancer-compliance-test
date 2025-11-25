package rule

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines/extensions

#
# PR-AZR-CLD-VM-003
#

default vm_protection = null

azure_attribute_absence["vm_protection"] {
    count([c | lower(input.resources[_].type) == "microsoft.compute/virtualmachines/extensions"; c := 1]) == 0
}

# azure_attribute_absence["vm_protection"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.compute/virtualmachines/extensions"
#     not resource.dependsOn
# }

azure_attribute_absence["vm_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachines/extensions"
    not resource.properties.type
}

azure_issue["vm_protection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachines"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.compute/virtualmachines/extensions";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(resource.properties.type) == "iaasantimalware";
              c := 1]) == 0
}

vm_protection {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines"
    not azure_attribute_absence["vm_protection"]
    not azure_issue["vm_protection"]
}

vm_protection = false {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines"
    azure_issue["vm_protection"]
}

vm_protection = false {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines"
    azure_attribute_absence["vm_protection"]
}

vm_protection_err = "Azure Virtual Machine does not have endpoint protection installed" {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines"
    azure_issue["vm_protection"]
} else = "VM extension attribute type missing in the resource" {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines"
    azure_attribute_absence["vm_protection"]
}

vm_protection_metadata := {
    "Policy Code": "PR-AZR-CLD-VM-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Virtual Machine should have endpoint protection installed",
    "Policy Description": "This policy identifies Azure Virtual Machines (VMs) that do not have endpoint protection installed. Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. As a best practice, install endpoint protection on all VMs and computers to help identify and remove viruses, spyware, and other malicious software.",
    "Resource Type": "microsoft.compute/virtualmachines/extensions",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines/extensions"
}
