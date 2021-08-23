package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines

#
# PR-AZR-0065-ARM
#

default vm_aset = null

azure_issue["vm_aset"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachines"
    not resource.properties.availabilitySet
}

vm_aset {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines"
    not azure_issue["vm_aset"]
}

vm_aset = false {
    azure_issue["vm_aset"]
}

vm_aset_err = "Azure Virtual Machine is not assigned to an availability set" {
    azure_issue["vm_aset"]
}

vm_aset_metadata := {
    "Policy Code": "PR-AZR-0065-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Virtual Machine should be assigned to an availability set",
    "Policy Description": "To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure._x005F_x000D_ _x005F_x000D_ This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.",
    "Resource Type": "microsoft.compute/virtualmachines",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines"
}


package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines
# https://github.com/Azure/azure-quickstart-templates/blob/master/quickstarts/microsoft.compute/vm-new-or-existing-conditions/azuredeploy.json
#
# PR-AZR-0141-ARM
#

default vm_linux_disabled_password_auth = null

azure_attribute_absence["vm_linux_disabled_password_auth"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachines"
    not resource.properties.osProfile.linuxConfiguration.disablePasswordAuthentication
}

azure_issue["vm_linux_disabled_password_auth"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachines"
    resource.properties.osProfile.linuxConfiguration.disablePasswordAuthentication != true
}

vm_linux_disabled_password_auth {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines"
    not azure_attribute_absence["vm_linux_disabled_password_auth"]
    not azure_issue["vm_linux_disabled_password_auth"]
}

vm_linux_disabled_password_auth = false {
    azure_attribute_absence["vm_linux_disabled_password_auth"]
}

vm_linux_disabled_password_auth = false {
    azure_issue["vm_linux_disabled_password_auth"]
}

vm_linux_disabled_password_auth_err = "'microsoft.compute/virtualmachines' property 'osProfile.linuxConfiguration.disablePasswordAuthentication' is missing from the resource" {
    azure_attribute_absence["vm_linux_disabled_password_auth"]
} else = "Azure Linux Instance currently does not have basic authentication disabled" {
    azure_issue["vm_linux_disabled_password_auth"]
}

vm_linux_disabled_password_auth_metadata := {
    "Policy Code": "PR-AZR-0141-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure Linux Instance does not use basic authentication(Use SSH Key Instead)",
    "Policy Description": "For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.",
    "Resource Type": "microsoft.compute/virtualmachines",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines"
}

