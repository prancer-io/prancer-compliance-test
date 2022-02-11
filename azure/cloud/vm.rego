package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines

#
# PR-AZR-CLD-VM-001
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
    "Policy Code": "PR-AZR-CLD-VM-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Virtual Machine should be assigned to an availability set",
    "Policy Description": "To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.",
    "Resource Type": "microsoft.compute/virtualmachines",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines"
}


# PR-AZR-CLD-VM-002
#

default linux_configuration = null

azure_attribute_absence["linux_configuration"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachines"
    not resource.properties.osProfile.linuxConfiguration.disablePasswordAuthentication
}

azure_issue["linux_configuration"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/virtualmachines"
    resource.properties.osProfile.linuxConfiguration.disablePasswordAuthentication != true
}

linux_configuration {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines"
    has_property(input.resources[_].properties.osProfile, "linuxConfiguration")
    not azure_attribute_absence["linux_configuration"]
    not azure_issue["linux_configuration"]
}

linux_configuration = false {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines"
    has_property(input.resources[_].properties.osProfile, "linuxConfiguration")
    azure_issue["linux_configuration"]
}

linux_configuration = false {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines"
    has_property(input.resources[_].properties.osProfile, "linuxConfiguration")
    azure_attribute_absence["linux_configuration"]
}

linux_configuration_err = "microsoft.compute/virtualmachines resource property linuxConfiguration.disablePasswordAuthentication missing in the resource" {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines"
    has_property(input.resources[_].properties.osProfile, "linuxConfiguration")
    azure_attribute_absence["linux_configuration"]
} else = "Azure instance does not authenticate using SSH keys" {
    lower(input.resources[_].type) == "microsoft.compute/virtualmachines"
    has_property(input.resources[_].properties.osProfile, "linuxConfiguration")
    azure_issue["linux_configuration"]
}

linux_configuration_metadata := {
    "Policy Code": "PR-AZR-CLD-VM-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Linux Instance should not use basic authentication(Use SSH Key Instead)",
    "Policy Description": "SSH is an encrypted connection protocol that allows secure sign-ins over unsecured connections. SSH is the default connection protocol for Linux VMs hosted in Azure. Using secure shell (SSH) key pair, it is possible to spin up a Linux virtual machine on Azure that defaults to using SSH keys for authentication, eliminating the need for passwords to sign in. We recommend connecting to a VM using SSH keys. Using basic authentication with SSH connections leaves VMs vulnerable to brute-force attacks or guessing of passwords.",
    "Resource Type": "microsoft.compute/virtualmachines",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/virtualmachines"
}
