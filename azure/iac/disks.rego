package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/disks

#
# Azure disk for VM operating system is not encrypted at rest using ADE (277)
#

default disk_encrypt = null

azure_attribute_absence["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    resource.properties.osType
    not resource.properties.encryptionSettingsCollection.encryptionSettings
    resource.properties.encryptionSettingsCollection.enabled == true
}

azure_issue["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    resource.properties.osType
    resource.properties.encryptionSettingsCollection.enabled != true
}

azure_issue["disk_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.compute/disks"
    resource.properties.osType
    not resource.properties.encryptionSettingsCollection.enabled
}

disk_encrypt {
    lower(input.resources[_].type) == "microsoft.compute/disks"
    not azure_issue["disk_encrypt"]
    not azure_attribute_absence["disk_encrypt"]
}

disk_encrypt = false {
    azure_issue["disk_encrypt"]
}

disk_encrypt = false {
    azure_attribute_absence["disk_encrypt"]
}

disk_encrypt_err = "Azure disk for VM operating system is not encrypted at rest using ADE" {
    azure_issue["disk_encrypt"]
}

disk_encrypt_miss_err = "Disk attribute encryptionSettings missing in the resource" {
    azure_attribute_absence["disk_encrypt"]
}
