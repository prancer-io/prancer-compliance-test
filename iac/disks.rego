package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.compute/disks

#
# Azure disk for VM operating system is not encrypted at rest using ADE (277)
#

default disk_encrypt = null

disk_encrypt {
    lower(input.type) == "microsoft.compute/disks"
    input.properties.osType
    input.properties.encryptionSettingsCollection.encryptionSettings
    input.properties.encryptionSettingsCollection.enabled == true
}

disk_encrypt {
    lower(input.type) == "microsoft.compute/disks"
    not input.properties.osType
}

disk_encrypt = false {
    lower(input.type) == "microsoft.compute/disks"
    input.properties.osType
    not input.properties.encryptionSettingsCollection.encryptionSettings
    input.properties.encryptionSettingsCollection.enabled == true
}

disk_encrypt = false {
    lower(input.type) == "microsoft.compute/disks"
    input.properties.osType
    input.properties.encryptionSettingsCollection.enabled != true
}

disk_encrypt_err = "Azure disk for VM operating system is not encrypted at rest using ADE" {
    disk_encrypt == false
}
