package rule
default rulepass = false

# Azure disk for VM operating system is not encrypted at rest using ADE
# If disk for VM operating system is encrypted test will pass

# https://docs.microsoft.com/en-us/rest/api/compute/disks/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Compute/disks

rulepass = true {
   count(disks) == 1
}

# 'osType exists and 
# (encryptionSettings is exist or 
# encryptionSettings.enabled == true)'

disks["osType exists"] {
   input.properties.osType
   input.properties.encryptionSettingsCollection.encryptionSettings
   input.properties.encryptionSettingsCollection.enabled = true
}

disks["osType Not exists"] {
   not input.properties.osType
}