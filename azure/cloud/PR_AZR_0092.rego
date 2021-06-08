#
# PR-AZR-0092
#

package rule

default rulepass = false

# Azure disk for VM operating system is not encrypted at rest using ADE
# If availability set is enabled test will pass

# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Storage/storageAccounts/vatsalstorage1
# https://docs.microsoft.com/en-us/rest/api/storagerp/storageaccounts/getproperties

rulepass {
    lower(input.type) == "microsoft.storage/storageaccounts"
    input.properties.supportsHttpsTrafficOnly == true
}

rulepass {
    lower(input.type) == "microsoft.storage/storageaccounts"
    not input.properties.supportsHttpsTrafficOnly
}

metadata := {
    "Policy Code": "PR-AZR-0092",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Storage Accounts without Secure transfer enabled",
    "Policy Description": "The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesnâ€™t support HTTPs for custom domain names, this option is not applied when using a custom domain name.",
    "Compliance": ["CIS","CSA-CCM","HIPAA","ISO 27001","NIST 800","PCI-DSS"],
    "Resource Type": "microsoft.storage/storageaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Storage/storageAccounts/vatsalstorage1"
}
