package rule

# https://github.com/Azure/azure-service-operator/blob/master/config/samples/azure_v1alpha1_storageaccount.yaml

#
# PR-AZR-0092-ASO
#

default storage_secure = null

azure_issue["storage_secure"] {
    resource := input.resources[_]
    lower(resource.kind) == "storageaccount"
    resource.spec.supportsHttpsTrafficOnly == false
}

storage_secure {
    lower(input.resources[_].type) == "storageaccount"
    not azure_issue["storage_secure"]
}

storage_secure = false {
    azure_issue["storage_secure"]
}

storage_secure_err = "Storage Accounts without Secure transfer enabled" {
    azure_issue["storage_secure"]
}

storage_secure_metadata := {
    "Policy Code": "PR-AZR-0092-ASO",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ASO template",
    "Policy Title": "Storage Accounts without Secure transfer enabled",
    "Policy Description": "The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access your storage accounts, you must connect using HTTPs. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When you are using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesnâ€™t support HTTPs for custom domain names, this option is not applied when using a custom domain name.",
    "Resource Type": "storageaccount",
    "Policy Help URL": "",
    "Resource Help URL": "https://github.com/Azure/azure-service-operator/blob/master/config/samples/azure_v1alpha1_storageaccount.yaml"
}
