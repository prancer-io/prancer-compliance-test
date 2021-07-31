package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries

# PR-AZR-0104-ARM

default adminUserDisabled = null


azure_issue ["adminUserDisabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    resource.properties.adminUserEnabled != false
}

adminUserDisabled {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    not azure_issue["adminUserDisabled"]
}


adminUserDisabled = false {
    azure_issue["adminUserDisabled"]
}

adminUserDisabled_err = "Azure Container Registry admin user is currently not disabled" {
    azure_issue["adminUserDisabled"]
}


adminUserDisabled_metadata := {
    "Policy Code": "PR-AZR-0104-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that admin user is disabled for Container Registry",
    "Policy Description": "The value that indicates whether the admin user is enabled. Each container registry includes an admin user account, which is disabled by default. You can enable the admin user and manage its credentials in the Azure portal, or by using the Azure CLI or other Azure tools. All users authenticating with the admin account appear as a single user with push and pull access to the registry. Changing or disabling this account disables registry access for all users who use its credentials.",
    "Resource Type": "microsoft.containerregistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries"
}