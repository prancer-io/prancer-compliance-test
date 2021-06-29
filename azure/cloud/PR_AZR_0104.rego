package rule

# https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/get
# PR_AZR_0104.rego

default adminUserEnabled = null
azure_issue ["adminUserEnabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    resource.properties.adminUserEnabled != false
}

adminUserEnabled {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    not azure_issue["adminUserEnabled"]
}

adminUserEnabled = false {
    azure_issue["adminUserEnabled"]
}


adminUserEnabled_err = "ENSURE THAT ADMIN USER IS DISABLED FOR CONTAINER REGISTRY" {
    azure_issue["adminUserEnabled"]
}


adminUserEnabled_metadata := {
    "Policy Code": "PR-AZR-0104",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "ENSURE THAT ADMIN USER IS DISABLED FOR CONTAINER REGISTRY",
    "Policy Description": "The value that indicates whether the admin user is enabled. Each container registry includes an admin user account, which is disabled by default. You can enable the admin user and manage its credentials in the Azure portal, or by using the Azure CLI or other Azure tools. All users authenticating with the admin account appear as a single user with push and pull access to the registry. Changing or disabling this account disables registry access for all users who use its credentials.",
    "Resource Type": "microsoft.containerregistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/get"
}