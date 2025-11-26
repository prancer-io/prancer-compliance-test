package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cosmosdb_account

# PR-AZR-TRF-CDA-001

default tagsLength = null

azure_attribute_absence ["tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cosmosdb_account"
    not resource.properties.tags
}

azure_issue ["tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cosmosdb_account"
    count(resource.properties.tags) == 0
}

tagsLength = false {
    azure_attribute_absence["tagsLength"]
}

tagsLength {
    lower(input.resources[_].type) == "azurerm_cosmosdb_account"
    not azure_attribute_absence["tagsLength"]
    not azure_issue["tagsLength"]
}

tagsLength = false {
    azure_issue["tagsLength"]
}

tagsLength_err = "azurerm_cosmosdb_account property 'tags' need to be exist. Its missing from the resource." {
    azure_attribute_absence["tagsLength"]
} else = "Resource 'azurerm_cosmosdb_account' does not have any associated tag. Please add one." {
    azure_issue["tagsLength"]
}

tagsLength_metadata := {
    "Policy Code": "PR-AZR-TRF-CDA-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Cosmos DB Account has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to resources to better organize them. They are particularly useful when you have many resources of the same type. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Some of the key advantages of tagging is Grouping, Filtering and Cost allocation.",
    "Resource Type": "azurerm_cosmosdb_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cosmosdb_account"
}