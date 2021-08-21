package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cosmosdb_account

# PR-AZR-0105-TRF

default tagsLength = null

azure_attribute_absence ["tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cosmosdb_account"
    not resource.tags
}

azure_issue ["tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cosmosdb_account"
    count(resource.tags) == 0
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
} else = "Resource 'Cosmos DB Account' does not have any associated tag. Please add one." {
    azure_issue["tagsLength"]
}

tagsLength_metadata := {
    "Policy Code": "PR-AZR-0105-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that Cosmos DB Account has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Azure Cosmos DB resources to better organize them. They are particularly useful when you have many resources of the same type, which in the case of Azure Cosmos DB, is a database. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Two of the key advantages of tagging your Cosmos DB are: Grouping and Filtering and Cost allocation.",
    "Resource Type": "azurerm_cosmosdb_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cosmosdb_account"
}