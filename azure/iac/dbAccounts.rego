package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts

# PR-AZR-0105-ARM

default tagsLength = null

azure_attribute_absence ["tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    not resource.tags
}

azure_issue ["tagsLength"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    count(resource.tags) == 0
}

tagsLength {
    lower(input.resources[_].type) == "microsoft.documentdb/databaseaccounts"
    not azure_attribute_absence["tagsLength"]
    not azure_issue["tagsLength"]
}

tagsLength = false {
    azure_issue["tagsLength"]
}

tagsLength = false {
    azure_attribute_absence["tagsLength"]
}


tagsLength_err = "Resource 'Cosmos DB Account' does not have any associated tag. Please add one." {
    azure_issue["tagsLength"]
}

tagsLength_miss_err = "property tags of type Object is absent from resource of type microsoft.documentdb/databaseaccounts" {
    azure_attribute_absence["tagsLength"]
}


tagsLength_metadata := {
    "Policy Code": "PR-AZR-0105-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that Cosmos DB Account has an associated tag",
    "Policy Description": "Tags are key-value pairs that you attach to Azure Cosmos DB resources to better organize them. They are particularly useful when you have many resources of the same type, which in the case of Azure Cosmos DB, is a database. By using tags, customers with hundreds of cloud resources, can easily access and analyze a specific set by filtering on those that contain the same tag. Two of the key advantages of tagging your Cosmos DB are: Grouping and Filtering and Cost allocation.",
    "Resource Type": "microsoft.documentdb/databaseaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts"
}