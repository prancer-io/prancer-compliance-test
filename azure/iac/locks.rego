package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.authorization/2016-09-01/locks

#
# Azure Resource Group does not have a resource lock (261)
#

default rg_locks = null

azure_attribute_absence["rg_locks"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/locks"
    not resource.properties.level
}

azure_issue["rg_locks"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.authorization/locks"
    contains(lower(resource.id), "resourcegroups")
    lower(resource.properties.level) != "cannotdelete"
}

rg_locks {
    lower(input.resources[_].type) == "microsoft.authorization/locks"
    not azure_issue["rg_locks"]
    not azure_attribute_absence["rg_locks"]
}

rg_locks = false {
    azure_issue["rg_locks"]
}

rg_locks = false {
    azure_attribute_absence["rg_locks"]
}

rg_locks_err = "Azure Resource Group does not have a resource lock" {
    azure_issue["rg_locks"]
}

rg_locks_miss_err = "Lock attribute level missing in the resource" {
    azure_attribute_absence["rg_locks"]
}
