package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.authorization/2016-09-01/locks

#
# Instance is communicating with ports known to mine Bitcoin (1)
#

default rg_locks = null

rg_locks {
    lower(input.type) == "microsoft.authorization/locks"
    contains(lower(input.id), "resourcegroups")
    lower(input.properties.level) == "cannotdelete"
}

rg_locks = false {
    lower(input.type) == "microsoft.authorization/locks"
    contains(lower(input.id), "resourcegroups")
    lower(input.properties.level) != "cannotdelete"
}

rg_locks_err = "Azure Resource Group does not have a resource lock" {
    rg_locks == false
}
