# Prancer Compliance Test - Resource Existence Library
#
# This library provides functions to check for resource existence
# before running compliance checks, preventing false positives.
#
# Usage:
#   import data.lib.existence
#
#   my_rule {
#       existence.azure_resource_exists("microsoft.network/networksecuritygroups")
#       # ... rest of compliance logic
#   }

package lib.existence

##############################################################################
# AZURE EXISTENCE CHECKS
##############################################################################

# Check if ANY resource of a specific Azure resource type exists
# Args:
#   resource_type: The Azure resource type (e.g., "microsoft.network/networksecuritygroups")
# Returns:
#   true if at least one resource of this type exists, undefined otherwise
azure_resource_exists(resource_type) {
    resource := input.resources[_]
    lower(resource.type) == lower(resource_type)
}

# Count resources of a specific Azure type
# Args:
#   resource_type: The Azure resource type
# Returns:
#   Integer count of matching resources
azure_resource_count(resource_type) = cnt {
    cnt := count([r |
        r := input.resources[_]
        lower(r.type) == lower(resource_type)
    ])
}

# Get all resources of a specific Azure type (safe - returns empty array if none)
# Args:
#   resource_type: The Azure resource type
# Returns:
#   Array of matching resources
azure_resources_by_type(resource_type) = resources {
    resources := [r |
        r := input.resources[_]
        lower(r.type) == lower(resource_type)
    ]
}

# Check if a specific Azure resource exists by ID
# Args:
#   resource_id: The full Azure resource ID
# Returns:
#   true if resource with this ID exists
azure_resource_exists_by_id(resource_id) {
    resource := input.resources[_]
    lower(resource.id) == lower(resource_id)
}

##############################################################################
# AWS EXISTENCE CHECKS
##############################################################################

# Check if AWS resource collection exists and has items
# Args:
#   resource_key: The key in input (e.g., "SecurityGroups", "Instances")
# Returns:
#   true if the key exists and has at least one item
aws_resource_exists(resource_key) {
    collection := input[resource_key]
    count(collection) > 0
}

# Check if AWS resource collection exists (may be empty)
# Args:
#   resource_key: The key in input
# Returns:
#   true if the key exists (even if empty)
aws_resource_key_exists(resource_key) {
    _ = input[resource_key]
}

# Count AWS resources in a collection
# Args:
#   resource_key: The key in input
# Returns:
#   Integer count of items in collection
aws_resource_count(resource_key) = cnt {
    cnt := count(input[resource_key])
} else = 0 {
    true
}

# Get AWS resources safely (returns empty array if not exists)
# Args:
#   resource_key: The key in input
# Returns:
#   Array of resources or empty array
aws_resources(resource_key) = resources {
    resources := input[resource_key]
} else = [] {
    true
}

##############################################################################
# GCP EXISTENCE CHECKS
##############################################################################

# Check if GCP resource matches expected kind
# Args:
#   kind: The GCP resource kind (e.g., "compute#firewall")
# Returns:
#   true if input.kind matches
gcp_resource_kind_matches(kind) {
    lower(input.kind) == lower(kind)
}

# Check if GCP resource exists by checking for name property
# Returns:
#   true if input.name exists (indicating a valid resource)
gcp_resource_exists {
    _ = input.name
}

# Check if GCP resource type matches (for compute resources)
# Args:
#   resource_type: The resource type string
# Returns:
#   true if selfLink contains the resource type
gcp_resource_type_matches(resource_type) {
    contains(lower(input.selfLink), lower(resource_type))
}

##############################################################################
# GENERIC EXISTENCE CHECKS
##############################################################################

# Check if input.resources array exists and is not empty
has_resources {
    count(input.resources) > 0
}

# Check if input.resources exists (may be empty)
resources_defined {
    _ = input.resources
}

# Check if input has any keys (not empty object)
input_not_empty {
    count(input) > 0
}

# Safe check for nested property existence
# Args:
#   obj: The parent object
#   path: Array of property names forming the path
# Returns:
#   true if the full path exists
nested_property_exists(obj, path) {
    count(path) == 0
}

nested_property_exists(obj, path) {
    count(path) > 0
    key := path[0]
    _ = obj[key]
    remaining := array.slice(path, 1, count(path))
    nested_property_exists(obj[key], remaining)
}

##############################################################################
# DEPENDENCY CHECKS
##############################################################################

# Check if Azure VNet exists
azure_vnet_exists {
    azure_resource_exists("microsoft.network/virtualnetworks")
}

# Check if Azure NSG exists
azure_nsg_exists {
    azure_resource_exists("microsoft.network/networksecuritygroups")
}

# Check if Azure Firewall exists
azure_firewall_exists {
    azure_resource_exists("microsoft.network/azurefirewalls")
}

# Check if Azure Storage Account exists
azure_storage_exists {
    azure_resource_exists("microsoft.storage/storageaccounts")
}

# Check if Azure Key Vault exists
azure_keyvault_exists {
    azure_resource_exists("microsoft.keyvault/vaults")
}

# Check if Azure AKS exists
azure_aks_exists {
    azure_resource_exists("microsoft.containerservice/managedclusters")
}

# Check if AWS Security Groups exist
aws_security_groups_exist {
    aws_resource_exists("SecurityGroups")
}

# Check if AWS EC2 Instances exist
aws_ec2_instances_exist {
    aws_resource_exists("Instances")
}

# Check if AWS S3 Buckets exist
aws_s3_buckets_exist {
    aws_resource_exists("Buckets")
}
