# Azure NSG Compliance Rules - WITH EXISTENCE CHECKS
#
# This file demonstrates the FIXED pattern for Azure NSG rules
# that properly checks for resource existence before running tests.
#
# Changes from original:
# 1. Import shared existence library
# 2. Add resource existence checks before each rule
# 3. Add skip reason metadata for non-existent resources

package rule

import data.lib.existence
import data.lib.helpers

##############################################################################
# RESOURCE TYPE CONSTANTS
##############################################################################

nsg_type := "microsoft.network/networksecuritygroups"

##############################################################################
# EXISTENCE CHECKS
##############################################################################

# Check if ANY NSG exists in the input
nsg_resources_exist {
    existence.azure_resource_exists(nsg_type)
}

# Get count of NSG resources
nsg_resource_count = cnt {
    cnt := existence.azure_resource_count(nsg_type)
}

##############################################################################
# PR-AZR-CLD-NSG-001 - NSG allows inbound TCP from all sources
##############################################################################

default nsg_in_tcp_all_src = null

# Existence helper for this rule
nsg_in_tcp_all_src_resource_exists {
    nsg_resources_exist
}

# Attribute absence check
azure_attribute_absence["nsg_in_tcp_all_src"] {
    nsg_resources_exist
    resource := input.resources[_]
    lower(resource.type) == nsg_type
    not resource.properties.securityRules
}

# Issue detection - resource exists and is non-compliant
azure_issue["nsg_in_tcp_all_src"] {
    nsg_resources_exist
    resource := input.resources[_]
    lower(resource.type) == nsg_type
    rule := resource.properties.securityRules[_]
    lower(rule.properties.access) == "allow"
    lower(rule.properties.direction) == "inbound"
    lower(rule.properties.protocol) == "tcp"
    helpers.is_source_open(rule.properties.sourceAddressPrefix)
    rule.properties.destinationPortRange == "*"
}

# PASS: Resource exists and is compliant
nsg_in_tcp_all_src {
    nsg_in_tcp_all_src_resource_exists
    not azure_issue["nsg_in_tcp_all_src"]
    not azure_attribute_absence["nsg_in_tcp_all_src"]
}

# FAIL: Resource exists and is non-compliant
nsg_in_tcp_all_src = false {
    nsg_in_tcp_all_src_resource_exists
    azure_issue["nsg_in_tcp_all_src"]
}

# FAIL: Resource exists but missing required properties
nsg_in_tcp_all_src = false {
    nsg_in_tcp_all_src_resource_exists
    azure_attribute_absence["nsg_in_tcp_all_src"]
}

# NOT APPLICABLE: Handled by default = null when nsg_resources_exist is false

# Error message
nsg_in_tcp_all_src_err = "Azure NSG allows inbound TCP traffic from all sources" {
    azure_issue["nsg_in_tcp_all_src"]
}

# Missing attribute message
nsg_in_tcp_all_src_miss_err = "Azure NSG missing securityRules property" {
    azure_attribute_absence["nsg_in_tcp_all_src"]
}

# Skip reason for non-existent resources
nsg_in_tcp_all_src_skip_reason = msg {
    not nsg_in_tcp_all_src_resource_exists
    msg := "No Network Security Groups found in the evaluated scope"
}

# Metadata
nsg_in_tcp_all_src_metadata := {
    "Policy Code": "PR-AZR-CLD-NSG-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Azure Cloud",
    "Policy Title": "Azure NSG allows inbound TCP traffic from all sources",
    "Policy Description": "This policy identifies NSGs that allow inbound TCP traffic from all sources (0.0.0.0/0 or *). This configuration is overly permissive and increases the attack surface.",
    "Resource Type": "Microsoft.Network/networkSecurityGroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

##############################################################################
# PR-AZR-CLD-NSG-002 - NSG allows SSH from internet
##############################################################################

default nsg_in_ssh_from_internet = null

# Existence helper for this rule
nsg_in_ssh_from_internet_resource_exists {
    nsg_resources_exist
}

# Issue detection - SSH port 22 open to internet
azure_issue["nsg_in_ssh_from_internet"] {
    nsg_resources_exist
    resource := input.resources[_]
    lower(resource.type) == nsg_type
    rule := resource.properties.securityRules[_]
    lower(rule.properties.access) == "allow"
    lower(rule.properties.direction) == "inbound"
    lower(rule.properties.protocol) == "tcp"
    helpers.is_source_open(rule.properties.sourceAddressPrefix)
    helpers.port_in_range(rule.properties.destinationPortRange, rule.properties.destinationPortRange, 22)
}

azure_issue["nsg_in_ssh_from_internet"] {
    nsg_resources_exist
    resource := input.resources[_]
    lower(resource.type) == nsg_type
    rule := resource.properties.securityRules[_]
    lower(rule.properties.access) == "allow"
    lower(rule.properties.direction) == "inbound"
    lower(rule.properties.protocol) == "tcp"
    helpers.is_source_open(rule.properties.sourceAddressPrefix)
    rule.properties.destinationPortRange == "22"
}

# PASS: Resource exists and is compliant
nsg_in_ssh_from_internet {
    nsg_in_ssh_from_internet_resource_exists
    not azure_issue["nsg_in_ssh_from_internet"]
}

# FAIL: Resource exists and is non-compliant
nsg_in_ssh_from_internet = false {
    nsg_in_ssh_from_internet_resource_exists
    azure_issue["nsg_in_ssh_from_internet"]
}

# Error message
nsg_in_ssh_from_internet_err = "Azure NSG allows SSH (port 22) from internet" {
    azure_issue["nsg_in_ssh_from_internet"]
}

# Skip reason
nsg_in_ssh_from_internet_skip_reason = msg {
    not nsg_in_ssh_from_internet_resource_exists
    msg := "No Network Security Groups found in the evaluated scope"
}

# Metadata
nsg_in_ssh_from_internet_metadata := {
    "Policy Code": "PR-AZR-CLD-NSG-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Azure Cloud",
    "Policy Title": "Azure NSG allows SSH from internet",
    "Policy Description": "This policy identifies NSGs that allow inbound SSH (port 22) from the internet. Exposing SSH to the internet increases the attack surface and risk of brute force attacks.",
    "Resource Type": "Microsoft.Network/networkSecurityGroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups"
}

##############################################################################
# PR-AZR-CLD-NSG-003 - NSG allows RDP from internet
##############################################################################

default nsg_in_rdp_from_internet = null

nsg_in_rdp_from_internet_resource_exists {
    nsg_resources_exist
}

azure_issue["nsg_in_rdp_from_internet"] {
    nsg_resources_exist
    resource := input.resources[_]
    lower(resource.type) == nsg_type
    rule := resource.properties.securityRules[_]
    lower(rule.properties.access) == "allow"
    lower(rule.properties.direction) == "inbound"
    lower(rule.properties.protocol) == "tcp"
    helpers.is_source_open(rule.properties.sourceAddressPrefix)
    rule.properties.destinationPortRange == "3389"
}

nsg_in_rdp_from_internet {
    nsg_in_rdp_from_internet_resource_exists
    not azure_issue["nsg_in_rdp_from_internet"]
}

nsg_in_rdp_from_internet = false {
    nsg_in_rdp_from_internet_resource_exists
    azure_issue["nsg_in_rdp_from_internet"]
}

nsg_in_rdp_from_internet_err = "Azure NSG allows RDP (port 3389) from internet" {
    azure_issue["nsg_in_rdp_from_internet"]
}

nsg_in_rdp_from_internet_skip_reason = msg {
    not nsg_in_rdp_from_internet_resource_exists
    msg := "No Network Security Groups found in the evaluated scope"
}

nsg_in_rdp_from_internet_metadata := {
    "Policy Code": "PR-AZR-CLD-NSG-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Azure Cloud",
    "Policy Title": "Azure NSG allows RDP from internet",
    "Policy Description": "This policy identifies NSGs that allow inbound RDP (port 3389) from the internet.",
    "Resource Type": "Microsoft.Network/networkSecurityGroups"
}
