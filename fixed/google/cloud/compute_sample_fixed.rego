# GCP Firewall Compliance Rules - WITH EXISTENCE CHECKS
#
# This file demonstrates the FIXED pattern for GCP Firewall rules
# that properly checks for resource existence before running tests.
#
# CRITICAL CHANGES from original:
# 1. Original has type checks COMMENTED OUT
# 2. Original directly accesses input.sourceRanges without validation
# 3. Fixed version validates resource type/kind before evaluation

package rule

import data.lib.existence
import data.lib.helpers

##############################################################################
# EXISTENCE CHECKS
##############################################################################

# Check if input is a GCP firewall resource
is_firewall_resource {
    existence.gcp_resource_kind_matches("compute#firewall")
}

is_firewall_resource {
    existence.gcp_resource_exists
    contains(lower(input.selfLink), "/firewalls/")
}

# Check if firewall has source ranges defined
has_source_ranges {
    _ = input.sourceRanges[_]
}

# Check if firewall has allowed rules
has_allowed_rules {
    _ = input.allowed[_]
}

##############################################################################
# HELPER FUNCTIONS
##############################################################################

# Check if firewall allows traffic from internet (0.0.0.0/0)
allows_from_internet {
    is_firewall_resource
    input.sourceRanges[_] == "0.0.0.0/0"
}

# Check if a specific port is in the allowed rules
allows_port(target_port) {
    is_firewall_resource
    allow := input.allowed[_]
    allow.ports[_] == target_port
}

# Check if port is in a range
allows_port_in_range(target_port) {
    is_firewall_resource
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= to_number(target_port)
    to_number(port_range[1]) >= to_number(target_port)
}

# Check if all ports are allowed (no ports specified = all ports)
allows_all_ports_tcp {
    is_firewall_resource
    allow := input.allowed[_]
    lower(allow.IPProtocol) == "tcp"
    not allow.ports
}

allows_all_ports_tcp {
    is_firewall_resource
    allow := input.allowed[_]
    lower(allow.IPProtocol) == "tcp"
    count(allow.ports) == 0
}

allows_all_ports_udp {
    is_firewall_resource
    allow := input.allowed[_]
    lower(allow.IPProtocol) == "udp"
    not allow.ports
}

allows_all_ports_udp {
    is_firewall_resource
    allow := input.allowed[_]
    lower(allow.IPProtocol) == "udp"
    count(allow.ports) == 0
}

##############################################################################
# PR-GCP-CLD-FW-001 - Default Firewall Rules
##############################################################################

default firewall_default = null

firewall_default_resource_exists {
    is_firewall_resource
}

gc_attribute_absence["firewall_default"] {
    is_firewall_resource
    not input.name
}

gc_issue["firewall_default"] {
    is_firewall_resource
    lower(input.name) == "default-allow-ssh"
    allows_from_internet
}

gc_issue["firewall_default"] {
    is_firewall_resource
    lower(input.name) == "default-allow-icmp"
    allows_from_internet
}

gc_issue["firewall_default"] {
    is_firewall_resource
    lower(input.name) == "default-allow-internal"
    allows_from_internet
}

gc_issue["firewall_default"] {
    is_firewall_resource
    lower(input.name) == "default-allow-rdp"
    allows_from_internet
}

firewall_default {
    firewall_default_resource_exists
    not gc_issue["firewall_default"]
    not gc_attribute_absence["firewall_default"]
}

firewall_default = false {
    firewall_default_resource_exists
    gc_issue["firewall_default"]
}

firewall_default = false {
    firewall_default_resource_exists
    gc_attribute_absence["firewall_default"]
}

firewall_default_err = "Default Firewall rule should not have any rules (except http and https)" {
    gc_issue["firewall_default"]
}

firewall_default_skip_reason = msg {
    not firewall_default_resource_exists
    msg := "Input is not a GCP firewall resource"
}

firewall_default_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-001",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "Default Firewall rule should not have any rules (except http and https)",
    "Policy Description": "The default Firewall rules will apply to all instances by default. It is a safe practice to not have these rules in the default Firewall.",
    "Resource Type": "compute.v1.firewall"
}

##############################################################################
# PR-GCP-CLD-FW-002 - DNS Port (53) Open to Internet
##############################################################################

default firewall_port_53 = null

firewall_port_53_resource_exists {
    is_firewall_resource
}

gc_issue["firewall_port_53"] {
    allows_from_internet
    allows_port("53")
}

gc_issue["firewall_port_53"] {
    allows_from_internet
    allows_port_in_range("53")
}

gc_issue["firewall_port_53"] {
    allows_from_internet
    allows_all_ports_tcp
}

gc_issue["firewall_port_53"] {
    allows_from_internet
    allows_all_ports_udp
}

firewall_port_53 {
    firewall_port_53_resource_exists
    not gc_issue["firewall_port_53"]
}

firewall_port_53 = false {
    firewall_port_53_resource_exists
    gc_issue["firewall_port_53"]
}

firewall_port_53_err = "GCP Firewall rule allows internet traffic to DNS port (53)" {
    gc_issue["firewall_port_53"]
}

firewall_port_53_skip_reason = msg {
    not firewall_port_53_resource_exists
    msg := "Input is not a GCP firewall resource"
}

firewall_port_53_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-002",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to DNS port (53)",
    "Policy Description": "This policy identifies GCP Firewall rules which allow inbound traffic on DNS port (53) from public internet.",
    "Resource Type": "compute.v1.firewall"
}

##############################################################################
# PR-GCP-CLD-FW-003 - FTP Port (21) Open to Internet
##############################################################################

default firewall_port_21 = null

firewall_port_21_resource_exists {
    is_firewall_resource
}

gc_issue["firewall_port_21"] {
    allows_from_internet
    allows_port("21")
}

gc_issue["firewall_port_21"] {
    allows_from_internet
    allows_port_in_range("21")
}

gc_issue["firewall_port_21"] {
    allows_from_internet
    allows_all_ports_tcp
}

firewall_port_21 {
    firewall_port_21_resource_exists
    not gc_issue["firewall_port_21"]
}

firewall_port_21 = false {
    firewall_port_21_resource_exists
    gc_issue["firewall_port_21"]
}

firewall_port_21_err = "GCP Firewall rule allows internet traffic to FTP port (21)" {
    gc_issue["firewall_port_21"]
}

firewall_port_21_skip_reason = msg {
    not firewall_port_21_resource_exists
    msg := "Input is not a GCP firewall resource"
}

firewall_port_21_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-003",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to FTP port (21)",
    "Policy Description": "This policy identifies GCP Firewall rules which allow inbound traffic on FTP port (21) from public internet.",
    "Resource Type": "compute.v1.firewall"
}

##############################################################################
# PR-GCP-CLD-FW-006 - SSH Port (22) Open to Internet
##############################################################################

default firewall_port_22 = null

firewall_port_22_resource_exists {
    is_firewall_resource
}

gc_issue["firewall_port_22"] {
    allows_from_internet
    allows_port("22")
}

gc_issue["firewall_port_22"] {
    allows_from_internet
    allows_port_in_range("22")
}

gc_issue["firewall_port_22"] {
    allows_from_internet
    allows_all_ports_tcp
}

firewall_port_22 {
    firewall_port_22_resource_exists
    not gc_issue["firewall_port_22"]
}

firewall_port_22 = false {
    firewall_port_22_resource_exists
    gc_issue["firewall_port_22"]
}

firewall_port_22_err = "GCP Firewall rule allows internet traffic to SSH port (22)" {
    gc_issue["firewall_port_22"]
}

firewall_port_22_skip_reason = msg {
    not firewall_port_22_resource_exists
    msg := "Input is not a GCP firewall resource"
}

firewall_port_22_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-006",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to SSH port (22)",
    "Policy Description": "This policy identifies GCP Firewall rules which allow inbound traffic on SSH port (22) from public internet.",
    "Resource Type": "compute.v1.firewall"
}

##############################################################################
# PR-GCP-CLD-FW-007 - RDP Port (3389) Open to Internet
##############################################################################

default firewall_port_3389 = null

firewall_port_3389_resource_exists {
    is_firewall_resource
}

gc_issue["firewall_port_3389"] {
    allows_from_internet
    allows_port("3389")
}

gc_issue["firewall_port_3389"] {
    allows_from_internet
    allows_port_in_range("3389")
}

gc_issue["firewall_port_3389"] {
    allows_from_internet
    allows_all_ports_tcp
}

firewall_port_3389 {
    firewall_port_3389_resource_exists
    not gc_issue["firewall_port_3389"]
}

firewall_port_3389 = false {
    firewall_port_3389_resource_exists
    gc_issue["firewall_port_3389"]
}

firewall_port_3389_err = "GCP Firewall rule allows internet traffic to RDP port (3389)" {
    gc_issue["firewall_port_3389"]
}

firewall_port_3389_skip_reason = msg {
    not firewall_port_3389_resource_exists
    msg := "Input is not a GCP firewall resource"
}

firewall_port_3389_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-007",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "GCP Cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to RDP port (3389)",
    "Policy Description": "This policy identifies GCP Firewall rules which allow inbound traffic on RDP port (3389) from public internet.",
    "Resource Type": "compute.v1.firewall"
}
