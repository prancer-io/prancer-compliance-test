# AWS Security Group Compliance Rules - WITH EXISTENCE CHECKS
#
# This file demonstrates the FIXED pattern for AWS Security Group rules
# that properly checks for resource existence before running tests.
#
# CRITICAL CHANGES from original:
# 1. Original uses "default = true" which causes FALSE POSITIVES
#    when SecurityGroups don't exist - rules pass by default!
# 2. Original has type checks COMMENTED OUT
# 3. Fixed version uses "default = null" and adds existence checks
#
# The original pattern causes the rule to return TRUE (pass) when:
# - No SecurityGroups exist in the input
# - Wrong resource type is being evaluated
# This is a MAJOR FALSE POSITIVE issue.

package rule

import data.lib.existence
import data.lib.helpers

##############################################################################
# EXISTENCE CHECKS
##############################################################################

# Check if SecurityGroups exist and have data
security_groups_exist {
    existence.aws_resource_exists("SecurityGroups")
}

# Get count of security groups
security_group_count = cnt {
    cnt := existence.aws_resource_count("SecurityGroups")
}

# Safe access to security groups (returns empty array if not exists)
security_groups = sgs {
    sgs := existence.aws_resources("SecurityGroups")
}

##############################################################################
# HELPER FUNCTIONS
##############################################################################

# Check if ingress rule allows traffic from internet on a specific port
ingress_allows_port_from_internet(port) {
    security_groups_exist
    sg := input.SecurityGroups[_]
    ingress := sg.IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

ingress_allows_port_from_internet(port) {
    security_groups_exist
    sg := input.SecurityGroups[_]
    ingress := sg.IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6 == "::/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

##############################################################################
# PR-AWS-CLD-SG-008 - SSH Port (22) Open to Internet
##############################################################################

# FIXED: Changed from "default port_22 = true" to "default port_22 = null"
# This prevents false positives when no SecurityGroups exist
default port_22 = null

# Existence helper
port_22_resource_exists {
    security_groups_exist
}

# Issue detection
aws_issue["port_22"] {
    ingress_allows_port_from_internet(22)
}

# PASS: Security groups exist and SSH is NOT open to internet
port_22 {
    port_22_resource_exists
    not aws_issue["port_22"]
}

# FAIL: Security groups exist and SSH IS open to internet
port_22 = false {
    port_22_resource_exists
    aws_issue["port_22"]
}

# NOT APPLICABLE: Handled by default = null when security_groups_exist is false

# Error message
port_22_err = "AWS Security Groups allow internet traffic to SSH port (22)" {
    aws_issue["port_22"]
}

# Skip reason for non-existent resources
port_22_skip_reason = msg {
    not port_22_resource_exists
    msg := "No Security Groups found in the evaluated scope"
}

port_22_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic to SSH port (22)",
    "Policy Description": "This policy identifies AWS Security Groups which allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system.",
    "Resource Type": "AWS::EC2::SecurityGroup",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

##############################################################################
# PR-AWS-CLD-SG-012 - RDP Port (3389) Open to Internet
##############################################################################

default port_3389 = null

port_3389_resource_exists {
    security_groups_exist
}

aws_issue["port_3389"] {
    ingress_allows_port_from_internet(3389)
}

port_3389 {
    port_3389_resource_exists
    not aws_issue["port_3389"]
}

port_3389 = false {
    port_3389_resource_exists
    aws_issue["port_3389"]
}

port_3389_err = "AWS Security Groups allow internet traffic to RDP port (3389)" {
    aws_issue["port_3389"]
}

port_3389_skip_reason = msg {
    not port_3389_resource_exists
    msg := "No Security Groups found in the evaluated scope"
}

port_3389_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-012",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic to RDP port (3389)",
    "Policy Description": "This policy identifies AWS Security Groups which expose RDP port (3389) to the internet.",
    "Resource Type": "AWS::EC2::SecurityGroup"
}

##############################################################################
# PR-AWS-CLD-SG-011 - MySQL Port (3306) Open to Internet
##############################################################################

default port_3306 = null

port_3306_resource_exists {
    security_groups_exist
}

aws_issue["port_3306"] {
    ingress_allows_port_from_internet(3306)
}

port_3306 {
    port_3306_resource_exists
    not aws_issue["port_3306"]
}

port_3306 = false {
    port_3306_resource_exists
    aws_issue["port_3306"]
}

port_3306_err = "AWS Security Groups allow internet traffic to MySQL port (3306)" {
    aws_issue["port_3306"]
}

port_3306_skip_reason = msg {
    not port_3306_resource_exists
    msg := "No Security Groups found in the evaluated scope"
}

port_3306_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-011",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic to MySQL port (3306)",
    "Policy Description": "This policy identifies Security Groups exposing MySQL port (3306) to the internet.",
    "Resource Type": "AWS::EC2::SecurityGroup"
}

##############################################################################
# PR-AWS-CLD-SG-016 - PostgreSQL Port (5432) Open to Internet
##############################################################################

default port_5432 = null

port_5432_resource_exists {
    security_groups_exist
}

aws_issue["port_5432"] {
    ingress_allows_port_from_internet(5432)
}

port_5432 {
    port_5432_resource_exists
    not aws_issue["port_5432"]
}

port_5432 = false {
    port_5432_resource_exists
    aws_issue["port_5432"]
}

port_5432_err = "AWS Security Groups allow internet traffic to PostgreSQL port (5432)" {
    aws_issue["port_5432"]
}

port_5432_skip_reason = msg {
    not port_5432_resource_exists
    msg := "No Security Groups found in the evaluated scope"
}

port_5432_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-016",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Security Groups allow internet traffic to PostgreSQL port (5432)",
    "Policy Description": "This policy identifies Security Groups exposing PostgreSQL port (5432) to the internet.",
    "Resource Type": "AWS::EC2::SecurityGroup"
}

##############################################################################
# PR-AWS-CLD-SG-030 - Database Ports Exposed to Internet
##############################################################################

default db_exposed = null

db_ports := [
    1433,  # SQL Server
    1521,  # Oracle
    3306,  # MySQL
    5000,  # Sybase
    5432,  # PostgreSQL
    5984,  # CouchDB
    6379,  # Redis
    6380,  # Redis SSL
    8080,  # RethinkDB
    9042,  # Cassandra
    11211, # Memcached
    27017, # MongoDB
    28015, # RethinkDB
    29015, # RethinkDB
    50000  # DB2
]

db_exposed_resource_exists {
    security_groups_exist
}

aws_issue["db_exposed"] {
    security_groups_exist
    sg := input.SecurityGroups[_]
    ingress := sg.IpPermissions[_]
    ingress.IpRanges[_].CidrIp == "0.0.0.0/0"
    port := db_ports[_]
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

aws_issue["db_exposed"] {
    security_groups_exist
    sg := input.SecurityGroups[_]
    ingress := sg.IpPermissions[_]
    ingress.Ipv6Ranges[_].CidrIpv6 == "::/0"
    port := db_ports[_]
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

db_exposed {
    db_exposed_resource_exists
    not aws_issue["db_exposed"]
}

db_exposed = false {
    db_exposed_resource_exists
    aws_issue["db_exposed"]
}

db_exposed_err = "Publicly exposed DB Ports" {
    aws_issue["db_exposed"]
}

db_exposed_skip_reason = msg {
    not db_exposed_resource_exists
    msg := "No Security Groups found in the evaluated scope"
}

db_exposed_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-030",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Publicly exposed DB Ports",
    "Policy Description": "DB Servers contain sensitive data and should not be exposed to direct internet traffic.",
    "Resource Type": "AWS::EC2::SecurityGroup"
}

##############################################################################
# PR-AWS-CLD-SG-022 - Security Group Missing Tags
##############################################################################

default sg_tag = null

sg_tag_resource_exists {
    security_groups_exist
}

aws_issue["sg_tag"] {
    security_groups_exist
    sg := input.SecurityGroups[_]
    not sg.Tags
}

aws_issue["sg_tag"] {
    security_groups_exist
    sg := input.SecurityGroups[_]
    count(sg.Tags) == 0
}

sg_tag {
    sg_tag_resource_exists
    not aws_issue["sg_tag"]
}

sg_tag = false {
    sg_tag_resource_exists
    aws_issue["sg_tag"]
}

sg_tag_err = "Ensure AWS resources that support tags have Tags" {
    aws_issue["sg_tag"]
}

sg_tag_skip_reason = msg {
    not sg_tag_resource_exists
    msg := "No Security Groups found in the evaluated scope"
}

sg_tag_metadata := {
    "Policy Code": "PR-AWS-CLD-SG-022",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure AWS resources that support tags have Tags",
    "Policy Description": "Tags allow you to add metadata to resources for cost analysis and resource management.",
    "Resource Type": "AWS::EC2::SecurityGroup"
}
