package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/firewalls

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

#
# PR-GCP-CLD-FW-001
#

default firewall_default = null


gc_attribute_absence["firewall_default"] {
    # lower(resource.type) == "compute.v1.firewall"
    not input.name
}

gc_issue["firewall_default"] {
    # lower(resource.type) == "compute.v1.firewall"
    lower(input.name) == "default-allow-ssh"
    input.sourceRanges[j] == "0.0.0.0/0"
}

gc_issue["firewall_default"] {
    # lower(resource.type) == "compute.v1.firewall"
    lower(input.name) == "default-allow-icmp"
    input.sourceRanges[j] == "0.0.0.0/0"
}

gc_issue["firewall_default"] {
    # lower(resource.type) == "compute.v1.firewall"
    lower(input.name) == "default-allow-internal"
    input.sourceRanges[j] == "0.0.0.0/0"
}

gc_issue["firewall_default"] {
    # lower(resource.type) == "compute.v1.firewall"
    lower(input.name) == "default-allow-rdp"
    input.sourceRanges[j] == "0.0.0.0/0"
}

firewall_default {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_default"]
    not gc_attribute_absence["firewall_default"]
}

firewall_default = false {
    gc_issue["firewall_default"]
}

firewall_default = false {
    gc_attribute_absence["firewall_default"]
}

firewall_default_err = "Default Firewall rule should not have any rules (except http and https)" {
    gc_issue["firewall_default"]
} else = "GCP vm firewall attribute name missing in the resource" {
    gc_attribute_absence["firewall_default"]
}

firewall_default_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Default Firewall rule should not have any rules (except http and https)",
    "Policy Description": "Checks to ensure that the default Firewall rule should not have any (non http, https) rules. The default Firewall rules will apply all instances by default in the absence of specific custom rules with higher priority. It is a safe practice to not have these rules in the default Firewall.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-002
#

default firewall_port_53 = null

gc_issue["firewall_port_53"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "53"
}

gc_issue["firewall_port_53"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 53
    to_number(port_range[1]) >= 53
}

gc_issue["firewall_port_53"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[k]
    count(allow.ports[l]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_53"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[k]
    count(allow.ports[l]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_53 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_53"]
}

firewall_port_53 = false {
    gc_issue["firewall_port_53"]
}

firewall_port_53_err = "GCP Firewall rule allows internet traffic to DNS port (53)" {
    gc_issue["firewall_port_53"]
}

firewall_port_53_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to DNS port (53)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on DNS port (53) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-003
#

default firewall_port_21 = null

gc_issue["firewall_port_21"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "21"
}

gc_issue["firewall_port_21"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 21
    to_number(port_range[1]) >= 21
}

gc_issue["firewall_port_21"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_21"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_21 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_21"]
}

firewall_port_21 = false {
    gc_issue["firewall_port_21"]
}

firewall_port_21_err = "GCP Firewall rule allows internet traffic to FTP port (21)" {
    gc_issue["firewall_port_21"]
}

firewall_port_21_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to FTP port (21)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on FTP port (21) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-004
#

default firewall_port_80 = null

gc_issue["firewall_port_80"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "80"
}

gc_issue["firewall_port_80"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 80
    to_number(port_range[1]) >= 80
}

gc_issue["firewall_port_80"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_80"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_80 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_80"]
}

firewall_port_80 = false {
    gc_issue["firewall_port_80"]
}

firewall_port_80_err = "GCP Firewall rule allows internet traffic to HTTP port (80)" {
    gc_issue["firewall_port_80"]
}

firewall_port_80_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to HTTP port (80)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on HTTP port (80) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-005
#

default firewall_port_445 = null

gc_issue["firewall_port_445"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "445"
}

gc_issue["firewall_port_445"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 445
    to_number(port_range[1]) >= 445
}

gc_issue["firewall_port_445"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_445"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_445 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_445"]
}

firewall_port_445 = false {
    gc_issue["firewall_port_445"]
}

firewall_port_445_err = "GCP Firewall rule allows internet traffic to Microsoft-DS port (445)" {
    gc_issue["firewall_port_445"]
}

firewall_port_445_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to Microsoft-DS port (445)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on Microsoft-DS port (445) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-006
#

default firewall_port_27017 = null

gc_issue["firewall_port_27017"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "27017"
}

gc_issue["firewall_port_27017"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 27017
    to_number(port_range[1]) >= 27017
}

gc_issue["firewall_port_27017"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_27017"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_27017 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_27017"]
}

firewall_port_27017 = false {
    gc_issue["firewall_port_27017"]
}

firewall_port_27017_err = "GCP Firewall rule allows internet traffic to MongoDB port (27017)" {
    gc_issue["firewall_port_27017"]
}

firewall_port_27017_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to MongoDB port (27017)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on MongoDB port (27017) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-007
#

default firewall_port_3306 = null

gc_issue["firewall_port_3306"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "3306"
}

gc_issue["firewall_port_3306"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 3306
    to_number(port_range[1]) >= 3306
}

gc_issue["firewall_port_3306"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_3306"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_3306 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_3306"]
}

firewall_port_3306 = false {
    gc_issue["firewall_port_3306"]
}

firewall_port_3306_err = "GCP Firewall rule allows internet traffic to MySQL DB port (3306)" {
    gc_issue["firewall_port_3306"]
}

firewall_port_3306_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to MySQL DB port (3306)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on MySQL DB port (3306) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-008
#

default firewall_port_139 = null

gc_issue["firewall_port_139"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "139"
}

gc_issue["firewall_port_139"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 139
    to_number(port_range[1]) >= 139
}

gc_issue["firewall_port_139"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_139"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_139 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_139"]
}

firewall_port_139 = false {
    gc_issue["firewall_port_139"]
}

firewall_port_139_err = "GCP Firewall rule allows internet traffic to NetBIOS-SSN port (139)" {
    gc_issue["firewall_port_139"]
}

firewall_port_139_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to NetBIOS-SSN port (139)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on NetBIOS-SSN port (139) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-009
#

default firewall_port_1521 = null

gc_issue["firewall_port_1521"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "1521"
}

gc_issue["firewall_port_1521"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 1521
    to_number(port_range[1]) >= 1521
}

gc_issue["firewall_port_1521"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_1521"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_1521 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_1521"]
}

firewall_port_1521 = false {
    gc_issue["firewall_port_1521"]
}

firewall_port_1521_err = "GCP Firewall rule allows internet traffic to Oracle DB port (1521)" {
    gc_issue["firewall_port_1521"]
}

firewall_port_1521_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-009",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to Oracle DB port (1521)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on Oracle DB port (1521) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-010
#

default firewall_port_110 = null

gc_issue["firewall_port_110"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "110"
}

gc_issue["firewall_port_110"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 110
    to_number(port_range[1]) >= 110
}

gc_issue["firewall_port_110"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_110"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_110 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_110"]
}

firewall_port_110 = false {
    gc_issue["firewall_port_110"]
}

firewall_port_110_err = "GCP Firewall rule allows internet traffic to POP3 port (110)" {
    gc_issue["firewall_port_110"]
}

firewall_port_110_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-010",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to POP3 port (110)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on POP3 port (110) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-011
#

default firewall_port_5432 = null

gc_issue["firewall_port_5432"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "5432"
}

gc_issue["firewall_port_5432"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 5432
    to_number(port_range[1]) >= 5432
}

gc_issue["firewall_port_5432"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_5432"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_5432 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_5432"]
}

firewall_port_5432 = false {
    gc_issue["firewall_port_5432"]
}

firewall_port_5432_err = "GCP Firewall rule allows internet traffic to PostgreSQL port (5432)" {
    gc_issue["firewall_port_5432"]
}

firewall_port_5432_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-011",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to PostgreSQL port (5432)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on PostgreSQL port (5432) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-012
#

default firewall_port_3389 = null

gc_issue["firewall_port_3389"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "3389"
}

gc_issue["firewall_port_3389"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 3389
    to_number(port_range[1]) >= 3389
}

gc_issue["firewall_port_3389"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_3389"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_3389 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_3389"]
}

firewall_port_3389 = false {
    gc_issue["firewall_port_3389"]
}

firewall_port_3389_err = "GCP Firewall rule allows internet traffic to RDP port (3389)" {
    gc_issue["firewall_port_3389"]
}

firewall_port_3389_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-012",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to RDP port (3389)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on RDP port (3389) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-013
#

default firewall_port_25 = null

gc_issue["firewall_port_25"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "25"
}

gc_issue["firewall_port_25"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 25
    to_number(port_range[1]) >= 25
}

gc_issue["firewall_port_25"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_25"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_25 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_25"]
}

firewall_port_25 = false {
    gc_issue["firewall_port_25"]
}

firewall_port_25_err = "GCP Firewall rule allows internet traffic to SMTP port (25)" {
    gc_issue["firewall_port_25"]
}

firewall_port_25_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-013",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to SMTP port (25)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on SMTP port (25) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-014
#

default firewall_port_22 = null

gc_issue["firewall_port_22"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "22"
}

gc_issue["firewall_port_22"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 22
    to_number(port_range[1]) >= 22
}

gc_issue["firewall_port_22"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_22"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_22 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_22"]
}

firewall_port_22 = false {
    gc_issue["firewall_port_22"]
}

firewall_port_22_err = "GCP Firewall rule allows internet traffic to SSH port (22)" {
    gc_issue["firewall_port_22"]
}

firewall_port_22_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-014",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to SSH port (22)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on SSH port (22) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-015
#

default firewall_port_23 = null

gc_issue["firewall_port_23"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    allow.ports[_] == "23"
}

gc_issue["firewall_port_23"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 23
    to_number(port_range[1]) >= 23
}

gc_issue["firewall_port_23"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_23"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    allow := input.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_23 {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_23"]
}

firewall_port_23 = false {
    gc_issue["firewall_port_23"]
}

firewall_port_23_err = "GCP Firewall rule allows internet traffic to Telnet port (23)" {
    gc_issue["firewall_port_23"]
}

firewall_port_23_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-015",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rule allows internet traffic to Telnet port (23)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on Telnet port (23) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-016
#

default firewall_inbound = null

gc_issue["firewall_inbound"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    lower(input.direction) != "egress"
    not input.targetTags
    not input.targetServiceAccounts
}

gc_issue["firewall_inbound"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    not input.direction
    not input.targetTags
    not input.targetServiceAccounts
}

firewall_inbound {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_inbound"]
}

firewall_inbound = false {
    gc_issue["firewall_inbound"]
}

firewall_inbound_err = "GCP Firewall rules allow inbound traffic from anywhere with no target tags set" {
    gc_issue["firewall_inbound"]
}

firewall_inbound_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-016",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall rules allow inbound traffic from anywhere with no target tags set",
    "Policy Description": "This policy identifies GCP Firewall rules which allow inbound traffic from anywhere with no target filtering. The default target is all instances in the network. The use of target tags or target service accounts allows the rule to apply to select instances. Not using any firewall rule filtering may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-CLD-FW-017
#

default firewall_inbound_all = null

gc_issue["firewall_inbound_all"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.sourceRanges[j] == "0.0.0.0/0"
    lower(input.allowed[_].IPProtocol) == "all"
}

firewall_inbound_all {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_inbound_all"]
}

firewall_inbound_all = false {
    gc_issue["firewall_inbound_all"]
}

firewall_inbound_all_err = "GCP Firewall with Inbound rule overly permissive to All Traffic" {
    gc_issue["firewall_inbound_all"]
}

firewall_inbound_all_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-017",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Firewall with Inbound rule overly permissive to All Traffic",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}


#
# PR-GCP-CLD-FW-018
#

default firewall_logging = null

gc_issue["firewall_logging"] {
    # lower(resource.type) == "compute.v1.firewall"
    not input.logConfig
}

gc_issue["firewall_logging"] {
    # lower(resource.type) == "compute.v1.firewall"
    input.logConfig.enable == false
}

gc_issue["firewall_logging"] {
    # lower(resource.type) == "compute.v1.firewall"
    lower(input.logConfig.enable) == "false"
}

firewall_logging {
    # lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_logging"]
}

firewall_logging = false {
    gc_issue["firewall_logging"]
}

firewall_logging_err = "Ensure GCP Firewall rule logging is enabled" {
    gc_issue["firewall_logging"]
}

firewall_logging_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-018",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP Firewall rule logging is enabled",
    "Policy Description": "This policy identifies GCP firewall rules that are not configured with firewall rule logging.  Firewall Rules Logging lets you audit, verify, and analyze the effects of your firewall rules. When you enable logging for a firewall rule, Google Cloud creates an entry called a connection record each time the rule allows or denies traffic. \n\nReference: https://cloud.google.com/vpc/docs/firewall-rules-logging",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}



#
# PR-GCP-CLD-FW-019
#

default overlly_permissive_traffic = null

gc_issue["overlly_permissive_traffic"]{
    Y := input.GOOGLE_FIREWALL[i]
    X := input.GOOGLE_CLUSTER[j]
    contains(Y.network, X.network)
    contains(Y.sourceRanges[_], "0.0.0.0/0")
    contains(Y.direction, "INGRESS")
    count(input.GOOGLE_FIREWALL[_].allowed[i]) > 0 
}

overlly_permissive_traffic {
    not gc_issue["overlly_permissive_traffic"]
}
overlly_permissive_traffic = false {
    gc_issue["overlly_permissive_traffic"]
}

overlly_permissive_traffic_err = "Ensure GCP Kubernetes Engine Clusters network firewall inbound rule overly permissive to all traffic." {
    gc_issue["overlly_permissive_traffic"]
}

overlly_permissive_traffic_metadata := {
    "Policy Code": "PR-GCP-CLD-FW-019",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP Kubernetes Engine Clusters network firewall inbound rule overly permissive to all traffic.",
    "Policy Description": "This policy checks Firewall rules attached to the cluster network which allows inbound traffic on all protocols from the public internet. Doing so may allow a bad actor to brute force their way into the system and potentially get access to the entire cluster network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters"
}


#
# PR-GCP-CLD-DISK-001
#

default disk_encrypt = null

gc_issue["disk_encrypt"] {
    # lower(resource.type) == "compute.v1.disk"
    not input.diskEncryptionKey
}

disk_encrypt {
    # lower(input.resources[i].type) == "compute.v1.disk"
    not gc_issue["disk_encrypt"]
}

disk_encrypt = false {
    gc_issue["disk_encrypt"]
}

disk_encrypt_err = "GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)" {
    gc_issue["disk_encrypt"]
}

disk_encrypt_metadata := {
    "Policy Code": "PR-GCP-CLD-DISK-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)",
    "Policy Description": "This policy identifies VM disks which are not encrypted with Customer-Supplied Encryption Keys (CSEK). If you provide your own encryption keys, Compute Engine uses your key to protect the Google-generated keys used to encrypt and decrypt your data. It is recommended to use VM disks encrypted with CSEK for business-critical VM instances.",
    "Resource Type": "compute.v1.disk",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/disks"
}


# https://cloud.google.com/compute/docs/reference/rest/v1/instances

#
# PR-GCP-CLD-INST-001
#

default vm_ip_forward = null

gc_issue["vm_ip_forward"] {
    # lower(resource.type) == "compute.v1.instance"
    input.canIpForward
}

vm_ip_forward {
    # lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_ip_forward"]
}

vm_ip_forward = false {
    gc_issue["vm_ip_forward"]
}

vm_ip_forward_err = "GCP VM instances have IP forwarding enabled" {
    gc_issue["vm_ip_forward"]
}

vm_ip_forward_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP VM instances have IP forwarding enabled",
    "Policy Description": "This policy identifies VM instances have IP forwarding enabled. IP Forwarding could open unintended and undesirable communication paths and allows VM instances to send and receive packets with the non-matching destination or source IPs. To enable source and destination IP match check, disable the IP Forwarding.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-CLD-INST-002
#

default vm_block_project_ssh_keys = null

gc_issue["vm_block_project_ssh_keys"] {
    # lower(resource.type) == "compute.v1.instance"
    count([c | contains(lower(input.metadata.items[_].key), "block-project-ssh-keys"); c := 1]) == 0
}

vm_block_project_ssh_keys {
    # lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_block_project_ssh_keys"]
}

vm_block_project_ssh_keys = false {
    gc_issue["vm_block_project_ssh_keys"]
}

vm_block_project_ssh_keys_err = "GCP VM instances have block project-wide SSH keys feature disabled" {
    gc_issue["vm_block_project_ssh_keys"]
}

vm_block_project_ssh_keys_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP VM instances have block project-wide SSH keys feature disabled",
    "Policy Description": "This policy identifies VM instances which have block project-wide SSH keys feature disabled. Project-wide SSH keys are stored in Compute/Project-metadata. Project-wide SSH keys can be used to login into all the instances within a project. Using project-wide SSH keys eases the SSH key management but if compromised, poses the security risk which can impact all the instances within a project. It is recommended to use Instance specific SSH keys which can limit the attack surface if the SSH keys are compromised.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-CLD-INST-003
#

default vm_serial_port = null

gc_issue["vm_serial_port"] {
    # lower(resource.type) == "compute.v1.instance"
    items := input.metadata.items[_]
    contains(lower(items.key), "serial-port-enable")
    lower(items.value) == "true"
}

gc_issue["vm_serial_port"] {
    # lower(resource.type) == "compute.v1.instance"
    items := input.metadata.items[_]
    contains(lower(items.key), "serial-port-enable")
    items.value == true
}

vm_serial_port {
    # lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_serial_port"]
}

vm_serial_port = false {
    gc_issue["vm_serial_port"]
}

vm_serial_port_err = "GCP VM instances have serial port access enabled" {
    gc_issue["vm_serial_port"]
}

vm_serial_port_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP VM instances have serial port access enabled",
    "Policy Description": "This policy identifies VM instances which have serial port access enabled. Interacting with a serial port is often referred to as the serial console. The interactive serial console does not support IP-based access restrictions such as IP whitelists. If you enable the interactive serial console on an instance, clients can attempt to connect to that instance from any IP address. So it is recommended to keep interactive serial console support disabled.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-CLD-INST-004
#

default vm_pre_emptible = null

gc_issue["vm_pre_emptible"] {
    # lower(resource.type) == "compute.v1.instance"
    input.scheduling.preemptible == true
}

vm_pre_emptible {
    # lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_pre_emptible"]
}

vm_pre_emptible = false {
    gc_issue["vm_pre_emptible"]
}

vm_pre_emptible_err = "VM Instances enabled with Pre-Emptible termination" {
    gc_issue["vm_pre_emptible"]
}

vm_pre_emptible_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "VM Instances enabled with Pre-Emptible termination",
    "Policy Description": "Checks to verify if any VM instance is initiated with the flag 'Pre-Emptible termination' set to True. Setting this instance to True implies that this VM instance will shut down within 24 hours or can also be terminated by a Service Engine when high demand is encountered. While this might save costs, it can also lead to unexpected loss of service when the VM instance is terminated.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-CLD-INST-005
#

default vm_metadata = null

gc_issue["vm_metadata"] {
    # lower(resource.type) == "compute.v1.instance"
    not input.metadata.items
}

gc_issue["vm_metadata"] {
    # lower(resource.type) == "compute.v1.instance"
    count(input.metadata.items) == 0
}

vm_metadata {
    # lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_metadata"]
}

vm_metadata = false {
    gc_issue["vm_metadata"]
}

vm_metadata_err = "VM Instances without any Custom metadata information" {
    gc_issue["vm_metadata"]
}

vm_metadata_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "VM Instances without any Custom metadata information",
    "Policy Description": "VM instance does not have any Custom metadata. Custom metadata can be used for easy identification and searches.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-CLD-INST-006
#

default vm_no_labels = null

gc_issue["vm_no_labels"] {
    # lower(resource.type) == "compute.v1.instance"
    not input.labels
}

gc_issue["vm_no_labels"] {
    # lower(resource.type) == "compute.v1.instance"
    count(input.labels) == 0
}

vm_no_labels {
    # lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_no_labels"]
}

vm_no_labels = false {
    gc_issue["vm_no_labels"]
}

vm_no_labels_err = "VM Instances without any Label information" {
    gc_issue["vm_no_labels"]
}

vm_no_labels_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "VM Instances without any Label information",
    "Policy Description": "VM instance does not have any Labels. Labels can be used for easy identification and searches.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-CLD-INST-007
#

default vm_info = null

gc_issue["vm_info"] {
    # lower(resource.type) == "compute.v1.instance"
    not input.labels
}

gc_issue["vm_info"] {
    # lower(resource.type) == "compute.v1.instance"
    count(input.labels) == 0
}

gc_issue["vm_info"] {
    # lower(resource.type) == "compute.v1.instance"
    not input.metadata.items
}

gc_issue["vm_info"] {
    # lower(resource.type) == "compute.v1.instance"
    count(input.metadata.items) == 0
}

gc_issue["vm_info"] {
    # lower(resource.type) == "compute.v1.instance"
    not input.zone
}

vm_info {
    # lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_info"]
}

vm_info = false {
    gc_issue["vm_info"]
}

vm_info_err = "VM instances without metadata, zone or label information" {
    gc_issue["vm_info"]
}

vm_info_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "VM instances without metadata, zone or label information",
    "Policy Description": "Checks to ensure that VM instances have proper metadata, zone and label information tags. These tags can be used for easier identification and searches.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-CLD-INST-008
#

default compute_disk_csek = null

gc_issue["compute_disk_csek"] {
    # lower(resource.type) == "compute.v1.instance"
    disks := input.disks[_]
    not disks.sourceSnapshotEncryptionKey.sha256
}

gc_issue["compute_disk_csek"] {
    # lower(resource.type) == "compute.v1.instance"
    disks := input.disks[_]
    count(disks.sourceSnapshotEncryptionKey.sha256) == 0
}

gc_issue["compute_disk_csek"] {
    # lower(resource.type) == "compute.v1.instance"
    disks := input.disks[_]
    disks.sourceSnapshotEncryptionKey.sha256 == null
}

compute_disk_csek {
    # lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["compute_disk_csek"]
}

compute_disk_csek = false {
    gc_issue["compute_disk_csek"]
}

compute_disk_csek_err = "Ensure GCP GCE Disk snapshot is encrypted with CSEK" {
    gc_issue["compute_disk_csek"]
}

compute_disk_csek_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP GCE Disk snapshot is encrypted with CSEK",
    "Policy Description": "This policy identifies GCP GCE Disk snapshots that are not encrypted with CSEK. It is recommended that to avoid data leakage provide your own encryption keys, Compute Engine uses your key to protect the Google-generated keys used to encrypt and decrypt your data. Only users who can provide the correct key can use resources protected by a customer-supplied encryption key",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-CLD-INST-009
#

default compute_ssl_profile_restricted = null

gc_issue["compute_ssl_profile_restricted"] {
    # lower(resource.type) == "compute.v1.sslPolicies"
    lower(input.profile) != "custom"
    lower(input.profile) != "restricted"
}

compute_ssl_profile_restricted {
    # lower(input.resources[i].type) == "compute.v1.sslPolicies"
    not gc_issue["compute_ssl_profile_restricted"]
}

compute_ssl_profile_restricted = false {
    gc_issue["compute_ssl_profile_restricted"]
}

compute_ssl_profile_restricted_err = "Ensure GCP HTTPS Load balancer SSL Policy is using restrictive profile" {
    gc_issue["compute_ssl_profile_restricted"]
}

compute_ssl_profile_restricted_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-009",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP HTTPS Load balancer SSL Policy is using restrictive profile",
    "Policy Description": "This policy identifies HTTPS Load balancers which are not using restrictive profile in it's SSL Policy, which controls sets of features used in negotiating SSL with clients. As a best security practice, use RESTRICTED as SSL policy profile as it meets stricter compliance requirements and does not include any out-of-date SSL features.",
    "Resource Type": "compute.v1.sslPolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-CLD-INST-010
#

deprecated_min_tls_version = ["tls_1_0", "tls_1_1"]

default compute_ssl_min_tls = null

gc_issue["compute_ssl_min_tls"] {
    # lower(resource.type) == "compute.v1.sslPolicies"
    lower(input.minTlsVersion) == deprecated_min_tls_version[_]
}

compute_ssl_min_tls {
    # lower(input.resources[i].type) == "compute.v1.sslPolicies"
    not gc_issue["compute_ssl_min_tls"]
}

compute_ssl_min_tls = false {
    gc_issue["compute_ssl_min_tls"]
}

compute_ssl_min_tls_err = "Ensure GCP HTTPS Load balancer is configured with SSL policy not having TLS version 1.1 or lower" {
    gc_issue["compute_ssl_min_tls"]
}

compute_ssl_min_tls_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-010",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP HTTPS Load balancer is configured with SSL policy not having TLS version 1.1 or lower",
    "Policy Description": "This policy identifies HTTPS Load balancers is configured with SSL policy having TLS version 1.1 or lower. As a best security practice, use TLS 1.2 as the minimum TLS version in your load balancers SSL security policies.",
    "Resource Type": "compute.v1.sslPolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-CLD-INST-011
#

default compute_configure_default_service = null

gc_issue["compute_configure_default_service"] {
    # lower(resource.type) == "compute.v1.instance"
    lower(input.status) == "running"
    not startswith(lower(input.name), "gke-")
    serviceAccount := input.serviceAccounts[_]
    contains(lower(serviceAccount.email), "compute@developer.gserviceaccount.com")
}

compute_configure_default_service {
    # lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["compute_configure_default_service"]
}

compute_configure_default_service = false {
    gc_issue["compute_configure_default_service"]
}

compute_configure_default_service_err = "Ensure GCP VM instance not configured with default service account" {
    gc_issue["compute_configure_default_service"]
}

compute_configure_default_service_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-011",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP VM instance not configured with default service account",
    "Policy Description": "This policy identifies GCP VM instances configured with the default service account. To defend against privilege escalations if your VM is compromised and prevent an attacker from gaining access to all of your project, it is recommended to not use the default Compute Engine service account because it has the Editor role on the project.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-CLD-INST-012
#

default compute_default_service_full_access = null

gc_issue["compute_default_service_full_access"] {
    # lower(resource.type) == "compute.v1.instance"
    lower(input.status) == "running"
    not startswith(lower(input.name), "gke-")
    serviceAccount := input.serviceAccounts[_]
    contains(lower(serviceAccount.email), "compute@developer.gserviceaccount.com")
    lower(serviceAccount.scopes) == "https://www.googleapis.com/auth/cloud-platform"
}

compute_default_service_full_access {
    # lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["compute_default_service_full_access"]
}

compute_default_service_full_access = false {
    gc_issue["compute_default_service_full_access"]
}

compute_default_service_full_access_err = "Ensure GCP VM instance not using a default service account with full access to all Cloud APIs" {
    gc_issue["compute_default_service_full_access"]
}

compute_default_service_full_access_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-012",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP VM instance not using a default service account with full access to all Cloud APIs",
    "Policy Description": "This policy identifies the GCP VM instances which are using a default service account with full access to all Cloud APIs. To compliant with the principle of least privileges and prevent potential privilege escalation it is recommended that instances are not assigned to default service account 'Compute Engine default service account' with scope 'Allow full access to all Cloud APIs'.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-CLD-INST-013
#

default compute_shielded_vm = null

gc_issue["compute_shielded_vm"] {
    # lower(resource.type) == "compute.v1.instance"
    lower(input.status) == "running"
    not startswith(lower(input.name), "gke-")
    input.shieldedInstanceConfig
    not input.shieldedInstanceConfig.enableVtpm
}

gc_issue["compute_shielded_vm"] {
    # lower(resource.type) == "compute.v1.instance"
    lower(input.status) == "running"
    not startswith(lower(input.name), "gke-")
    input.shieldedInstanceConfig
    not input.shieldedInstanceConfig.enableIntegrityMonitoring
}

compute_shielded_vm {
    # lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["compute_shielded_vm"]
}

compute_shielded_vm = false {
    gc_issue["compute_shielded_vm"]
}

compute_shielded_vm_err = "Ensure GCP VM instance with Shielded VM features enabled" {
    gc_issue["compute_shielded_vm"]
}

compute_shielded_vm_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-013",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP VM instance with Shielded VM features enabled",
    "Policy Description": "This policy identifies VM instances which have Shielded VM features disabled. Shielded VMs are virtual machines (VMs) on Google Cloud Platform hardened by a set of security controls that help defend against rootkits and bootkits. Shielded VM's verifiable integrity is achieved through the use of Secure Boot, virtual trusted platform module (vTPM)-enabled Measured Boot, and integrity monitoring. Shielded VM instances run firmware which is signed and verified using Google's Certificate Authority, ensuring that the instance's firmware is unmodified and establishing the root of trust for Secure Boot.\n\nNOTE: You can only enable Shielded VM options on instances that have Shielded VM support. This policy reports VM instances that have Shielded VM support and are disabled with the Shielded VM features.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-CLD-INST-014
#

default compute_instance_external_ip = null

gc_issue["compute_instance_external_ip"] {
    # lower(resource.type) == "compute.v1.instance"
    lower(input.status) == "running"
    networkInterface := input.networkInterfaces[_]
    has_property(networkInterface, "accessConfigs")
    not startswith(lower(input.name), "gke-")
    not contains(lower(input.name), "default-pool")
}

compute_instance_external_ip {
    # lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["compute_instance_external_ip"]
}

compute_instance_external_ip = false {
    gc_issue["compute_instance_external_ip"]
}

compute_instance_external_ip_err = "Ensure GCP VM instance not have the external IP address" {
    gc_issue["compute_instance_external_ip"]
}

compute_instance_external_ip_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-014",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP VM instance not have the external IP address",
    "Policy Description": "This policy identifies the VM instances with the external IP address associated. To reduce your attack surface, VM instances should not have public/external IP addresses. Instead, instances should be configured behind load balancers, to minimize the instance's exposure to the internet.\n\nNOTE: This policy will not report instances created by GKE because some of them have external IP addresses and cannot be changed by editing the instance settings. Instances created by GKE should be excluded. These instances have names that start with 'gke-' and contains 'default-pool'.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-CLD-INST-015
#

default compute_ip_forwarding_enable = null

gc_issue["compute_ip_forwarding_enable"] {
    # lower(resource.type) == "compute.v1.instance"
    lower(input.status) == "running"
    input.canIpForward == true
    not startswith(lower(input.name), "gke-")
}

compute_ip_forwarding_enable {
    # lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["compute_ip_forwarding_enable"]
}

compute_ip_forwarding_enable = false {
    gc_issue["compute_ip_forwarding_enable"]
}

compute_ip_forwarding_enable_err = "Ensure GCP VM instances have IP Forwarding enabled." {
    gc_issue["compute_ip_forwarding_enable"]
}

compute_ip_forwarding_enable_metadata := {
    "Policy Code": "PR-GCP-CLD-INST-015",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure GCP VM instances have IP Forwarding enabled.",
    "Policy Description": "This policy checks VM instances that have IP Forwarding enabled. IP Forwarding could open unintended and undesirable communication paths and allows VM instances to send and receive packets with the non-matching destination or source IPs. To enable the source and destination IP match check, disable IP Forwarding.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}


#
# PR-GCP-CLD-SCP-001
#

default armor_not_config_with_cve = null

gc_issue["armor_not_config_with_cve"] {
    rule := input.rules[_].match.expr
    not contains(rule.expression, "cve-canary")
}

gc_issue["armor_not_config_with_cve"] {
    has_property(input, "rules")
    rule := input.rules[_]
    contains(rule.match.expr.expression, "cve-canary")
    rule.action == "allow"
}

armor_not_config_with_cve {
    not gc_issue["armor_not_config_with_cve"]
}

armor_not_config_with_cve = false {
    gc_issue["armor_not_config_with_cve"]
}

armor_not_config_with_cve_err = "Ensure, GCP Cloud Armor policy not configured with cve-canary rule." {
    gc_issue["armor_not_config_with_cve"]
}

armor_not_config_with_cve_metadata := {
    "Policy Code": "PR-GCP-CLD-SCP-001",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "Ensure, GCP Cloud Armor policy not configured with cve-canary rule.",
    "Policy Description": "This policy identifies GCP Cloud Armor rules where cve-canary is not enabled. Preconfigured WAF rule called 'cve-canary' can help detect and block exploit attempts of CVE-2021-44228 and CVE-2021-45046 to address the Apache Log4j vulnerability. It is recommended to create a Cloud Armor security policy with rule blocking Apache Log4j exploit attempts. Reference : https://cloud.google.com/blog/products/identity-security/cloud-armor-waf-rule-to-help-address-apache-log4j-vulnerability",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/securityPolicies"
}


#
# PR-GCP-CLD-NET-001
#

default net_legacy = null

gc_issue["net_legacy"] {
    # lower(resource.type) == "compute.v1.network"
    not input.autoCreateSubnetworks
}

net_legacy {
    # lower(input.resources[i].type) == "compute.v1.network"
    not gc_issue["net_legacy"]
}

net_legacy = false {
    gc_issue["net_legacy"]
}

net_legacy_err = "GCP project is configured with legacy network" {
    gc_issue["net_legacy"]
}

net_legacy_metadata := {
    "Policy Code": "PR-GCP-CLD-NET-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP project is configured with legacy network",
    "Policy Description": "This policy identifies the projects which have configured with legacy networks. Legacy networks have a single network IPv4 prefix range and a single gateway IP address for the whole network. Subnetworks cannot be created in a legacy network. Legacy networks can have an impact on high network traffic projects and subject to the single point of failure.",
    "Resource Type": "compute.v1.network",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/networks"
}

#
# PR-GCP-CLD-NET-002
#

default net_default = null


gc_attribute_absence["net_default"] {
    # lower(resource.type) == "compute.v1.network"
    not input.name
}

gc_issue["net_default"] {
    # lower(resource.type) == "compute.v1.network"
    lower(input.name) == "default"
}

net_default {
    # lower(input.resources[i].type) == "compute.v1.network"
    not gc_issue["net_default"]
    not gc_attribute_absence["net_default"]
}

net_default = false {
    gc_issue["net_default"]
}

net_default = false {
    gc_attribute_absence["net_default"]
}

net_default_err = "GCP project is using the default network" {
    gc_issue["net_default"]
}

net_default_miss_err = "GCP network attribute name missing in the resource" {
    gc_attribute_absence["net_default"]
}

net_default_metadata := {
    "Policy Code": "PR-GCP-CLD-NET-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP project is using the default network",
    "Policy Description": "This policy identifies the projects which have default network configured. It is recommended to use network configuration based on your security and networking requirements, you should create your network and delete the default network.",
    "Resource Type": "compute.v1.network",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/networks"
}

#
# PR-GCP-CLD-SUBN-001
#

default vpc_flow_logs = null

gc_issue["vpc_flow_logs"] {
    # lower(resource.type) == "compute.v1.subnetwork"
    not input.enableFlowLogs
}

vpc_flow_logs {
    # lower(input.resources[i].type) == "compute.v1.subnetwork"
    not gc_issue["vpc_flow_logs"]
}

vpc_flow_logs = false {
    gc_issue["vpc_flow_logs"]
}

vpc_flow_logs_err = "GCP VPC Flow logs for the subnet is set to Off" {
    gc_issue["vpc_flow_logs"]
}

vpc_flow_logs_metadata := {
    "Policy Code": "PR-GCP-CLD-SUBN-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP VPC Flow logs for the subnet is set to Off",
    "Policy Description": "This policy identifies the subnets in VPC Network which have Flow logs disabled. It enables to capture information about the IP traffic going to and from network interfaces in VPC Subnets.",
    "Resource Type": "compute.v1.subnetwork",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks"
}

#
# PR-GCP-CLD-SUBN-002
#

default vpc_private_ip_google = null

gc_issue["vpc_private_ip_google"] {
    # lower(resource.type) == "compute.v1.subnetwork"
    not input.privateIpGoogleAccess
}

vpc_private_ip_google {
    # lower(input.resources[i].type) == "compute.v1.subnetwork"
    not gc_issue["vpc_private_ip_google"]
}

vpc_private_ip_google = false {
    gc_issue["vpc_private_ip_google"]
}

vpc_private_ip_google_err = "GCP VPC Network subnets have Private Google access disabled" {
    gc_issue["vpc_private_ip_google"]
}

vpc_private_ip_google_metadata := {
    "Policy Code": "PR-GCP-CLD-SUBN-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP VPC Network subnets have Private Google access disabled",
    "Policy Description": "This policy identifies GCP VPC Network subnets have disabled Private Google access. Private Google access enables virtual machine instances on a subnet to reach Google APIs and services using an internal IP address rather than an external IP address. Internal (private) IP addresses are internal to Google Cloud Platform and are not routable or reachable over the Internet. You can use Private Google access to allow VMs without Internet access to reach Google APIs, services, and properties that are accessible over HTTP/HTTPS.",
    "Resource Type": "compute.v1.subnetwork",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks"
}


#
# PR-GCP-CLD-THP-001
#

default lbs_ssl_policy = null

gc_issue["lbs_ssl_policy"] {
    # lower(resource.type) == "compute.v1.targethttpsproxy"
    not input.sslPolicy
}

gc_issue["lbs_ssl_policy"] {
    # lower(resource.type) == "compute.v1.targethttpsproxy"
    count(input.sslPolicy) == 0
}

gc_issue["lbs_ssl_policy"] {
    # lower(resource.type) == "compute.v1.targethttpsproxy"
    input.sslPolicy == null
}

lbs_ssl_policy {
    # lower(input.resources[i].type) == "compute.v1.targethttpsproxy"
    not gc_issue["lbs_ssl_policy"]
}

lbs_ssl_policy = false {
    gc_issue["lbs_ssl_policy"]
}

lbs_ssl_policy_err = "GCP Load balancer HTTPS target proxy configured with default SSL policy instead of custom SSL policy" {
    gc_issue["lbs_ssl_policy"]
}

lbs_ssl_policy_metadata := {
    "Policy Code": "PR-GCP-CLD-THP-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Load balancer HTTPS target proxy configured with default SSL policy instead of custom SSL policy",
    "Policy Description": "This policy identifies Load balancer HTTPS target proxies which are configured with default SSL Policy instead of custom SSL policy. It is a best practice to use custom SSL policy to access load balancers. It gives you closer control over SSL/TLS versions and ciphers.",
    "Resource Type": "compute.v1.targethttpsproxy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies"
}

#
# PR-GCP-CLD-THP-002
#

default lbs_quic = null

gc_attribute_absence["lbs_quic"] {
    # lower(resource.type) == "compute.v1.targethttpsproxy"
    not input.quicOverride
}

gc_issue["lbs_quic"] {
    # lower(resource.type) == "compute.v1.targethttpsproxy"
    lower(input.quicOverride) != "enable"
}

lbs_quic {
    # lower(input.resources[i].type) == "compute.v1.targethttpsproxy"
    not gc_issue["lbs_quic"]
    not gc_attribute_absence["lbs_quic"]
}

lbs_quic = false {
    gc_issue["lbs_quic"]
}

lbs_quic = false {
    gc_attribute_absence["lbs_quic"]
}

lbs_quic_err = "GCP Load balancer HTTPS target proxy is not configured with QUIC protocol" {
    gc_issue["lbs_quic"]
}

lbs_quic_miss_err = "GCP Load balancer attribute quicOverride missing in the resource" {
    gc_attribute_absence["lbs_quic"]
}

lbs_quic_metadata := {
    "Policy Code": "PR-GCP-CLD-THP-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP cloud",
    "Policy Title": "GCP Load balancer HTTPS target proxy is not configured with QUIC protocol",
    "Policy Description": "This policy identifies Load Balancer HTTPS target proxies which are not configured with QUIC protocol. Enabling QUIC protocol in load balancer target https proxies adds advantage by establishing connections faster, stream-based multiplexing, improved loss recovery, and eliminates head-of-line blocking.",
    "Resource Type": "compute.v1.targethttpsproxy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies"
}


#
# PR-GCP-CLD-CLR-001
#

default cld_run_with_over_permission_ingress = null

gc_attribute_absence["cld_run_with_over_permission_ingress"]{
    count([c | has_property(input.items[_].status, "conditions"); c=1]) == 0
}

gc_issue["cld_run_with_over_permission_ingress"]{
    lower(input.items[_].status.conditions[_].type) == "ready"
    lower(input.items[_].status.conditions[_].status) == "true"
    lower(input.items[_].status.conditions[_].type) == "routesready"
    lower(input.items[_].status.conditions[_].status) == "true"
    lower(input.items[_].metadata.annotations["run.googleapis.com/ingress"]) == "all"
}

cld_run_with_over_permission_ingress {
    not gc_issue["cld_run_with_over_permission_ingress"]
    not gc_attribute_absence["cld_run_with_over_permission_ingress"]
}

cld_run_with_over_permission_ingress = false {
    gc_issue["cld_run_with_over_permission_ingress"]
}

cld_run_with_over_permission_ingress = false {
    gc_attribute_absence["cld_run_with_over_permission_ingress"]
}

cld_run_with_over_permission_ingress_err = "Ensure, GCP Cloud Run service with overly permissive ingress rule." {
    gc_issue["cld_run_with_over_permission_ingress"]
}else = "Ensure, GCP Cloud Run service with overly permissive ingress rule."{
    gc_attribute_absence["cld_run_with_over_permission_ingress"]
}

cld_run_with_over_permission_ingress_metadata := {
    "Policy Code": "PR-GCP-CLD-CLR-001",
    "Type": "cloud",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Ensure, GCP Cloud Run service with overly permissive ingress rule.",
    "Policy Description": "This policy checks GCP Cloud Run services configured with overly permissive ingress rules. It is recommended to restrict the traffic from the internet and other resources by allowing traffic to enter through load balancers or internal traffic for better network-based access control.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/projects"
}