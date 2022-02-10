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
    "Policy Description": "This policy identifies GCP Firewall rules which allow inbound traffic from anywhere with no target filtering. _x005F_x000D_ _x005F_x000D_ The default target is all instances in the network. The use of target tags or target service accounts allows the rule to apply to select instances. Not using any firewall rule filtering may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
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
