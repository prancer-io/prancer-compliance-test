package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/firewalls

#
# PR-GCP-GDF-FW-001
#

default firewall_default = null


gc_attribute_absence["firewall_default"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    not resource.properties.name
}


source_path[{"firewall_default": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    not resource.properties.name
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "name"]
        ],
    }
}

gc_issue["firewall_default"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    lower(resource.properties.name) == "default-allow-ssh"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
}

source_path[{"firewall_default": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    lower(resource.properties.name) == "default-allow-ssh"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "sourceRanges", j]
        ],
    }
}

gc_issue["firewall_default"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    lower(resource.properties.name) == "default-allow-icmp"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
}

source_path[{"firewall_default": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    lower(resource.properties.name) == "default-allow-icmp"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "sourceRanges", j]
        ],
    }
}

gc_issue["firewall_default"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    lower(resource.properties.name) == "default-allow-internal"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
}

source_path[{"firewall_default": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    lower(resource.properties.name) == "default-allow-internal"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "sourceRanges", j]
        ],
    }
}

gc_issue["firewall_default"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    lower(resource.properties.name) == "default-allow-rdp"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
}

source_path[{"firewall_default": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    lower(resource.properties.name) == "default-allow-rdp"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "sourceRanges", j]
        ],
    }
}

firewall_default {
    lower(input.resources[i].type) == "compute.v1.firewall"
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
}

firewall_default_miss_err = "GCP vm firewall attribute name missing in the resource" {
    gc_attribute_absence["firewall_default"]
}

firewall_default_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "Default Firewall rule should not have any rules (except http and https)",
    "Policy Description": "Checks to ensure that the default Firewall rule should not have any (non http, https) rules. The default Firewall rules will apply all instances by default in the absence of specific custom rules with higher priority. It is a safe practice to not have these rules in the default Firewall.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-002
#

default firewall_port_53 = null

gc_issue["firewall_port_53"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "53"
}

source_path[{"firewall_port_53": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[k]
    allow.ports[l] == "53"
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "allowed", k, "ports", l]
        ],
    }
}

gc_issue["firewall_port_53"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 53
    to_number(port_range[1]) >= 53
}

source_path[{"firewall_port_53": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[k]
    port := allow.ports[l]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 53
    to_number(port_range[1]) >= 53
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "allowed", k, "ports", l]
        ],
    }
}

gc_issue["firewall_port_53"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[k]
    count(allow.ports[l]) < 1
    lower(allow.IPProtocol) == "tcp"
}

source_path[{"firewall_port_53": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[k]
    count(allow.ports[l]) < 1
    lower(allow.IPProtocol) == "tcp"
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "allowed", k, "IPProtocol"]
        ],
    }
}

gc_issue["firewall_port_53"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[k]
    count(allow.ports[l]) < 1
    lower(allow.IPProtocol) == "udp"
}

source_path[{"firewall_port_53": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[k]
    count(allow.ports[l]) < 1
    lower(allow.IPProtocol) == "udp"
    metadata := {
        "resource_path": [
            ["resources", i, "properties" "allowed", k, "IPProtocol"]
        ],
    }
}

firewall_port_53 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_53"]
}

firewall_port_53 = false {
    gc_issue["firewall_port_53"]
}

firewall_port_53_err = "GCP Firewall rule allows internet traffic to DNS port (53)" {
    gc_issue["firewall_port_53"]
}

firewall_port_53_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to DNS port (53)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on DNS port (53) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-003
#

default firewall_port_21 = null

gc_issue["firewall_port_21"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "21"
}

gc_issue["firewall_port_21"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 21
    to_number(port_range[1]) >= 21
}

gc_issue["firewall_port_21"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_21"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_21 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_21"]
}

firewall_port_21 = false {
    gc_issue["firewall_port_21"]
}

firewall_port_21_err = "GCP Firewall rule allows internet traffic to FTP port (21)" {
    gc_issue["firewall_port_21"]
}

firewall_port_21_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to FTP port (21)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on FTP port (21) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-004
#

default firewall_port_80 = null

gc_issue["firewall_port_80"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "80"
}

gc_issue["firewall_port_80"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 80
    to_number(port_range[1]) >= 80
}

gc_issue["firewall_port_80"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_80"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_80 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_80"]
}

firewall_port_80 = false {
    gc_issue["firewall_port_80"]
}

firewall_port_80_err = "GCP Firewall rule allows internet traffic to HTTP port (80)" {
    gc_issue["firewall_port_80"]
}

firewall_port_80_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to HTTP port (80)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on HTTP port (80) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-005
#

default firewall_port_445 = null

gc_issue["firewall_port_445"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "445"
}

gc_issue["firewall_port_445"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 445
    to_number(port_range[1]) >= 445
}

gc_issue["firewall_port_445"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_445"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_445 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_445"]
}

firewall_port_445 = false {
    gc_issue["firewall_port_445"]
}

firewall_port_445_err = "GCP Firewall rule allows internet traffic to Microsoft-DS port (445)" {
    gc_issue["firewall_port_445"]
}

firewall_port_445_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to Microsoft-DS port (445)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on Microsoft-DS port (445) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-006
#

default firewall_port_27017 = null

gc_issue["firewall_port_27017"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "27017"
}

gc_issue["firewall_port_27017"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 27017
    to_number(port_range[1]) >= 27017
}

gc_issue["firewall_port_27017"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_27017"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_27017 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_27017"]
}

firewall_port_27017 = false {
    gc_issue["firewall_port_27017"]
}

firewall_port_27017_err = "GCP Firewall rule allows internet traffic to MongoDB port (27017)" {
    gc_issue["firewall_port_27017"]
}

firewall_port_27017_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to MongoDB port (27017)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on MongoDB port (27017) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-007
#

default firewall_port_3306 = null

gc_issue["firewall_port_3306"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "3306"
}

gc_issue["firewall_port_3306"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 3306
    to_number(port_range[1]) >= 3306
}

gc_issue["firewall_port_3306"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_3306"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_3306 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_3306"]
}

firewall_port_3306 = false {
    gc_issue["firewall_port_3306"]
}

firewall_port_3306_err = "GCP Firewall rule allows internet traffic to MySQL DB port (3306)" {
    gc_issue["firewall_port_3306"]
}

firewall_port_3306_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to MySQL DB port (3306)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on MySQL DB port (3306) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-008
#

default firewall_port_139 = null

gc_issue["firewall_port_139"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "139"
}

gc_issue["firewall_port_139"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 139
    to_number(port_range[1]) >= 139
}

gc_issue["firewall_port_139"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_139"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_139 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_139"]
}

firewall_port_139 = false {
    gc_issue["firewall_port_139"]
}

firewall_port_139_err = "GCP Firewall rule allows internet traffic to NetBIOS-SSN port (139)" {
    gc_issue["firewall_port_139"]
}

firewall_port_139_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-008",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to NetBIOS-SSN port (139)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on NetBIOS-SSN port (139) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-009
#

default firewall_port_1521 = null

gc_issue["firewall_port_1521"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "1521"
}

gc_issue["firewall_port_1521"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 1521
    to_number(port_range[1]) >= 1521
}

gc_issue["firewall_port_1521"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_1521"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_1521 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_1521"]
}

firewall_port_1521 = false {
    gc_issue["firewall_port_1521"]
}

firewall_port_1521_err = "GCP Firewall rule allows internet traffic to Oracle DB port (1521)" {
    gc_issue["firewall_port_1521"]
}

firewall_port_1521_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-009",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to Oracle DB port (1521)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on Oracle DB port (1521) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-010
#

default firewall_port_110 = null

gc_issue["firewall_port_110"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "110"
}

gc_issue["firewall_port_110"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 110
    to_number(port_range[1]) >= 110
}

gc_issue["firewall_port_110"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_110"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_110 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_110"]
}

firewall_port_110 = false {
    gc_issue["firewall_port_110"]
}

firewall_port_110_err = "GCP Firewall rule allows internet traffic to POP3 port (110)" {
    gc_issue["firewall_port_110"]
}

firewall_port_110_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-010",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to POP3 port (110)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on POP3 port (110) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-011
#

default firewall_port_5432 = null

gc_issue["firewall_port_5432"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "5432"
}

gc_issue["firewall_port_5432"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 5432
    to_number(port_range[1]) >= 5432
}

gc_issue["firewall_port_5432"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_5432"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_5432 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_5432"]
}

firewall_port_5432 = false {
    gc_issue["firewall_port_5432"]
}

firewall_port_5432_err = "GCP Firewall rule allows internet traffic to PostgreSQL port (5432)" {
    gc_issue["firewall_port_5432"]
}

firewall_port_5432_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-011",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to PostgreSQL port (5432)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on PostgreSQL port (5432) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-012
#

default firewall_port_3389 = null

gc_issue["firewall_port_3389"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "3389"
}

gc_issue["firewall_port_3389"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 3389
    to_number(port_range[1]) >= 3389
}

gc_issue["firewall_port_3389"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_3389"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_3389 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_3389"]
}

firewall_port_3389 = false {
    gc_issue["firewall_port_3389"]
}

firewall_port_3389_err = "GCP Firewall rule allows internet traffic to RDP port (3389)" {
    gc_issue["firewall_port_3389"]
}

firewall_port_3389_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-012",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to RDP port (3389)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on RDP port (3389) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-013
#

default firewall_port_25 = null

gc_issue["firewall_port_25"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "25"
}

gc_issue["firewall_port_25"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 25
    to_number(port_range[1]) >= 25
}

gc_issue["firewall_port_25"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_25"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_25 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_25"]
}

firewall_port_25 = false {
    gc_issue["firewall_port_25"]
}

firewall_port_25_err = "GCP Firewall rule allows internet traffic to SMTP port (25)" {
    gc_issue["firewall_port_25"]
}

firewall_port_25_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-013",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to SMTP port (25)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on SMTP port (25) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-014
#

default firewall_port_22 = null

gc_issue["firewall_port_22"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "22"
}

gc_issue["firewall_port_22"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 22
    to_number(port_range[1]) >= 22
}

gc_issue["firewall_port_22"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_22"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_22 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_22"]
}

firewall_port_22 = false {
    gc_issue["firewall_port_22"]
}

firewall_port_22_err = "GCP Firewall rule allows internet traffic to SSH port (22)" {
    gc_issue["firewall_port_22"]
}

firewall_port_22_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-014",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to SSH port (22)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on SSH port (22) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-015
#

default firewall_port_23 = null

gc_issue["firewall_port_23"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    allow.ports[_] == "23"
}

gc_issue["firewall_port_23"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    port := allow.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 23
    to_number(port_range[1]) >= 23
}

gc_issue["firewall_port_23"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "tcp"
}

gc_issue["firewall_port_23"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    allow := resource.properties.allowed[_]
    count(allow.ports[_]) < 1
    lower(allow.IPProtocol) == "udp"
}

firewall_port_23 {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_port_23"]
}

firewall_port_23 = false {
    gc_issue["firewall_port_23"]
}

firewall_port_23_err = "GCP Firewall rule allows internet traffic to Telnet port (23)" {
    gc_issue["firewall_port_23"]
}

firewall_port_23_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-015",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rule allows internet traffic to Telnet port (23)",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on Telnet port (23) from public internet. Allowing access from arbitrary internet IP addresses to this port increases the attack surface of your network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-016
#

default firewall_inbound = null

gc_issue["firewall_inbound"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    lower(resource.properties.direction) == "ingress"
    not resource.properties.targetTags
    not resource.properties.targetServiceAccounts
}

firewall_inbound {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_inbound"]
}

firewall_inbound = false {
    gc_issue["firewall_inbound"]
}

firewall_inbound_err = "GCP Firewall rules allow inbound traffic from anywhere with no target tags set" {
    gc_issue["firewall_inbound"]
}

firewall_inbound_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-016",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall rules allow inbound traffic from anywhere with no target tags set",
    "Policy Description": "This policy identifies GCP Firewall rules which allow inbound traffic from anywhere with no target filtering. _x005F_x000D_ _x005F_x000D_ The default target is all instances in the network. The use of target tags or target service accounts allows the rule to apply to select instances. Not using any firewall rule filtering may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-FW-017
#

default firewall_inbound_all = null

gc_issue["firewall_inbound_all"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.firewall"
    resource.properties.sourceRanges[j] == "0.0.0.0/0"
    lower(resource.properties.allowed[_].IPProtocol) == "all"
}

firewall_inbound_all {
    lower(input.resources[i].type) == "compute.v1.firewall"
    not gc_issue["firewall_inbound_all"]
}

firewall_inbound_all = false {
    gc_issue["firewall_inbound_all"]
}

firewall_inbound_all_err = "GCP Firewall with Inbound rule overly permissive to All Traffic" {
    gc_issue["firewall_inbound_all"]
}

firewall_inbound_all_metadata := {
    "Policy Code": "PR-GCP-GDF-FW-017",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Firewall with Inbound rule overly permissive to All Traffic",
    "Policy Description": "This policy identifies GCP Firewall rules which allows inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "compute.v1.firewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/firewalls"
}

#
# PR-GCP-GDF-DISK-001
#

default disk_encrypt = null

gc_issue["disk_encrypt"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.disk"
    not resource.properties.diskEncryptionKey
}

disk_encrypt {
    lower(input.resources[i].type) == "compute.v1.disk"
    not gc_issue["disk_encrypt"]
}

disk_encrypt = false {
    gc_issue["disk_encrypt"]
}

disk_encrypt_err = "GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)" {
    gc_issue["disk_encrypt"]
}

disk_encrypt_metadata := {
    "Policy Code": "PR-GCP-GDF-DISK-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP VM disks not encrypted with Customer-Supplied Encryption Keys (CSEK)",
    "Policy Description": "This policy identifies VM disks which are not encrypted with Customer-Supplied Encryption Keys (CSEK). If you provide your own encryption keys, Compute Engine uses your key to protect the Google-generated keys used to encrypt and decrypt your data. It is recommended to use VM disks encrypted with CSEK for business-critical VM instances.",
    "Resource Type": "compute.v1.disk",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/disks"
}


# https://cloud.google.com/compute/docs/reference/rest/v1/instances

#
# PR-GCP-GDF-INST-001
#

default vm_ip_forward = null

gc_issue["vm_ip_forward"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.instance"
    resource.properties.canIpForward
}

vm_ip_forward {
    lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_ip_forward"]
}

vm_ip_forward = false {
    gc_issue["vm_ip_forward"]
}

vm_ip_forward_err = "GCP VM instances have IP forwarding enabled" {
    gc_issue["vm_ip_forward"]
}

vm_ip_forward_metadata := {
    "Policy Code": "PR-GCP-GDF-INST-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP VM instances have IP forwarding enabled",
    "Policy Description": "This policy identifies VM instances have IP forwarding enabled. IP Forwarding could open unintended and undesirable communication paths and allows VM instances to send and receive packets with the non-matching destination or source IPs. To enable source and destination IP match check, disable the IP Forwarding.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-GDF-INST-002
#

default vm_block_project_ssh_keys = null

gc_issue["vm_block_project_ssh_keys"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.instance"
    count([c | contains(lower(resource.properties.metadata.items[_].key), "block-project-ssh-keys"); c := 1]) == 0
}

vm_block_project_ssh_keys {
    lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_block_project_ssh_keys"]
}

vm_block_project_ssh_keys = false {
    gc_issue["vm_block_project_ssh_keys"]
}

vm_block_project_ssh_keys_err = "GCP VM instances have block project-wide SSH keys feature disabled" {
    gc_issue["vm_block_project_ssh_keys"]
}

vm_block_project_ssh_keys_metadata := {
    "Policy Code": "PR-GCP-GDF-INST-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP VM instances have block project-wide SSH keys feature disabled",
    "Policy Description": "This policy identifies VM instances which have block project-wide SSH keys feature disabled. Project-wide SSH keys are stored in Compute/Project-metadata. Project-wide SSH keys can be used to login into all the instances within a project. Using project-wide SSH keys eases the SSH key management but if compromised, poses the security risk which can impact all the instances within a project. It is recommended to use Instance specific SSH keys which can limit the attack surface if the SSH keys are compromised.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-GDF-INST-003
#

default vm_serial_port = null

gc_issue["vm_serial_port"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.instance"
    items := resource.properties.metadata.items[_]
    contains(lower(items.key), "serial-port-enable")
    lower(items.value) == "true"
}

vm_serial_port {
    lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_serial_port"]
}

vm_serial_port = false {
    gc_issue["vm_serial_port"]
}

vm_serial_port_err = "GCP VM instances have serial port access enabled" {
    gc_issue["vm_serial_port"]
}

vm_serial_port_metadata := {
    "Policy Code": "PR-GCP-GDF-INST-003",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP VM instances have serial port access enabled",
    "Policy Description": "This policy identifies VM instances which have serial port access enabled. Interacting with a serial port is often referred to as the serial console. The interactive serial console does not support IP-based access restrictions such as IP whitelists. If you enable the interactive serial console on an instance, clients can attempt to connect to that instance from any IP address. So it is recommended to keep interactive serial console support disabled.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-GDF-INST-004
#

default vm_pre_emptible = null

gc_issue["vm_pre_emptible"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.instance"
    resource.properties.scheduling.preemptible == true
}

vm_pre_emptible {
    lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_pre_emptible"]
}

vm_pre_emptible = false {
    gc_issue["vm_pre_emptible"]
}

vm_pre_emptible_err = "VM Instances enabled with Pre-Emptible termination" {
    gc_issue["vm_pre_emptible"]
}

vm_pre_emptible_metadata := {
    "Policy Code": "PR-GCP-GDF-INST-004",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "VM Instances enabled with Pre-Emptible termination",
    "Policy Description": "Checks to verify if any VM instance is initiated with the flag 'Pre-Emptible termination' set to True. Setting this instance to True implies that this VM instance will shut down within 24 hours or can also be terminated by a Service Engine when high demand is encountered. While this might save costs, it can also lead to unexpected loss of service when the VM instance is terminated.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-GDF-INST-005
#

default vm_metadata = null

gc_issue["vm_metadata"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.instance"
    not resource.properties.metadata.items
}

gc_issue["vm_metadata"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.instance"
    count(resource.properties.metadata.items) == 0
}

vm_metadata {
    lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_metadata"]
}

vm_metadata = false {
    gc_issue["vm_metadata"]
}

vm_metadata_err = "VM Instances without any Custom metadata information" {
    gc_issue["vm_metadata"]
}

vm_metadata_metadata := {
    "Policy Code": "PR-GCP-GDF-INST-005",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "VM Instances without any Custom metadata information",
    "Policy Description": "VM instance does not have any Custom metadata. Custom metadata can be used for easy identification and searches.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-GDF-INST-006
#

default vm_no_labels = null

gc_issue["vm_no_labels"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.instance"
    not resource.properties.labels
}

gc_issue["vm_no_labels"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.instance"
    count(resource.properties.labels) == 0
}

vm_no_labels {
    lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_no_labels"]
}

vm_no_labels = false {
    gc_issue["vm_no_labels"]
}

vm_no_labels_err = "VM Instances without any Label information" {
    gc_issue["vm_no_labels"]
}

vm_no_labels_metadata := {
    "Policy Code": "PR-GCP-GDF-INST-006",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "VM Instances without any Label information",
    "Policy Description": "VM instance does not have any Labels. Labels can be used for easy identification and searches.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

#
# PR-GCP-GDF-INST-007
#

default vm_info = null

gc_issue["vm_info"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.instance"
    not resource.properties.labels
}

gc_issue["vm_info"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.instance"
    count(resource.properties.labels) == 0
}

gc_issue["vm_info"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.instance"
    not resource.properties.metadata.items
}

gc_issue["vm_info"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.instance"
    count(resource.properties.metadata.items) == 0
}

gc_issue["vm_info"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.instance"
    not resource.properties.zone
}

vm_info {
    lower(input.resources[i].type) == "compute.v1.instance"
    not gc_issue["vm_info"]
}

vm_info = false {
    gc_issue["vm_info"]
}

vm_info_err = "VM instances without metadata, zone or label information" {
    gc_issue["vm_info"]
}

vm_info_metadata := {
    "Policy Code": "PR-GCP-GDF-INST-007",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "VM instances without metadata, zone or label information",
    "Policy Description": "Checks to ensure that VM instances have proper metadata, zone and label information tags. These tags can be used for easier identification and searches.",
    "Resource Type": "compute.v1.instance",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
}

# https://cloud.google.com/compute/docs/reference/rest/v1/networks

#
# PR-GCP-GDF-NET-001
#

default net_legacy = null

gc_issue["net_legacy"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.network"
    not resource.properties.autoCreateSubnetworks
}

net_legacy {
    lower(input.resources[i].type) == "compute.v1.network"
    not gc_issue["net_legacy"]
}

net_legacy = false {
    gc_issue["net_legacy"]
}

net_legacy_err = "GCP project is configured with legacy network" {
    gc_issue["net_legacy"]
}

net_legacy_metadata := {
    "Policy Code": "PR-GCP-GDF-NET-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP project is configured with legacy network",
    "Policy Description": "This policy identifies the projects which have configured with legacy networks. Legacy networks have a single network IPv4 prefix range and a single gateway IP address for the whole network. Subnetworks cannot be created in a legacy network. Legacy networks can have an impact on high network traffic projects and subject to the single point of failure.",
    "Resource Type": "compute.v1.network",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/networks"
}

#
# PR-GCP-GDF-NET-002
#

default net_default = null


gc_attribute_absence["net_default"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.network"
    not resource.properties.name
}

gc_issue["net_default"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.network"
    lower(resource.properties.name) == "default"
}

net_default {
    lower(input.resources[i].type) == "compute.v1.network"
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
    "Policy Code": "PR-GCP-GDF-NET-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP project is using the default network",
    "Policy Description": "This policy identifies the projects which have default network configured. It is recommended to use network configuration based on your security and networking requirements, you should create your network and delete the default network.",
    "Resource Type": "compute.v1.network",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/networks"
}

# https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks

#
# PR-GCP-GDF-SUBN-001
#

default vpc_flow_logs = null

gc_issue["vpc_flow_logs"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.subnetwork"
    not resource.properties.enableFlowLogs
}

vpc_flow_logs {
    lower(input.resources[i].type) == "compute.v1.subnetwork"
    not gc_issue["vpc_flow_logs"]
}

vpc_flow_logs = false {
    gc_issue["vpc_flow_logs"]
}

vpc_flow_logs_err = "GCP VPC Flow logs for the subnet is set to Off" {
    gc_issue["vpc_flow_logs"]
}

vpc_flow_logs_metadata := {
    "Policy Code": "PR-GCP-GDF-SUBN-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP VPC Flow logs for the subnet is set to Off",
    "Policy Description": "This policy identifies the subnets in VPC Network which have Flow logs disabled. It enables to capture information about the IP traffic going to and from network interfaces in VPC Subnets.",
    "Resource Type": "compute.v1.subnetwork",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks"
}

#
# PR-GCP-GDF-SUBN-002
#

default vpc_private_ip_google = null

gc_issue["vpc_private_ip_google"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.subnetwork"
    not resource.properties.privateIpGoogleAccess
}

vpc_private_ip_google {
    lower(input.resources[i].type) == "compute.v1.subnetwork"
    not gc_issue["vpc_private_ip_google"]
}

vpc_private_ip_google = false {
    gc_issue["vpc_private_ip_google"]
}

vpc_private_ip_google_err = "GCP VPC Network subnets have Private Google access disabled" {
    gc_issue["vpc_private_ip_google"]
}

vpc_private_ip_google_metadata := {
    "Policy Code": "PR-GCP-GDF-SUBN-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP VPC Network subnets have Private Google access disabled",
    "Policy Description": "This policy identifies GCP VPC Network subnets have disabled Private Google access. Private Google access enables virtual machine instances on a subnet to reach Google APIs and services using an internal IP address rather than an external IP address. Internal (private) IP addresses are internal to Google Cloud Platform and are not routable or reachable over the Internet. You can use Private Google access to allow VMs without Internet access to reach Google APIs, services, and properties that are accessible over HTTP/HTTPS.",
    "Resource Type": "compute.v1.subnetwork",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks"
}

# https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies

#
# PR-GCP-GDF-THP-001
#

default lbs_ssl_policy = null

gc_issue["lbs_ssl_policy"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.targethttpsproxy"
    not resource.properties.sslPolicy
}

gc_issue["lbs_ssl_policy"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.targethttpsproxy"
    count(resource.properties.sslPolicy) == 0
}

lbs_ssl_policy {
    lower(input.resources[i].type) == "compute.v1.targethttpsproxy"
    not gc_issue["lbs_ssl_policy"]
}

lbs_ssl_policy = false {
    gc_issue["lbs_ssl_policy"]
}

lbs_ssl_policy_err = "GCP Load balancer HTTPS target proxy configured with default SSL policy instead of custom SSL policy" {
    gc_issue["lbs_ssl_policy"]
}

lbs_ssl_policy_metadata := {
    "Policy Code": "PR-GCP-GDF-THP-001",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Load balancer HTTPS target proxy configured with default SSL policy instead of custom SSL policy",
    "Policy Description": "This policy identifies Load balancer HTTPS target proxies which are configured with default SSL Policy instead of custom SSL policy. It is a best practice to use custom SSL policy to access load balancers. It gives you closer control over SSL/TLS versions and ciphers.",
    "Resource Type": "compute.v1.targethttpsproxy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies"
}

#
# PR-GCP-GDF-THP-002
#

default lbs_quic = null

gc_attribute_absence["lbs_quic"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.targethttpsproxy"
    not resource.properties.quicOverride
}

gc_issue["lbs_quic"] {
    resource := input.resources[i]
    lower(resource.type) == "compute.v1.targethttpsproxy"
    lower(resource.properties.quicOverride) != "enable"
}

lbs_quic {
    lower(input.resources[i].type) == "compute.v1.targethttpsproxy"
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
    "Policy Code": "PR-GCP-GDF-THP-002",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "GCP deployment",
    "Policy Title": "GCP Load balancer HTTPS target proxy is not configured with QUIC protocol",
    "Policy Description": "This policy identifies Load Balancer HTTPS target proxies which are not configured with QUIC protocol. Enabling QUIC protocol in load balancer target https proxies adds advantage by establishing connections faster, stream-based multiplexing, improved loss recovery, and eliminates head-of-line blocking.",
    "Resource Type": "compute.v1.targethttpsproxy",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/compute/docs/reference/rest/v1/targetHttpsProxies"
}
