package rule

# https://cloud.google.com/compute/docs/reference/rest/v1/firewalls

#
# PR-GCP-0002-TRF
#

default firewall_default = null


gc_attribute_absence["firewall_default"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.name
}

gc_issue["firewall_default"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    lower(resource.properties.name) == "default-allow-ssh"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
}

gc_issue["firewall_default"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    lower(resource.properties.name) == "default-allow-ssh"
    not resource.properties.source_ranges
}

gc_issue["firewall_default"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    lower(resource.properties.name) == "default-allow-icmp"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
}

gc_issue["firewall_default"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    lower(resource.properties.name) == "default-allow-icmp"
    not resource.properties.source_ranges
}

gc_issue["firewall_default"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    lower(resource.properties.name) == "default-allow-internal"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
}

gc_issue["firewall_default"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    lower(resource.properties.name) == "default-allow-internal"
    not resource.properties.source_ranges
}

gc_issue["firewall_default"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    lower(resource.properties.name) == "default-allow-rdp"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
}

gc_issue["firewall_default"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    lower(resource.properties.name) == "default-allow-rdp"
    not resource.properties.source_ranges
}

firewall_default {
    lower(input.resources[_].type) == "google_compute_firewall"
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

#
# PR-GCP-0006-TRF
#

default firewall_port_53 = null

gc_issue["firewall_port_53"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 53
}

gc_issue["firewall_port_53"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 53
}

gc_issue["firewall_port_53"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 53
    to_number(port_range[1]) >= 53
}

gc_issue["firewall_port_53"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 53
    to_number(port_range[1]) >= 53
}

gc_issue["firewall_port_53"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_53"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_53"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_53"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_53 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_53"]
}

firewall_port_53 = false {
    gc_issue["firewall_port_53"]
}

firewall_port_53_err = "GCP Firewall rule allows internet traffic to DNS port (53)" {
    gc_issue["firewall_port_53"]
}

#
# PR-GCP-0007-TRF
#

default firewall_port_21 = null

gc_issue["firewall_port_21"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 21
}

gc_issue["firewall_port_21"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 21
}

gc_issue["firewall_port_21"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 21
    to_number(port_range[1]) >= 21
}

gc_issue["firewall_port_21"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 21
    to_number(port_range[1]) >= 21
}

gc_issue["firewall_port_21"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_21"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_21"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_21"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_21 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_21"]
}

firewall_port_21 = false {
    gc_issue["firewall_port_21"]
}

firewall_port_21_err = "GCP Firewall rule allows internet traffic to FTP port (21)" {
    gc_issue["firewall_port_21"]
}

#
# PR-GCP-0008-TRF
#

default firewall_port_80 = null

gc_issue["firewall_port_80"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 80
}

gc_issue["firewall_port_80"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 80
}

gc_issue["firewall_port_80"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 80
    to_number(port_range[1]) >= 80
}

gc_issue["firewall_port_80"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 80
    to_number(port_range[1]) >= 80
}

gc_issue["firewall_port_80"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_80"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_80"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_80"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_80 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_80"]
}

firewall_port_80 = false {
    gc_issue["firewall_port_80"]
}

firewall_port_80_err = "GCP Firewall rule allows internet traffic to HTTP port (80)" {
    gc_issue["firewall_port_80"]
}

#
# PR-GCP-0009-TRF
#

default firewall_port_445 = null

gc_issue["firewall_port_445"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 445
}

gc_issue["firewall_port_445"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 445
}

gc_issue["firewall_port_445"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 445
    to_number(port_range[1]) >= 445
}

gc_issue["firewall_port_445"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 445
    to_number(port_range[1]) >= 445
}

gc_issue["firewall_port_445"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_445"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_445"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_445"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_445 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_445"]
}

firewall_port_445 = false {
    gc_issue["firewall_port_445"]
}

firewall_port_445_err = "GCP Firewall rule allows internet traffic to Microsoft-DS port (445)" {
    gc_issue["firewall_port_445"]
}

#
# PR-GCP-0010-TRF
#

default firewall_port_27017 = null

gc_issue["firewall_port_27017"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 27017
}

gc_issue["firewall_port_27017"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 27017
}

gc_issue["firewall_port_27017"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 27017
    to_number(port_range[1]) >= 27017
}

gc_issue["firewall_port_27017"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 27017
    to_number(port_range[1]) >= 27017
}

gc_issue["firewall_port_27017"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_27017"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_27017"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_27017"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_27017 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_27017"]
}

firewall_port_27017 = false {
    gc_issue["firewall_port_27017"]
}

firewall_port_27017_err = "GCP Firewall rule allows internet traffic to MongoDB port (27017)" {
    gc_issue["firewall_port_27017"]
}

#
# PR-GCP-0011-TRF
#

default firewall_port_3306 = null

gc_issue["firewall_port_3306"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 3306
}

gc_issue["firewall_port_3306"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 3306
}

gc_issue["firewall_port_3306"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 3306
    to_number(port_range[1]) >= 3306
}

gc_issue["firewall_port_3306"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 3306
    to_number(port_range[1]) >= 3306
}

gc_issue["firewall_port_3306"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_3306"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_3306"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_3306"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_3306 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_3306"]
}

firewall_port_3306 = false {
    gc_issue["firewall_port_3306"]
}

firewall_port_3306_err = "GCP Firewall rule allows internet traffic to MySQL DB port (3306)" {
    gc_issue["firewall_port_3306"]
}

#
# PR-GCP-0012-TRF
#

default firewall_port_139 = null

gc_issue["firewall_port_139"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 139
}

gc_issue["firewall_port_139"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 139
}

gc_issue["firewall_port_139"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 139
    to_number(port_range[1]) >= 139
}

gc_issue["firewall_port_139"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 139
    to_number(port_range[1]) >= 139
}

gc_issue["firewall_port_139"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_139"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_139"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_139"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_139 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_139"]
}

firewall_port_139 = false {
    gc_issue["firewall_port_139"]
}

firewall_port_139_err = "GCP Firewall rule allows internet traffic to NetBIOS-SSN port (139)" {
    gc_issue["firewall_port_139"]
}

#
# PR-GCP-0013-TRF
#

default firewall_port_1521 = null

gc_issue["firewall_port_1521"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 1521
}

gc_issue["firewall_port_1521"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 1521
}

gc_issue["firewall_port_1521"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 1521
    to_number(port_range[1]) >= 1521
}

gc_issue["firewall_port_1521"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 1521
    to_number(port_range[1]) >= 1521
}

gc_issue["firewall_port_1521"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_1521"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_1521"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_1521"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_1521 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_1521"]
}

firewall_port_1521 = false {
    gc_issue["firewall_port_1521"]
}

firewall_port_1521_err = "GCP Firewall rule allows internet traffic to Oracle DB port (1521)" {
    gc_issue["firewall_port_1521"]
}

#
# PR-GCP-0014-TRF
#

default firewall_port_110 = null

gc_issue["firewall_port_110"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 110
}

gc_issue["firewall_port_110"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 110
}

gc_issue["firewall_port_110"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 110
    to_number(port_range[1]) >= 110
}

gc_issue["firewall_port_110"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 110
    to_number(port_range[1]) >= 110
}

gc_issue["firewall_port_110"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_110"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_110"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_110"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_110 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_110"]
}

firewall_port_110 = false {
    gc_issue["firewall_port_110"]
}

firewall_port_110_err = "GCP Firewall rule allows internet traffic to POP3 port (110)" {
    gc_issue["firewall_port_110"]
}

#
# PR-GCP-0015-TRF
#

default firewall_port_5432 = null

gc_issue["firewall_port_5432"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 5432
}

gc_issue["firewall_port_5432"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 5432
}

gc_issue["firewall_port_5432"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 5432
    to_number(port_range[1]) >= 5432
}

gc_issue["firewall_port_5432"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 5432
    to_number(port_range[1]) >= 5432
}

gc_issue["firewall_port_5432"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_5432"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_5432"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_5432"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_5432 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_5432"]
}

firewall_port_5432 = false {
    gc_issue["firewall_port_5432"]
}

firewall_port_5432_err = "GCP Firewall rule allows internet traffic to PostgreSQL port (5432)" {
    gc_issue["firewall_port_5432"]
}

#
# PR-GCP-0016-TRF
#

default firewall_port_3389 = null

gc_issue["firewall_port_3389"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 3389
}

gc_issue["firewall_port_3389"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 3389
}

gc_issue["firewall_port_3389"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 3389
    to_number(port_range[1]) >= 3389
}

gc_issue["firewall_port_3389"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 3389
    to_number(port_range[1]) >= 3389
}

gc_issue["firewall_port_3389"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_3389"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_3389"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_3389"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_3389 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_3389"]
}

firewall_port_3389 = false {
    gc_issue["firewall_port_3389"]
}

firewall_port_3389_err = "GCP Firewall rule allows internet traffic to RDP port (3389)" {
    gc_issue["firewall_port_3389"]
}

#
# PR-GCP-0017-TRF
#

default firewall_port_25 = null

gc_issue["firewall_port_25"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 25
}

gc_issue["firewall_port_25"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 25
}

gc_issue["firewall_port_25"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 25
    to_number(port_range[1]) >= 25
}

gc_issue["firewall_port_25"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 25
    to_number(port_range[1]) >= 25
}

gc_issue["firewall_port_25"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_25"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_25"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_25"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_25 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_25"]
}

firewall_port_25 = false {
    gc_issue["firewall_port_25"]
}

firewall_port_25_err = "GCP Firewall rule allows internet traffic to SMTP port (25)" {
    gc_issue["firewall_port_25"]
}

#
# PR-GCP-0018-TRF
#

default firewall_port_22 = null

gc_issue["firewall_port_22"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 22
}

gc_issue["firewall_port_22"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 22
}

gc_issue["firewall_port_22"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 22
    to_number(port_range[1]) >= 22
}

gc_issue["firewall_port_22"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 22
    to_number(port_range[1]) >= 22
}

gc_issue["firewall_port_22"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_22"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_22"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_22"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_22 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_22"]
}

firewall_port_22 = false {
    gc_issue["firewall_port_22"]
}

firewall_port_22_err = "GCP Firewall rule allows internet traffic to SSH port (22)" {
    gc_issue["firewall_port_22"]
}

#
# PR-GCP-0019-TRF
#

default firewall_port_23 = null

gc_issue["firewall_port_23"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    allow.ports[_] == 23
}

gc_issue["firewall_port_23"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    allow.ports[_] == 23
}

gc_issue["firewall_port_23"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 23
    to_number(port_range[1]) >= 23
}

gc_issue["firewall_port_23"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    port := allow.ports[_]
    is_string(port)
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 23
    to_number(port_range[1]) >= 23
}

gc_issue["firewall_port_23"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_23"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "tcp"
}

gc_issue["firewall_port_23"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

gc_issue["firewall_port_23"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    allow := resource.properties.allow[_]
    is_set(allow.ports)
    count(allow.ports[_]) < 1
    lower(allow.protocol) == "udp"
}

firewall_port_23 {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_port_23"]
}

firewall_port_23 = false {
    gc_issue["firewall_port_23"]
}

firewall_port_23_err = "GCP Firewall rule allows internet traffic to Telnet port (23)" {
    gc_issue["firewall_port_23"]
}

#
# PR-GCP-0020-TRF
#

default firewall_inbound = null

gc_issue["firewall_inbound"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    lower(resource.properties.direction) == "ingress"
    not resource.properties.targetTags
    not resource.properties.targetServiceAccounts
}

gc_issue["firewall_inbound"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    lower(resource.properties.direction) == "ingress"
    not resource.properties.targetTags
    not resource.properties.targetServiceAccounts
}

firewall_inbound {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_inbound"]
}

firewall_inbound = false {
    gc_issue["firewall_inbound"]
}

firewall_inbound_err = "GCP Firewall rules allow inbound traffic from anywhere with no target tags set" {
    gc_issue["firewall_inbound"]
}

#
# PR-GCP-0021-TRF
#

default firewall_inbound_all = null

gc_issue["firewall_inbound_all"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    resource.properties.source_ranges[_] == "0.0.0.0/0"
    lower(resource.properties.allow[_].protocol) == "all"
}

gc_issue["firewall_inbound_all"] {
    resource := input.resources[_]
    lower(resource.type) == "google_compute_firewall"
    not resource.properties.source_ranges
    lower(resource.properties.allow[_].protocol) == "all"
}

firewall_inbound_all {
    lower(input.resources[_].type) == "google_compute_firewall"
    not gc_issue["firewall_inbound_all"]
}

firewall_inbound_all = false {
    gc_issue["firewall_inbound_all"]
}

firewall_inbound_all_err = "GCP Firewall with Inbound rule overly permissive to All Traffic" {
    gc_issue["firewall_inbound_all"]
}
