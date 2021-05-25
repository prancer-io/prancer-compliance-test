package rule

# https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall

#
# EGRESS_DENY_RULE_NOT_SET
#

default egress_deny_rule_not_set = null

gc_issue["egress_deny_rule_not_set"] {
    lower(input.kind) == "computefirewall"
    not input.spec.deny
}

gc_issue["egress_deny_rule_not_set"] {
    lower(input.kind) == "computefirewall"
    count([
        c | lower(input.spec.deny[_].protocol) == "all";
        input.spec.deny[_].destinationRanges[_] == "0.0.0.0/0"; c := 1
    ]) == 0
}

egress_deny_rule_not_set {
    lower(input.kind) == "computefirewall"
    not gc_issue["egress_deny_rule_not_set"]
}

egress_deny_rule_not_set = false {
    gc_issue["egress_deny_rule_not_set"]
}

egress_deny_rule_not_set_err = "An egress deny rule is not set on a firewall." {
    gc_issue["egress_deny_rule_not_set"]
}

egress_deny_rule_not_set_metadata := {
    "Policy Code": "EGRESS_DENY_RULE_NOT_SET",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Egress Deny Rule Not Set",
    "Policy Description": "An egress deny rule is not set on a firewall.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# FIREWALL_RULE_LOGGING_DISABLED
#

default firewall_rule_logging_disabled = null

gc_issue["firewall_rule_logging_disabled"] {
    lower(input.kind) == "computefirewall"
    not input.spec.logConfig
}

firewall_rule_logging_disabled {
    lower(input.kind) == "computefirewall"
    not gc_issue["firewall_rule_logging_disabled"]
}

firewall_rule_logging_disabled = false {
    gc_issue["firewall_rule_logging_disabled"]
}

firewall_rule_logging_disabled_err = "Firewall rule logging is disabled." {
    gc_issue["firewall_rule_logging_disabled"]
}

firewall_rule_logging_disabled_metadata := {
    "Policy Code": "FIREWALL_RULE_LOGGING_DISABLED",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "Firewall Rule Logging Disabled",
    "Policy Description": "Firewall rule logging is disabled.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}

#
# OPEN_CASSANDRA_PORT
#

default open_cassandra_port = null

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    lower(allowed.protocol) == "tcp"
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 7000
    to_number(port_range[1]) >= 7001
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    lower(allowed.protocol) == "tcp"
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 7199
    to_number(port_range[1]) >= 7199
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    lower(allowed.protocol) == "tcp"
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 8888
    to_number(port_range[1]) >= 8888
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    lower(allowed.protocol) == "tcp"
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 9042
    to_number(port_range[1]) >= 9042
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    lower(allowed.protocol) == "tcp"
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 9160
    to_number(port_range[1]) >= 9160
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    lower(allowed.protocol) == "tcp"
    port := allowed.ports[_]
    contains(port, "-")
    port_range := split(port, "-")
    to_number(port_range[0]) <= 61620
    to_number(port_range[1]) >= 61621
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    lower(allowed.protocol) == "tcp"
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) <= 7000
    to_number(port) >= 7001
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    lower(allowed.protocol) == "tcp"
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 7199
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    lower(allowed.protocol) == "tcp"
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 8888
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    lower(allowed.protocol) == "tcp"
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 9042
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    lower(allowed.protocol) == "tcp"
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) == 9160
}

gc_issue["open_cassandra_port"] {
    lower(input.kind) == "computefirewall"
    allowed := input.spec.allow[_]
    lower(allowed.protocol) == "tcp"
    port := allowed.ports[_]
    not contains(port, "-")
    to_number(port) <= 61620
    to_number(port) >= 61621
}

open_cassandra_port {
    lower(input.kind) == "computefirewall"
    not gc_issue["open_cassandra_port"]
}

open_cassandra_port = false {
    gc_issue["open_cassandra_port"]
}

open_cassandra_port_err = "A firewall is configured to have an open CASSANDRA port that allows generic access." {
    gc_issue["open_cassandra_port"]
}

open_cassandra_port_metadata := {
    "Policy Code": "OPEN_CASSANDRA_PORT",
    "Type": "IaC",
    "Product": "GCP",
    "Language": "KCC",
    "Policy Title": "OPEN CASSANDRA PORT",
    "Policy Description": "A firewall is configured to have an open CASSANDRA port that allows generic access.",
    "Resource Type": "ComputeFirewall",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/config-connector/docs/reference/resource-docs/compute/computefirewall"
}
