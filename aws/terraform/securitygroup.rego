package rule


ports = [
    "135", "137", "138", "1433", "1434", "20", "21", "22", "23", "25", "3306", "3389", "4333",
    "445", "53", "5432", "5500", "5900", "69", "9300", "5601", "2379", "5986", "5985", "1270"
]

aws_issue[port] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    port := ports[_]

    ingress.cidr_blocks[k] == "0.0.0.0/0"
    to_number(ingress.from_port) <= to_number(port)
    to_number(ingress.to_port) >= to_number(port)
}

source_path[{concat("_",["port", port]): metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    port := ports[_]

    ingress.cidr_blocks[k] == "0.0.0.0/0"
    to_number(ingress.from_port) <= to_number(port)
    to_number(ingress.to_port) >= to_number(port)

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "cidr_blocks", k]
        ],
    }
}

aws_issue[port] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress
    port := ports[_]

    ingress.cidr_blocks[k] == "0.0.0.0/0"
    to_number(ingress.from_port) <= to_number(port)
    to_number(ingress.to_port) >= to_number(port)
}

source_path[{concat("_",["port", port]): metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress
    port := ports[_]

    ingress.cidr_blocks[k] == "0.0.0.0/0"
    to_number(ingress.from_port) <= to_number(port)
    to_number(ingress.to_port) >= to_number(port)

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", "cidr_blocks", k]
        ],
    }
}

aws_issue[port] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    lower(resource.properties.type) == "ingress"
    port := ports[_]

    resource.properties.cidr_blocks[j] == "0.0.0.0/0"
    to_number(resource.properties.from_port) <= to_number(port)
    to_number(resource.properties.to_port) >= to_number(port)
}

source_path[{concat("_",["port", port]): metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    lower(resource.properties.type) == "ingress"
    port := ports[_]

    resource.properties.cidr_blocks[j] == "0.0.0.0/0"
    to_number(resource.properties.from_port) <= to_number(port)
    to_number(resource.properties.to_port) >= to_number(port)

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cidr_blocks", j]
        ],
    }
}

aws_issue[port] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    port := ports[_]

    ingress.ipv6_cidr_blocks[k] == "::/0"
    to_number(ingress.from_port) <= to_number(port)
    to_number(ingress.to_port) >= to_number(port)
}

source_path[{concat("_",["port", port]): metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    port := ports[_]

    ingress.ipv6_cidr_blocks[k] == "::/0"
    to_number(ingress.from_port) <= to_number(port)
    to_number(ingress.to_port) >= to_number(port)

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "ipv6_cidr_blocks", k]
        ],
    }
}

aws_issue[port] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress
    port := ports[_]

    ingress.ipv6_cidr_blocks[j] == "::/0"
    to_number(ingress.from_port) <= to_number(port)
    to_number(ingress.to_port) >= to_number(port)
}

source_path[{concat("_",["port", port]): metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress
    port := ports[_]

    ingress.ipv6_cidr_blocks[j] == "::/0"
    to_number(ingress.from_port) <= to_number(port)
    to_number(ingress.to_port) >= to_number(port)

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", "ipv6_cidr_blocks", j]
        ],
    }
}


aws_issue[port] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    lower(resource.properties.type) == "ingress"
    port := ports[_]

    resource.properties.ipv6_cidr_blocks[j] == "::/0"
    to_number(resource.properties.from_port) <= to_number(port)
    to_number(resource.properties.to_port) >= to_number(port)
}

source_path[{concat("_",["port", port]): metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    lower(resource.properties.type) == "ingress"
    port := ports[_]

    resource.properties.ipv6_cidr_blocks[j] == "::/0"
    to_number(resource.properties.from_port) <= to_number(port)
    to_number(resource.properties.to_port) >= to_number(port)

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", "ipv6_cidr_blocks", j]
        ],
    }
}

aws_issue["all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    lower(resource.properties.name) == "default"
    ingress := resource.properties.ingress[j]
    ingress.ipv6_cidr_blocks[k] == "::/0"
}

source_path[{"all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    lower(resource.properties.name) == "default"
    ingress := resource.properties.ingress[j]
    ingress.ipv6_cidr_blocks[k] == "::/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "ipv6_cidr_blocks", k]
        ],
    }
}

aws_issue["all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    lower(resource.properties.name) == "default"
    egress := resource.properties.egress[j]
    egress.ipv6_cidr_blocks[k] == "::/0"
}

source_path[{"all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    lower(resource.properties.name) == "default"
    egress := resource.properties.egress[j]
    egress.ipv6_cidr_blocks[k] == "::/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "egress", j, "ipv6_cidr_blocks", k]
        ],
    }
}

aws_issue["all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    lower(resource.properties.name) == "default"
    ingress := resource.properties.ingress[j]
    ingress.cidr_blocks[k] == "0.0.0.0/0"
}

source_path[{"all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    lower(resource.properties.name) == "default"
    ingress := resource.properties.ingress[j]
    ingress.cidr_blocks[k] == "0.0.0.0/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "cidr_blocks", k]
        ],
    }
}

aws_issue["all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    lower(resource.properties.name) == "default"
    egress := resource.properties.egress[j]
    egress.cidr_blocks[k] == "0.0.0.0/0"
}

source_path[{"all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    lower(resource.properties.name) == "default"
    egress := resource.properties.egress[j]
    egress.cidr_blocks[k] == "0.0.0.0/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "egress", j, "cidr_blocks", k]
        ],
    }
}

aws_issue["all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.ipv6_cidr_blocks[j] == "::/0"
}

source_path[{"all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.ipv6_cidr_blocks[j] == "::/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ipv6_cidr_blocks", j]
        ],
    }
}

aws_issue["all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.cidr_blocks[j] == "0.0.0.0/0"
}

source_path[{"all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.cidr_blocks[j] == "0.0.0.0/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cidr_blocks", j]
        ],
    }
}

aws_issue["proto_all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ingress.protocol == "-1"
    ingress.cidr_blocks[k] == "0.0.0.0/0"
}

source_path[{"proto_all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ingress.protocol == "-1"
    ingress.cidr_blocks[k] == "0.0.0.0/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "cidr_blocks", k]
        ],
    }
}

aws_issue["proto_all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ingress.protocol == "all"
    ingress.cidr_blocks[k] == "0.0.0.0/0"
}

source_path[{"proto_all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ingress.protocol == "all"
    ingress.cidr_blocks[k] == "0.0.0.0/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "cidr_blocks", k]
        ],
    }
}

aws_issue["proto_all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.protocol == "-1"
    resource.properties.cidr_blocks[j] == "0.0.0.0/0"
}

source_path[{"proto_all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.protocol == "-1"
    resource.properties.cidr_blocks[j] == "0.0.0.0/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cidr_blocks", j]
        ],
    }
}

aws_issue["proto_all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.protocol == "all"
    resource.properties.cidr_blocks[j] == "0.0.0.0/0"
}

source_path[{"proto_all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.protocol == "all"
    resource.properties.cidr_blocks[j] == "0.0.0.0/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cidr_blocks", j]
        ],
    }
}

aws_issue["proto_all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ingress.protocol == "-1"
    ingress.ipv6_cidr_blocks[k] == "::/0"
}

source_path[{"proto_all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ingress.protocol == "-1"
    ingress.ipv6_cidr_blocks[k] == "::/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "ipv6_cidr_blocks", k]
        ],
    }
}

aws_issue["proto_all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ingress.protocol == "all"
    ingress.ipv6_cidr_blocks[k] == "::/0"
}

source_path[{"proto_all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ingress.protocol == "all"
    ingress.ipv6_cidr_blocks[k] == "::/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "ipv6_cidr_blocks", k]
        ],
    }
}

aws_issue["proto_all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.protocol == "-1"
    resource.properties.ipv6_cidr_blocks[j] == "::/0"
}

source_path[{"proto_all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.protocol == "-1"
    resource.properties.ipv6_cidr_blocks[j] == "::/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ipv6_cidr_blocks", j]
        ],
    }
}

aws_issue["proto_all"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.protocol == "all"
    resource.properties.ipv6_cidr_blocks[j] == "::/0"
}

source_path[{"proto_all": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    resource.properties.protocol == "all"
    resource.properties.ipv6_cidr_blocks[j] == "::/0"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ipv6_cidr_blocks", j]
        ],
    }
}

#
# PR-AWS-TRF-SG-030
#

default db_exposed = null

db_ports := [
    1433, 1521, 3306, 5000, 5432, 5984, 6379, 6380, 8080, 9042, 11211, 27017, 28015, 29015, 50000
]

aws_issue["db_exposed"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    cidr_blocks := ingress.cidr_blocks[k]
    cidr_blocks == "0.0.0.0/0"
    port := db_ports[_]
    to_number(ingress.from_port) <= port
    to_number(ingress.to_port) >= port
}

source_path[{"db_exposed": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    cidr_blocks := ingress.cidr_blocks[k]
    cidr_blocks == "0.0.0.0/0"
    port := db_ports[_]
    to_number(ingress.from_port) <= port
    to_number(ingress.to_port) >= port

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "cidr_blocks", k]
        ],
    }
}

aws_issue["db_exposed"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ipv6_cidr_blocks := ingress.ipv6_cidr_blocks[k]
    ipv6_cidr_blocks="::/0"
    port := db_ports[_]
    to_number(ingress.from_port) <= port
    to_number(ingress.to_port) >= port
}

source_path[{"db_exposed": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ipv6_cidr_blocks := ingress.ipv6_cidr_blocks[k]
    ipv6_cidr_blocks="::/0"
    port := db_ports[_]
    to_number(ingress.from_port) <= port
    to_number(ingress.to_port) >= port

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "ipv6_cidr_blocks", k]
        ],
    }
}

aws_issue["db_exposed"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    properties := resource.properties
    lower(properties.type) == "ingress"
    cidr_blocks := properties.cidr_blocks[k]
    cidr_blocks == "0.0.0.0/0"
    port := db_ports[_]
    to_number(properties.from_port) <= port
    to_number(properties.to_port) >= port
}

source_path[{"db_exposed": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    properties := resource.properties
    lower(properties.type) == "ingress"
    cidr_blocks := properties.cidr_blocks[k]
    cidr_blocks == "0.0.0.0/0"
    port := db_ports[_]
    to_number(properties.from_port) <= port
    to_number(properties.to_port) >= port

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cidr_blocks", k]
        ],
    }
}

aws_issue["db_exposed"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    properties := resource.properties
    lower(properties.type) == "ingress"
    ipv6_cidr_blocks := properties.ipv6_cidr_blocks[k]
    ipv6_cidr_blocks="::/0"
    port := db_ports[_]
    to_number(properties.from_port) <= port
    to_number(properties.to_port) >= port
}

source_path[{"db_exposed": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    properties := resource.properties
    lower(properties.type) == "ingress"
    ipv6_cidr_blocks := properties.ipv6_cidr_blocks[k]
    ipv6_cidr_blocks="::/0"
    port := db_ports[_]
    to_number(properties.from_port) <= port
    to_number(properties.to_port) >= port

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ipv6_cidr_blocks", k]
        ],
    }
}

db_exposed {
    lower(input.resources[i].type) == "aws_security_group"
    not aws_issue["db_exposed"]
}

db_exposed = false {
    aws_issue["db_exposed"]
}

db_exposed_err = "Publicly exposed DB Ports" {
    aws_issue["db_exposed"]
}

db_exposed_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-030",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Publicly exposed DB Ports",
    "Policy Description": "DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}

#
# PR-AWS-TRF-SG-031
#

default bitcoin_ports = null

bc_ports := [
    8332, 8333
]

aws_issue["bitcoin_ports"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    cidr_blocks := ingress.cidr_blocks[k]
    cidr_blocks == "0.0.0.0/0"
    port := bc_ports[_]
    to_number(ingress.from_port) <= port
    to_number(ingress.to_port) >= port
}

source_path[{"bitcoin_ports": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    cidr_blocks := ingress.cidr_blocks[k]
    cidr_blocks == "0.0.0.0/0"
    port := bc_ports[_]
    to_number(ingress.from_port) <= port
    to_number(ingress.to_port) >= port

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "cidr_blocks", k]
        ],
    }
}

aws_issue["bitcoin_ports"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ipv6_cidr_blocks := ingress.ipv6_cidr_blocks[k]
    ipv6_cidr_blocks="::/0"
    port := bc_ports[_]
    to_number(ingress.from_port) <= port
    to_number(ingress.to_port) >= port
}

source_path[{"bitcoin_ports": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ipv6_cidr_blocks := ingress.ipv6_cidr_blocks[k]
    ipv6_cidr_blocks="::/0"
    port := bc_ports[_]
    to_number(ingress.from_port) <= port
    to_number(ingress.to_port) >= port

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "ipv6_cidr_blocks", k]
        ],
    }
}

aws_issue["bitcoin_ports"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    properties := resource.properties
    lower(properties.type) == "ingress"
    cidr_blocks := properties.cidr_blocks[k]
    cidr_blocks == "0.0.0.0/0"
    port := bc_ports[_]
    to_number(properties.from_port) <= port
    to_number(properties.to_port) >= port
}

source_path[{"bitcoin_ports": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    properties := resource.properties
    lower(properties.type) == "ingress"
    cidr_blocks := properties.cidr_blocks[k]
    cidr_blocks == "0.0.0.0/0"
    port := bc_ports[_]
    to_number(properties.from_port) <= port
    to_number(properties.to_port) >= port

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cidr_blocks", k]
        ],
    }
}

aws_issue["bitcoin_ports"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    properties := resource.properties
    lower(properties.type) == "ingress"
    ipv6_cidr_blocks := properties.ipv6_cidr_blocks[k]
    ipv6_cidr_blocks="::/0"
    port := bc_ports[_]
    to_number(properties.from_port) <= port
    to_number(properties.to_port) >= port
}

source_path[{"bitcoin_ports": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    properties := resource.properties
    lower(properties.type) == "ingress"
    ipv6_cidr_blocks := properties.ipv6_cidr_blocks[k]
    ipv6_cidr_blocks="::/0"
    port := bc_ports[_]
    to_number(properties.from_port) <= port
    to_number(properties.to_port) >= port

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ipv6_cidr_blocks", k]
        ],
    }
}

bitcoin_ports {
    lower(input.resources[i].type) == "aws_security_group"
    not aws_issue["bitcoin_ports"]
}

bitcoin_ports = false {
    aws_issue["bitcoin_ports"]
}

bitcoin_ports_err = "Instance is communicating with ports known to mine Bitcoin" {
    aws_issue["bitcoin_ports"]
}

bitcoin_ports_metadata := {
    "Policy Code": "PR-AWS-gID2-TRF",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Instance is communicating with ports known to mine Bitcoin",
    "Policy Description": "Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}

#
# PR-AWS-TRF-SG-032
#

default ethereum_ports = null

eth_ports := [
    8545, 30303
]

aws_issue["ethereum_ports"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    cidr_blocks := ingress.cidr_blocks[k]
    cidr_blocks == "0.0.0.0/0"
    port := eth_ports[_]
    to_number(ingress.from_port) <= port
    to_number(ingress.to_port) >= port
}

source_path[{"ethereum_ports": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    cidr_blocks := ingress.cidr_blocks[k]
    cidr_blocks == "0.0.0.0/0"
    port := eth_ports[_]
    to_number(ingress.from_port) <= port
    to_number(ingress.to_port) >= port

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "cidr_blocks", k]
        ],
    }
}

aws_issue["ethereum_ports"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ipv6_cidr_blocks := ingress.ipv6_cidr_blocks[k]
    ipv6_cidr_blocks="::/0"
    port := eth_ports[_]
    to_number(ingress.from_port) <= port
    to_number(ingress.to_port) >= port
}

source_path[{"ethereum_ports": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    ingress := resource.properties.ingress[j]
    ipv6_cidr_blocks := ingress.ipv6_cidr_blocks[k]
    ipv6_cidr_blocks="::/0"
    port := eth_ports[_]
    to_number(ingress.from_port) <= port
    to_number(ingress.to_port) >= port

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "ipv6_cidr_blocks", k]
        ],
    }
}

aws_issue["ethereum_ports"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    properties := resource.properties
    lower(properties.type) == "ingress"
    cidr_blocks := properties.cidr_blocks[k]
    cidr_blocks == "0.0.0.0/0"
    port := bc_ports[_]
    to_number(properties.from_port) <= port
    to_number(properties.to_port) >= port
}

source_path[{"ethereum_ports": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    properties := resource.properties
    lower(properties.type) == "ingress"
    cidr_blocks := properties.cidr_blocks[k]
    cidr_blocks == "0.0.0.0/0"
    port := bc_ports[_]
    to_number(properties.from_port) <= port
    to_number(properties.to_port) >= port

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cidr_blocks", k]
        ],
    }
}

aws_issue["ethereum_ports"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    properties := resource.properties
    lower(properties.type) == "ingress"
    ipv6_cidr_blocks := properties.ipv6_cidr_blocks[k]
    ipv6_cidr_blocks="::/0"
    port := bc_ports[_]
    to_number(properties.from_port) <= port
    to_number(properties.to_port) >= port
}

source_path[{"ethereum_ports": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    properties := resource.properties
    lower(properties.type) == "ingress"
    ipv6_cidr_blocks := properties.ipv6_cidr_blocks[k]
    ipv6_cidr_blocks="::/0"
    port := bc_ports[_]
    to_number(properties.from_port) <= port
    to_number(properties.to_port) >= port

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ipv6_cidr_blocks", k]
        ],
    }
}

ethereum_ports {
    lower(input.resources[i].type) == "aws_security_group"
    not aws_issue["ethereum_ports"]
}

ethereum_ports = false {
    aws_issue["ethereum_ports"]
}

ethereum_ports_err = "Instance is communicating with ports known to mine Ethereum" {
    aws_issue["ethereum_ports"]
}

ethereum_ports_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-032",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Instance is communicating with ports known to mine Ethereum",
    "Policy Description": "Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}

#
# PR-AWS-TRF-SG-001
#

default port_135 = null

port_135 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["135"]
}

port_135 = false {
    aws_issue["135"]
}

port_135_err = "AWS Security Groups allow internet traffic from internet to Windows RPC port (135)" {
    aws_issue["135"]
}

port_135_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to Windows RPC port (135)",
    "Policy Description": "This policy identifies the security groups which are exposing Windows RPC port (135) to the internet. It is recommended that Global permission to access the well known services Windows RPC port (135) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-002
#

default port_137 = null

port_137 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["137"]
}

port_137 = false {
    aws_issue["137"]
}

port_137_err = "AWS Security Groups allow internet traffic from internet to NetBIOS port (137)" {
    aws_issue["137"]
}

port_137_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to NetBIOS port (137)",
    "Policy Description": "This policy identifies the security groups which are exposing NetBIOS port (137) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (137) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-003
#

default port_138 = null

port_138 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["138"]
}

port_138 = false {
    aws_issue["138"]
}

port_138_err = "AWS Security Groups allow internet traffic from internet to NetBIOS port (138)" {
    aws_issue["138"]
}

port_138_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to NetBIOS port (138)",
    "Policy Description": "This policy identifies the security groups which are exposing NetBIOS port (138) to the internet. It is recommended that Global permission to access the well known services NetBIOS port (138) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-004
#

default port_1433 = null

port_1433 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["1433"]
}

port_1433 = false {
    aws_issue["1433"]
}

port_1433_err = "AWS Security Groups allow internet traffic from internet to SQLServer port (1433)" {
    aws_issue["1433"]
}

port_1433_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to SQLServer port (1433)",
    "Policy Description": "This policy identifies the security groups which are exposing SQLServer port (1433) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1433) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-005
#

default port_1434 = null

port_1434 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["1434"]
}

port_1434 = false {
    aws_issue["1434"]
}

port_1434_err = "AWS Security Groups allow internet traffic from internet to SQLServer port (1434)" {
    aws_issue["1434"]
}

port_1434_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to SQLServer port (1434)",
    "Policy Description": "This policy identifies the security groups which are exposing SQLServer port (1434) to the internet. It is recommended that Global permission to access the well known services SQLServer port (1434) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-006
#

default port_20 = null

port_20 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["20"]
}

port_20 = false {
    aws_issue["20"]
}

port_20_err = "AWS Security Groups allow internet traffic from internet to FTP-Data port (20)" {
    aws_issue["20"]
}

port_20_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to FTP-Data port (20)",
    "Policy Description": "This policy identifies the security groups which are exposing FTP-Data port (20) to the internet. It is recommended that Global permission to access the well known services FTP-Data port (20) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-007
#

default port_21 = null

port_21 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["21"]
}

port_21 = false {
    aws_issue["21"]
}

port_21_err = "AWS Security Groups allow internet traffic from internet to FTP port (21)" {
    aws_issue["21"]
}

port_21_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to FTP port (21)",
    "Policy Description": "This policy identifies the security groups which are exposing FTP port (21) to the internet. It is recommended that Global permission to access the well known services FTP port (21) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-008
#

default port_22 = null

port_22 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["22"]
}

port_22 = false {
    aws_issue["22"]
}

port_22_err = "AWS Security Groups allow internet traffic to SSH port (22)" {
    aws_issue["22"]
}

port_22_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic to SSH port (22)",
    "Policy Description": "This policy identifies AWS Security Groups which do allow inbound traffic on SSH port (22) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-009
#

default port_23 = null

port_23 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["23"]
}

port_23 = false {
    aws_issue["23"]
}

port_23_err = "AWS Security Groups allow internet traffic from internet to Telnet port (23)" {
    aws_issue["23"]
}

port_23_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to Telnet port (23)",
    "Policy Description": "This policy identifies the security groups which are exposing Telnet port (23) to the internet. It is recommended that Global permission to access the well known services Telnet port (23) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-010
#

default port_25 = null

port_25 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["25"]
}

port_25 = false {
    aws_issue["25"]
}

port_25_err = "AWS Security Groups allow internet traffic from internet to SMTP port (25)" {
    aws_issue["25"]
}

port_25_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to SMTP port (25)",
    "Policy Description": "This policy identifies the security groups which are exposing SMTP port (25) to the internet. It is recommended that Global permission to access the well known services SMTP port (25) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-011
#

default port_3306 = null

port_3306 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["3306"]
}

port_3306 = false {
    aws_issue["3306"]
}

port_3306_err = "AWS Security Groups allow internet traffic from internet to MYSQL port (3306)" {
    aws_issue["3306"]
}

port_3306_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-011",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to MYSQL port (3306)",
    "Policy Description": "This policy identifies the security groups which are exposing MYSQL port (3306) to the internet. It is recommended that Global permission to access the well known services MYSQL port (3306) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-012
#

default port_3389 = null

port_3389 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["3389"]
}

port_3389 = false {
    aws_issue["3389"]
}

port_3389_err = "AWS Security Groups allow internet traffic from internet to RDP port (3389)" {
    aws_issue["3389"]
}

port_3389_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-012",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to RDP port (3389)",
    "Policy Description": "This policy identifies the security groups which is exposing RDP port (3389) to the internet. Security Groups do not allow inbound traffic on RDP port (3389) from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-013
#

default port_4333 = null

port_4333 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["4333"]
}

port_4333 = false {
    aws_issue["4333"]
}

port_4333_err = "AWS Security Groups allow internet traffic from internet to MSQL port (4333)" {
    aws_issue["4333"]
}

port_4333_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-013",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to MSQL port (4333)",
    "Policy Description": "This policy identifies the security groups which are exposing MSQL port (4333) to the internet. It is recommended that Global permission to access the well known services MSQL port (4333) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-014
#

default port_445 = null

port_445 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["445"]
}

port_445 = false {
    aws_issue["445"]
}

port_445_err = "AWS Security Groups allow internet traffic from internet to CIFS port (445)" {
    aws_issue["445"]
}

port_445_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-014",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to CIFS port (445)",
    "Policy Description": "This policy identifies the security groups which are exposing CIFS port (445) to the internet. It is recommended that Global permission to access the well known services CIFS port (445) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-015
#

default port_53 = null

port_53 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["53"]
}

port_53 = false {
    aws_issue["53"]
}

port_53_err = "AWS Security Groups allow internet traffic from internet to DNS port (53)" {
    aws_issue["53"]
}

port_53_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-015",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to DNS port (53)",
    "Policy Description": "This policy identifies the security groups which are exposing DNS port (53) to the internet. It is recommended that Global permission to access the well known services DNS port (53) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-016
#

default port_5432 = null

port_5432 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["5432"]
}

port_5432 = false {
    aws_issue["5432"]
}

port_5432_err = "AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)" {
    aws_issue["5432"]
}

port_5432_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-016",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)",
    "Policy Description": "This policy identifies the security groups which are exposing PostgreSQL port (5432) to the internet. It is recommended that Global permission to access the well known services PostgreSQL port (5432) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-017
#

default port_5500 = null

port_5500 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["5500"]
}

port_5500 = false {
    aws_issue["5500"]
}

port_5500_err = "AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)" {
    aws_issue["5500"]
}

port_5500_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-017",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)",
    "Policy Description": "This policy identifies the security groups which are exposing VNC Listener port (5500) to the internet. It is recommended that Global permission to access the well known services VNC Listener port (5500) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-018
#

default port_5900 = null

port_5900 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["5900"]
}

port_5900 = false {
    aws_issue["5900"]
}

port_5900_err = "AWS Security Groups allow internet traffic from internet to VNC Server port (5900)" {
    aws_issue["5900"]
}

port_5900_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-018",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to VNC Server port (5900)",
    "Policy Description": "This policy identifies the security groups which are exposing VNC Server port (5900) to the internet. It is recommended that Global permission to access the well known services VNC Server port (5900) should not be allowed in a security group.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-019
#

default port_all = null

port_all {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["all"]
}

port_all = false {
    aws_issue["all"]
}

port_all_err = "AWS Default Security Group does not restrict all traffic" {
    aws_issue["all"]
}

port_all_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-019",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Default Security Group does not restrict all traffic",
    "Policy Description": "This policy identifies the default security group which does not restrict all inbound and outbound traffic. A VPC comes with a default security group whose initial configuration deny all inbound traffic from internet and allow all outbound traffic. If you do not specify a security group when you launch an instance, the instance is automatically assigned to this default security group. As a result, the instance may accidentally send outbound traffic.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-020
#

default port_proto_all = null

port_proto_all {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["proto_all"]
}

port_proto_all = false {
    aws_issue["proto_all"]
}

port_proto_all_err = "AWS Security Groups with Inbound rule overly permissive to All Traffic" {
    aws_issue["proto_all"]
}

port_proto_all_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-020",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups with Inbound rule overly permissive to All Traffic",
    "Policy Description": "This policy identifies AWS Security Groups which do allow inbound traffic on all protocols from public internet. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network.",
    "Resource Type": "aws_security_group_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-021
#

default port_69 = null

port_69 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["69"]
}

port_69 = false {
    aws_issue["69"]
}

port_69_err = "AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)" {
    aws_issue["69"]
}

port_69_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-021",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)",
    "Policy Description": "This policy identifies the security groups which are exposing Trivial File Transfer Protocol Port (69) to the internet. It is recommended that Global permission to access the well known services Trivial File Transfer Protocol Port (69) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html"
}

#
# PR-AWS-TRF-SG-022
#

default sg_tag = null

aws_issue["sg_tag"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    count(resource.properties.tags) == 0
}

aws_issue["sg_tag"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    not resource.properties.tags
}

sg_tag {
    lower(input.resources[i].type) == "aws_security_group"
    not aws_issue["sg_tag"]
}

sg_tag = false {
    aws_issue["sg_tag"]
}

sg_tag_err = "Ensure AWS resources that support tags have Tags" {
    aws_issue["sg_tag"]
}

sg_tag_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-022",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure AWS resources that support tags have Tags",
    "Policy Description": "Many different types of AWS resources support tags. Tags allow you to add metadata to a resource to help identify ownership, perform cost / billing analysis, and to enrich a resource with other valuable information, such as descriptions and environment names. While there are many ways that tags can be used, we recommend you follow a tagging practice.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html#cfn-ec2-securitygroup-tags"
}


#
# PR-AWS-TRF-SG-023
#

default sg_description_absent = null

aws_issue["sg_description_absent"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    ingress := resource.properties.ingress[j]
    not ingress.description
}

source_path[{"sg_description_absent": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    ingress := resource.properties.ingress[j]
    not ingress.description
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "description"]
        ],
    }
}

aws_issue["sg_description_absent"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    ingress := resource.properties.ingress[j]
    count(ingress.description) == 0
}

source_path[{"sg_description_absent": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group_rule"
    ingress := resource.properties.ingress[j]
    count(ingress.description) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ingress", j, "description"]
        ],
    }
}

sg_description_absent {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["sg_description_absent"]
}

sg_description_absent = false {
    aws_issue["sg_description_absent"]
}

sg_description_absent_err = "Ensure every Security Group rule contains a description" {
    aws_issue["sg_description_absent"]
}

sg_description_absent_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-023",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure every Security Group rule contains a description",
    "Policy Description": "We recommend you add descriptive text to each of your Security Group Rules clarifying each rule's goals, this helps prevent developer errors.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group"
}


#
# PR-AWS-TRF-SG-024
#

default port_9300 = null

port_9300 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["9300"]
}

port_9300 = false {
    aws_issue["9300"]
}

port_9300_err = "AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)" {
    aws_issue["9300"]
}

port_9300_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-024",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)",
    "Policy Description": "This policy identifies the security groups which are exposing ElasticSearch Protocol Port (9300) to the internet. It is recommended that Global permission to access the well known services ElasticSearch Protocol Port (9300) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group"
}

#
# PR-AWS-TRF-SG-025
#

default port_5601 = null

port_5601 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["5601"]
}

port_5601 = false {
    aws_issue["5601"]
}

port_5601_err = "AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)" {
    aws_issue["5601"]
}

port_5601_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-025",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)",
    "Policy Description": "This policy identifies the security groups which are exposing Kibana Protocol Port (5601) to the internet. It is recommended that Global permission to access the well known services Kibana Protocol Port (5601) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group"
}


#
# PR-AWS-TRF-SG-026
#

default port_2379 = null

port_2379 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["2379"]
}

port_2379 = false {
    aws_issue["2379"]
}

port_2379_err = "AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)" {
    aws_issue["2379"]
}

port_2379_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-026",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)",
    "Policy Description": "This policy identifies the security groups which are exposing etcd-client Protocol Port (2379) to the internet. It is recommended that Global permission to access the well known services etcd-client Protocol Port (2379) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group"
}

#
# PR-AWS-TRF-SG-027
#

default port_5986 = null

port_5986 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["5986"]
}

port_5986 = false {
    aws_issue["5986"]
}

port_5986_err = "AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)" {
    aws_issue["5986"]
}

port_5986_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-027",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)",
    "Policy Description": "This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group"
}


#
# PR-AWS-TRF-SG-028
#

default port_5985 = null

port_5985 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["5985"]
}

port_5985 = false {
    aws_issue["5985"]
}

port_5985_err = "AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)" {
    aws_issue["5985"]
}

port_5985_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-028",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)",
    "Policy Description": "This policy identifies the security groups which are exposing WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) to the internet. It is recommended that Global permission to access the well known services WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group"
}


#
# PR-AWS-TRF-SG-029
#

default port_1270 = null

port_1270 {
    type := ["aws_security_group", "aws_security_group_rule"]
    lower(input.resources[i].type) == type[_]
    not aws_issue["1270"]
}

port_1270 = false {
    aws_issue["1270"]
}

port_1270_err = "AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)" {
    aws_issue["1270"]
}

port_1270_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-029",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)",
    "Policy Description": "This policy identifies the security groups which are exposing Microsoft Operations Manager Protocol Port (1270) to the internet. It is recommended that Global permission to access the well known services Microsoft Operations Manager Protocol Port (1270) should not be allowed in a security group.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group"
}

#
# PR-AWS-TRF-SG-034
#

default ec2_instance_has_restricted_access = null

ec2_instance_allowed_protocols := ["http", "https"]

ec2_instance_allowed_ports := [443, 80]

is_secure["ipv4"] = true {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    SecurityRule := resource.properties.ingress[_]
    lower(SecurityRule.protocol) == ec2_instance_allowed_protocols[_]
    lower(SecurityRule.cidr_blocks[_]) == "0.0.0.0/0"
	SecurityRule.from_port == ec2_instance_allowed_ports[_]
	SecurityRule.to_port == ec2_instance_allowed_ports[_]
    SecurityRule.from_port == SecurityRule.to_port
}

aws_issue["ec2_instance_has_restricted_access"]{
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    SecurityRule := resource.properties.ingress[_]
    lower(SecurityRule.cidr_blocks[_]) == "0.0.0.0/0"
    not is_secure["ipv4"]
}

is_secure["ipv6"] = true {
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    SecurityRule := resource.properties.ingress[_]
    lower(SecurityRule.protocol) == ec2_instance_allowed_protocols[_]
    lower(SecurityRule.ipv6_cidr_blocks[_]) == "::/0"
	SecurityRule.from_port == ec2_instance_allowed_ports[_]
	SecurityRule.to_port == ec2_instance_allowed_ports[_]
    SecurityRule.from_port == SecurityRule.to_port
}

aws_issue["ec2_instance_has_restricted_access"]{
    resource := input.resources[i]
    lower(resource.type) == "aws_security_group"
    SecurityRule := resource.properties.ingress[_]
    lower(SecurityRule.ipv6_cidr_blocks[_]) == "::/0"
    not is_secure["ipv6"]
}

ec2_instance_has_restricted_access_err = "Ensure EC2 instance that is not internet reachable with unrestricted access (0.0.0.0/0) other than HTTP/HTTPS port monitoring is enabled for EC2 instances" {
    aws_issue["ec2_instance_has_restricted_access"]
}

ec2_instance_has_restricted_access {
    lower(input.resources[i].type) == "aws_security_group"
    not aws_issue["ec2_instance_has_restricted_access"]
}

ec2_instance_has_restricted_access = false {
    aws_issue["ec2_instance_has_restricted_access"]
}

ec2_instance_has_restricted_access_metadata := {
    "Policy Code": "PR-AWS-TRF-SG-034",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure EC2 instance that is not internet reachable with unrestricted access (0.0.0.0/0) other than HTTP/HTTPS port monitoring is enabled for EC2 instances",
    "Policy Description": "Ensure restrict traffic from unknown IP addresses and limit the access to known hosts, services, or specific entities. NOTE: We are excluding the HTTP-80 and HTTPs-443 web ports as these are Internet-facing ports with legitimate traffic.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group"
}