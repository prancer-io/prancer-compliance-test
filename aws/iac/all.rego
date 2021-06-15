package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html

#
# PR-AWS-0002-CFR
#

default api_gw_cert = null

aws_attribute_absence["api_gw_cert"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    not resource.Properties.ClientCertificateId
}

aws_issue["api_gw_cert"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    lower(resource.Properties.ClientCertificateId) == "none"
}

api_gw_cert {
    lower(input.Resources[i].Type) == "aws::apigateway::stage"
    not aws_issue["api_gw_cert"]
    not aws_attribute_absence["api_gw_cert"]
}

api_gw_cert = false {
    aws_issue["api_gw_cert"]
}

api_gw_cert = false {
    aws_attribute_absence["api_gw_cert"]
}

api_gw_cert_err = "AWS API Gateway endpoints without client certificate authentication" {
    aws_issue["api_gw_cert"]
}

api_gw_cert_miss_err = "API Gateway attribute ClientCertificateId missing in the resource" {
    aws_attribute_absence["api_gw_cert"]
}

api_gw_cert_metadata := {
    "Policy Code": "PR-AWS-0002-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS API Gateway endpoints without client certificate authentication",
    "Policy Description": "API Gateway can generate an SSL certificate and use its public key in the backend to verify that HTTP requests to your backend system are from API Gateway. This allows your HTTP backend to control and accept only requests originating from Amazon API Gateway, even if the backend is publicly accessible._x005F_x000D_ _x005F_x000D_ Note: Some backend servers may not support SSL client authentication as API Gateway does and could return an SSL certificate error. For a list of incompatible backend servers, see Known Issues. https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html",
    "Compliance": ["CSA-CCM","HITRUST", "ISO 27001","NIST 800"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}

#
# gID6
#

default db_exposed = null

db_ports := [
    1433, 1521, 3306, 5000, 5432, 5984, 6379, 6380, 8080, 9042, 11211, 27017, 28015, 29015, 50000
]

aws_issue["db_exposed"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := db_ports[_]
    ingress.CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

aws_issue["db_exposed"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := db_ports[_]
    ingress.CidrIpv6="::/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

db_exposed {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["db_exposed"]
}

db_exposed = false {
    aws_issue["db_exposed"]
}

db_exposed_err = "Publicly exposed DB Ports" {
    aws_issue["db_exposed"]
}

db_exposed_metadata := {
    "Policy Code": "",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Publicly exposed DB Ports",
    "Policy Description": "DB Servers contain sensitive data and should not be exposed to any direct traffic from internet. This policy checks for the network traffic from internet hitting the DB Servers on their default ports. The DB servers monitored on the default ports are : Microsoft SQL Server (1433), Oracle (1521), MySQL (3306), Sybase (5000), Postgresql (5432), CouchDB (5984), Redis (6379, 6380), RethinkDB (8080,28015, 29015), CassandraDB (9042), Memcached (11211), MongoDB (27017), DB2 (50000).",
    "Compliance": [],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}

#
# gID1
#

default bitcoin_ports = null

bc_ports := [
    8332, 8333
]

aws_issue["bitcoin_ports"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := bc_ports[_]
    ingress.CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

aws_issue["bitcoin_ports"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := bc_ports[_]
    ingress.CidrIpv6="::/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

bitcoin_ports {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["bitcoin_ports"]
}

bitcoin_ports = false {
    aws_issue["bitcoin_ports"]
}

bitcoin_ports_err = "Instance is communicating with ports known to mine Bitcoin" {
    aws_issue["bitcoin_ports"]
}

bitcoin_ports_metadata := {
    "Policy Code": "",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Instance is communicating with ports known to mine Bitcoin",
    "Policy Description": "Identifies traffic from internal workloads to internet IPs on ports 8332,8333 that are known to mine Bitcoins. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.",
    "Compliance": ["HIPAA","NIST 800"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}

#
# gID2
#

default ethereum_ports = null

eth_ports := [
    8545, 30303
]

aws_issue["ethereum_ports"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := eth_ports[_]
    ingress.CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

aws_issue["ethereum_ports"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::ec2::securitygroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    port := eth_ports[_]
    ingress.CidrIpv6="::/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

ethereum_ports {
    lower(input.Resources[i].Type) == "aws::ec2::securitygroup"
    not aws_issue["ethereum_ports"]
}

ethereum_ports = false {
    aws_issue["ethereum_ports"]
}

ethereum_ports_err = "Instance is communicating with ports known to mine Ethereum" {
    aws_issue["ethereum_ports"]
}

ethereum_ports_metadata := {
    "Policy Code": "",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Instance is communicating with ports known to mine Ethereum",
    "Policy Description": "Ethereum Identifies traffic from internal workloads to internet IPs on ports 8545,30303 that are known to mine Ethereum. Unless this traffic is part of authorized applications and processes, your instances may have been compromised.",
    "Compliance": ["HIPAA","NIST 800"],
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}
