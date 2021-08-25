package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html

#
# PR-AWS-0002-CFR
#

default api_gw_cert = null

aws_issue["api_gw_cert"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    not resource.Properties.ClientCertificateId
}

aws_issue["api_gw_cert"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::apigateway::stage"
    count(resource.Properties.ClientCertificateId) == 0
}

api_gw_cert {
    lower(input.Resources[i].Type) == "aws::apigateway::stage"
    not aws_issue["api_gw_cert"]
}

api_gw_cert = false {
    aws_issue["api_gw_cert"]
}

api_gw_cert_err = "AWS API Gateway endpoints without client certificate authentication" {
    aws_issue["api_gw_cert"]
}

api_gw_cert_metadata := {
    "Policy Code": "PR-AWS-0002-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS API Gateway endpoints without client certificate authentication",
    "Policy Description": "API Gateway can generate an SSL certificate and use its public key in the backend to verify that HTTP requests to your backend system are from API Gateway. This allows your HTTP backend to control and accept only requests originating from Amazon API Gateway, even if the backend is publicly accessible._x005F_x000D_ _x005F_x000D_ Note: Some backend servers may not support SSL client authentication as API Gateway does and could return an SSL certificate error. For a list of incompatible backend servers, see Known Issues. https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html",
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
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html"
}


#
# PR-AWS-0257-CFR
#

default dax_encrypt = null

aws_issue["dax_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dax::cluster"
    lower(resource.Properties.SSESpecification.SSEEnabled) != "true"
}

aws_bool_issue["dax_encrypt"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::dax::cluster"
    not resource.Properties.SSESpecification.SSEEnabled
}

dax_encrypt {
    lower(input.Resources[i].Type) == "aws::dax::cluster"
    not aws_issue["dax_encrypt"]
    not aws_bool_issue["dax_encrypt"]
}

dax_encrypt = false {
    aws_issue["dax_encrypt"]
}

dax_encrypt = false {
    aws_bool_issue["dax_encrypt"]
}

dax_encrypt_err = "Ensure DAX is securely encrypted at rest" {
    aws_issue["dax_encrypt"]
} else = "Ensure DAX is securely encrypted at rest" {
    aws_bool_issue["dax_encrypt"]
}

dax_encrypt_metadata := {
    "Policy Code": "PR-AWS-0257-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure DAX is securely encrypted at rest",
    "Policy Description": "Amazon DynamoDB Accelerator (DAX) encryption at rest provides an additional layer of data protection, helping secure your data from unauthorized access to underlying storage. With encryption at rest the data persisted by DAX on disk is encrypted using 256-bit Advanced Encryption Standard (AES-256). DAX writes data to disk as part of propagating changes from the primary node to read replicas. DAX encryption at rest automatically integrates with AWS KMS for managing the single service default key used to encrypt clusters.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dax-cluster-ssespecification.html"
}


#
# PR-AWS-0259-CFR
#

default qldb_permission_mode = null

aws_issue["qldb_permission_mode"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::qldb::ledger"
    lower(resource.Properties.PermissionsMode) != "standard"
}

aws_issue["qldb_permission_mode"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::qldb::ledger"
    not resource.Properties.PermissionsMode
}

qldb_permission_mode {
    lower(input.Resources[i].Type) == "aws::qldb::ledger"
    not aws_issue["qldb_permission_mode"]
}

qldb_permission_mode = false {
    aws_issue["qldb_permission_mode"]
}

qldb_permission_mode_err = "Ensure QLDB ledger permissions mode is set to STANDARD" {
    aws_issue["qldb_permission_mode"]
}

qldb_permission_mode_metadata := {
    "Policy Code": "PR-AWS-0259-CFR",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure QLDB ledger permissions mode is set to STANDARD",
    "Policy Description": "In Amazon Quantum Ledger Database define PermissionsMode value to STANDARD permissions mode that enables access control with finer granularity for ledgers, tables, and PartiQL commands",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-permissionsmode"
}
