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
