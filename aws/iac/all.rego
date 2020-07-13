package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-stage.html

#
# Id: 2
#

default api_gw_cert = null

api_gw_cert {
    lower(input.Type) == "aws::apigateway::stage"
    lower(input.Properties.ClientCertificateId) != "none"
}

api_gw_cert = false {
    lower(input.Type) == "aws::apigateway::stage"
    not input.Properties.ClientCertificateId
}

api_gw_cert = false {
    lower(input.Type) == "aws::apigateway::stage"
    lower(input.Properties.ClientCertificateId) == "none"
}

api_gw_cert_err = "AWS API Gateway endpoints without client certificate authentication" {
    api_gw_cert == false
}

#
# Id: 359
#

default db_exposed = null

db_ports := [
    1433, 1521, 3306, 5000, 5432, 5984, 6379, 6380, 8080, 9042, 11211, 27017, 28015, 29015, 50000
]

db_exposed_f["ipv4"] {
    lower(input.Type) == "aws::ec2::securitygroup"
    ingress := input.Properties.SecurityGroupIngress[_]
    port := db_ports[_]
    ingress.CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

db_exposed_f["ipv6"] {
    lower(input.Type) == "aws::ec2::securitygroup"
    ingress := input.Properties.SecurityGroupIngress[_]
    port := db_ports[_]
    ingress.CidrIpv6="::/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

db_exposed {
    lower(input.Type) == "aws::ec2::securitygroup"
    count(db_exposed_f) == 0
}

db_exposed = false {
    lower(input.Type) == "aws::ec2::securitygroup"
    count(db_exposed_f) > 0
}

db_exposed_err = "Publicly exposed DB Ports" {
    db_exposed == false
}

#
# Id: 349
#

default bitcoin_ports = null

bc_ports := [
    8332, 8333
]

bitcoin_ports_f["ipv4"] {
    lower(input.Type) == "aws::ec2::securitygroup"
    ingress := input.Properties.SecurityGroupIngress[_]
    port := bc_ports[_]
    ingress.CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

bitcoin_ports_f["ipv6"] {
    lower(input.Type) == "aws::ec2::securitygroup"
    ingress := input.Properties.SecurityGroupIngress[_]
    port := bc_ports[_]
    ingress.CidrIpv6="::/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

bitcoin_ports {
    lower(input.Type) == "aws::ec2::securitygroup"
    count(bitcoin_ports_f) == 0
}

bitcoin_ports = false {
    lower(input.Type) == "aws::ec2::securitygroup"
    count(bitcoin_ports_f) > 0
}

bitcoin_ports_err = "Instance is communicating with ports known to mine Bitcoin" {
    bitcoin_ports == false
}

#
# Id: 350
#

default ethereum_ports = null

eth_ports := [
    8545, 30303
]

ethereum_ports_f["ipv4"] {
    lower(input.Type) == "aws::ec2::securitygroup"
    ingress := input.Properties.SecurityGroupIngress[_]
    port := eth_ports[_]
    ingress.CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

ethereum_ports_f["ipv6"] {
    lower(input.Type) == "aws::ec2::securitygroup"
    ingress := input.Properties.SecurityGroupIngress[_]
    port := eth_ports[_]
    ingress.CidrIpv6="::/0"
    to_number(ingress.FromPort) <= port
    to_number(ingress.ToPort) >= port
}

ethereum_ports {
    lower(input.Type) == "aws::ec2::securitygroup"
    count(ethereum_ports_f) == 0
}

ethereum_ports = false {
    lower(input.Type) == "aws::ec2::securitygroup"
    count(ethereum_ports_f) > 0
}

ethereum_ports_err = "Instance is communicating with ports known to mine Ethereum" {
    ethereum_ports == false
}
