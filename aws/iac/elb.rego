package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html

#
# Id: 62
#

default elb_insecure_cipher = null

insecure_ciphers := [
    "DHE-RSA-AES128-SHA",
    "DHE-DSS-AES128-SHA",
    "CAMELLIA128-SHA",
    "EDH-RSA-DES-CBC3-SHA",
    "DES-CBC3-SHA",
    "ECDHE-RSA-RC4-SHA",
    "RC4-SHA",
    "ECDHE-ECDSA-RC4-SHA",
    "DHE-DSS-AES256-GCM-SHA384",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES256-SHA256",
    "DHE-DSS-AES256-SHA256",
    "DHE-RSA-AES256-SHA",
    "DHE-DSS-AES256-SHA",
    "DHE-RSA-CAMELLIA256-SHA",
    "DHE-DSS-CAMELLIA256-SHA",
    "CAMELLIA256-SHA",
    "EDH-DSS-DES-CBC3-SHA",
    "DHE-DSS-AES128-GCM-SHA256",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES128-SHA256",
    "DHE-DSS-AES128-SHA256",
    "DHE-RSA-CAMELLIA128-SHA",
    "DHE-DSS-CAMELLIA128-SHA",
    "ADH-AES128-GCM-SHA256",
    "ADH-AES128-SHA",
    "ADH-AES128-SHA256",
    "ADH-AES256-GCM-SHA384",
    "ADH-AES256-SHA",
    "ADH-AES256-SHA256",
    "ADH-CAMELLIA128-SHA",
    "ADH-CAMELLIA256-SHA",
    "ADH-DES-CBC3-SHA",
    "ADH-DES-CBC-SHA",
    "ADH-RC4-MD5",
    "ADH-SEED-SHA",
    "DES-CBC-SHA",
    "DHE-DSS-SEED-SHA",
    "DHE-RSA-SEED-SHA",
    "EDH-DSS-DES-CBC-SHA",
    "EDH-RSA-DES-CBC-SHA",
    "IDEA-CBC-SHA",
    "RC4-MD5",
    "SEED-SHA",
    "DES-CBC3-MD5",
    "DES-CBC-MD5",
    "RC2-CBC-MD5",
    "PSK-AES256-CBC-SHA",
    "PSK-3DES-EDE-CBC-SHA",
    "KRB5-DES-CBC3-SHA",
    "KRB5-DES-CBC3-MD5",
    "PSK-AES128-CBC-SHA",
    "PSK-RC4-SHA",
    "KRB5-RC4-SHA",
    "KRB5-RC4-MD5",
    "KRB5-DES-CBC-SHA",
    "KRB5-DES-CBC-MD5",
    "EXP-EDH-RSA-DES-CBC-SHA",
    "EXP-EDH-DSS-DES-CBC-SHA",
    "EXP-ADH-DES-CBC-SHA",
    "EXP-DES-CBC-SHA",
    "EXP-RC2-CBC-MD5",
    "EXP-KRB5-RC2-CBC-SHA",
    "EXP-KRB5-DES-CBC-SHA",
    "EXP-KRB5-RC2-CBC-MD5",
    "EXP-KRB5-DES-CBC-MD5",
    "EXP-ADH-RC4-MD5",
    "EXP-RC4-MD5",
    "EXP-KRB5-RC4-SHA",
    "EXP-KRB5-RC4-MD5"
]

elb_insecure_cipher_f["insecure_ciphers"] {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    policy := input.Properties.Policies
    attribute := policy.Attributes[_]
    lower(attribute.AttributeName) == lower(insecure_ciphers[_])
    attribute.AttributeValue == "true"
}

elb_insecure_cipher {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(elb_insecure_cipher_f) == 0
}

elb_insecure_cipher = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(elb_insecure_cipher_f) > 0
}

elb_insecure_cipher_err = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers" {
    elb_insecure_cipher == false
}

#
# Id: 63
#

default elb_insecure_protocol = null

insecure_ssl_protocols := [
    "Protocol-SSLv3",
    "Protocol-TLSv1",
    "Protocol-TLSv1.1"
]

elb_insecure_protocol_f["insecure_protocols"] {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    policy := input.Properties.Policies
    attribute := policy.Attributes[_]
    lower(attribute.AttributeName) == lower(insecure_ssl_protocols[_])
    lower(attribute.AttributeValue) == "true"
}

elb_insecure_protocol {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(elb_insecure_protocol_f) == 0
}

elb_insecure_protocol = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(elb_insecure_protocol_f) > 0
}

elb_insecure_protocol_err = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol" {
    elb_insecure_protocol == false
}

#
# Id: 64
#

default elb_access_log = null

elb_access_log {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    input.Properties.AccessLoggingPolicy.Enabled == true
}

elb_access_log = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    input.Properties.AccessLoggingPolicy.Enabled == false
}

elb_access_log_err = "AWS Elastic Load Balancer (Classic) with access log disabled" {
    elb_access_log == false
}

#
# Id: 65
#

default elb_conn_drain = null

elb_conn_drain {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    input.Properties.ConnectionDraining.Enabled == true
}

elb_conn_drain = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    input.Properties.ConnectionDraining.Enabled == false
}

elb_conn_drain_err = "AWS Elastic Load Balancer (Classic) with connection draining disabled" {
    elb_conn_drain == false
}

#
# Id: 66
#

default elb_crosszone = null

elb_crosszone {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    input.Properties.CrossZone == true
}

elb_crosszone = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    input.Properties.CrossZone == false
}

elb_crosszone_err = "AWS Elastic Load Balancer (Classic) with cross-zone load balancing disabled" {
    elb_crosszone == false
}

#
# Id: 67, 68
#

# There is only reference to security groups, no info about security group rules

default elb_sec_group = null

elb_sec_group {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(input.Properties.SecurityGroups) > 0
}

elb_sec_group = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(input.Properties.SecurityGroups) == 0
}

elb_sec_group_err = "AWS Elastic Load Balancer (ELB) has security group with no inbound/outbound rules" {
    elb_crosszone == false
}

#
# Id: 69
#

default elb_not_in_use = null

elb_not_in_use {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(input.Properties.Instances) > 0
}

elb_not_in_use = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(input.Properties.Instances) == 0
}

elb_not_in_use = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    not input.Properties.Instances
}

elb_not_in_use_err = "AWS Elastic Load Balancer (ELB) not in use" {
    elb_not_in_use == false
}


#
# Id: 72
#

default elb_alb_logs = null

elb_alb_logs {
    lower(input.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    input.Properties.LoadBalancerAttribute.Key == "access_logs.s3.enabled"
    input.Properties.LoadBalancerAttribute.Value == "true"
}

elb_alb_logs = false {
    lower(input.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    input.Properties.LoadBalancerAttribute.Key == "access_logs.s3.enabled"
    input.Properties.LoadBalancerAttribute.Value == "false"
}

elb_alb_logs_err = "AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled" {
    elb_alb_logs == false
}

#
# Id: 73
#


default elb_listener_ssl = null

elb_listener_ssl_f["empty_ssl"] {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    input.Properties.Listeners[_].SSLCertificateId == ""
}

elb_listener_ssl_f["null_ssl"] {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    input.Properties.Listeners[_].SSLCertificateId == null
}

elb_listener_ssl_f["missing_ssl"] {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    listener := input.Properties.Listeners[_]
    not listener.SSLCertificateId
}

elb_listener_ssl {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(elb_listener_ssl_f) == 0
}

elb_listener_ssl = false {
    lower(input.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(elb_listener_ssl_f) > 0
}

elb_listener_ssl_err = "AWS Elastic Load Balancer with listener TLS/SSL disabled" {
    elb_listener_ssl == false
}
