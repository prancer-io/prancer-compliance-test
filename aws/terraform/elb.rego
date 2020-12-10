package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html

#
# PR-AWS-0062-TRF
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

aws_issue["elb_insecure_cipher"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_load_balancer_policy"
    policy := resource.properties.policy_attribute[_]
    lower(policy.name) == lower(insecure_ciphers[_])
    lower(policy.value) == "true"
}

elb_insecure_cipher {
    lower(input.json.resources[_].type) == "aws_load_balancer_policy"
    not aws_issue["elb_insecure_cipher"]
}

elb_insecure_cipher = false {
    aws_issue["elb_insecure_cipher"]
}

elb_insecure_cipher_err = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers" {
    aws_issue["elb_insecure_cipher"]
}

#
# PR-AWS-0063-TRF
#

default elb_insecure_protocol = null

insecure_ssl_protocols := [
    "Protocol-SSLv3",
    "Protocol-TLSv1",
    "Protocol-TLSv1.1"
]

aws_issue["elb_insecure_protocol"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_load_balancer_policy"
    policy := resource.properties.policy_attribute[_]
    lower(policy.name) == lower(insecure_ssl_protocols[_])
    lower(policy.value) == "true"
}

elb_insecure_protocol {
    lower(input.json.resources[_].type) == "aws_load_balancer_policy"
    not aws_issue["elb_insecure_protocol"]
}

elb_insecure_protocol = false {
    aws_issue["elb_insecure_protocol"]
}

elb_insecure_protocol_err = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol" {
    aws_issue["elb_insecure_protocol"]
}

#
# PR-AWS-0064-TRF
#

default elb_access_log = null

aws_issue["elb_access_log"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elb"
    resource.properties.access_logs.enabled == false
}

elb_access_log {
    lower(input.json.resources[_].type) == "aws_elb"
    not aws_issue["elb_access_log"]
}

elb_access_log = false {
    aws_issue["elb_access_log"]
}

elb_access_log_err = "AWS Elastic Load Balancer (Classic) with access log disabled" {
    aws_issue["elb_access_log"]
}

#
# PR-AWS-0065-TRF
#

default elb_conn_drain = null

aws_issue["elb_conn_drain"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elb"
    not resource.properties.connection_draining
}

elb_conn_drain {
    lower(input.json.resources[_].type) == "aws_elb"
    not aws_issue["elb_conn_drain"]
}

elb_conn_drain = false {
    aws_issue["elb_conn_drain"]
}

elb_conn_drain_err = "AWS Elastic Load Balancer (Classic) with connection draining disabled" {
    aws_issue["elb_conn_drain"]
}

#
# PR-AWS-0066-TRF
#

default elb_crosszone = null

aws_issue["elb_crosszone"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elb"
    resource.properties.cross_zone_load_balancing == false
}

elb_crosszone {
    lower(input.json.resources[_].type) == "aws_elb"
    not aws_issue["elb_crosszone"]
}

elb_crosszone = false {
    aws_issue["elb_crosszone"]
}

elb_crosszone_err = "AWS Elastic Load Balancer (Classic) with cross-zone load balancing disabled" {
    aws_issue["elb_access_log"]
}

#
# PR-AWS-0067-TRF
# PR-AWS-0068-TRF
#

# There is only reference to security groups, no info about security group rules

default elb_sec_group = null

aws_attribute_absence["elb_sec_group"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elb"
    not resource.properties.security_groups
}

aws_issue["elb_sec_group"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elb"
    count(resource.properties.security_groups) == 0
}

elb_sec_group {
    lower(input.json.resources[_].type) == "aws_elb"
    not aws_issue["elb_sec_group"]
}

elb_sec_group = false {
    aws_issue["elb_sec_group"]
}

elb_sec_group_err = "AWS Elastic Load Balancer (ELB) has security group with no inbound/outbound rules" {
    aws_issue["elb_access_log"]
}

elb_sec_group_miss_err = "ELB attribute security_groups missing in the resource" {
    aws_issue["elb_access_log"]
}

#
# PR-AWS-0069-TRF
#

default elb_not_in_use = null

aws_attribute_absence["elb_not_in_use"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elb"
    not resource.properties.instances
}

aws_issue["elb_not_in_use"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elb"
    count(resource.properties.instances) == 0
}

elb_not_in_use {
    lower(input.json.resources[_].type) == "aws_elb"
    not aws_issue["elb_not_in_use"]
    not aws_attribute_absence["elb_not_in_use"]
}

elb_not_in_use = false {
    aws_issue["elb_not_in_use"]
}

elb_not_in_use = false {
    aws_attribute_absence["elb_not_in_use"]
}

elb_not_in_use_err = "AWS Elastic Load Balancer (ELB) not in use" {
    aws_issue["elb_not_in_use"]
}

elb_not_in_use_miss_err = "ELB attribute instances missing in the resource" {
    aws_attribute_absence["elb_not_in_use"]
}

#
# PR-AWS-0072-TRF
#


default elb_alb_logs = null

aws_attribute_absence["elb_alb_logs"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_lb"
    not resource.properties.access_logs
}

aws_issue["elb_alb_logs"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_lb"
    resource.properties.access_logs[_].enabled != true
}

aws_issue["elb_alb_logs"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_lb"
    count(resource.properties.access_logs) == 0
}

elb_alb_logs {
    lower(input.json.resources[_].type) == "aws_lb"
    not aws_attribute_absence["elb_alb_logs"]
    not aws_issue["elb_alb_logs"]
}

elb_alb_logs = false {
    aws_issue["elb_alb_logs"]
}

elb_alb_logs = false {
    aws_attribute_absence["elb_alb_logs"]
}

elb_alb_logs_err = "AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled" {
    aws_issue["elb_alb_logs"]
}

elb_alb_logs_miss_err = "ELBv2 attribute access_logs.enabled missing in the resource" {
    aws_attribute_absence["elb_alb_logs"]
}

#
# PR-AWS-0073-TRF
#

default elb_listener_ssl = null

aws_attribute_absence["elb_listener_ssl"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elb"
    not resource.properties.listeners
}

aws_issue["elb_listener_ssl"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elb"
    resource.properties.listeners[_].ssl_certificate_id == ""
}

aws_issue["elb_listener_ssl"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elb"
    resource.properties.listeners[_].ssl_certificate_id == null
}

aws_issue["elb_listener_ssl"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elb"
    listener := resource.properties.listeners[_]
    not listener.ssl_certificate_id
}

elb_listener_ssl {
    lower(input.json.resources[_].type) == "aws_elb"
    not aws_issue["elb_listener_ssl"]
    not aws_attribute_absence["elb_listener_ssl"]
}

elb_listener_ssl = false {
    aws_issue["elb_listener_ssl"]
}

elb_listener_ssl = false {
    aws_attribute_absence["elb_listener_ssl"]
}

elb_listener_ssl_err = "AWS Elastic Load Balancer with listener TLS/SSL disabled" {
    aws_issue["elb_listener_ssl"]
}

elb_listener_ssl_miss_err = "ELB attribute listeners missing in the resource" {
    aws_attribute_absence["elb_listener_ssl"]
}

#
# PR-AWS-0006-TRF
#

default elb_over_https = null

aws_attribute_absence["elb_over_https"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elb"
    listener := resource.properties.listener[_]
    not listener.lb_protocol
}

aws_issue["elb_over_https"] {
    resource := input.json.resources[_]
    lower(resource.type) == "aws_elb"
    lower(resource.properties.listener[_].lb_protocol) == "http"
}

elb_over_https {
    lower(input.json.resources[_].type) == "aws_elb"
    not aws_issue["elb_over_https"]
    not aws_attribute_absence["elb_over_https"]
}

elb_over_https = false {
    aws_issue["elb_over_https"]
}

elb_over_https = false {
    aws_attribute_absence["elb_over_https"]
}

elb_over_https_err = "AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled" {
    aws_issue["elb_over_https"]
}

elb_over_https_miss_err = "ELBv2 attribute lb_protocol missing in the resource" {
    aws_attribute_absence["elb_over_https"]
}
