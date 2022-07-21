package rule


#
# PR-AWS-TRF-ELB-001
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
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    policy := resource.properties.policy_attribute[j]
    lower(policy.name) == lower(insecure_ciphers[_])
    lower(policy.value) == "true"
}

source_path[{"elb_insecure_cipher": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    policy := resource.properties.policy_attribute[j]
    lower(policy.name) == lower(insecure_ciphers[_])
    lower(policy.value) == "true"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy_attribute", j, "value"]
        ],
    }
}

aws_bool_issue["elb_insecure_cipher"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    policy := resource.properties.policy_attribute[j]
    lower(policy.name) == lower(insecure_ciphers[_])
    policy.value == true
}

source_path[{"elb_insecure_cipher": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    policy := resource.properties.policy_attribute[j]
    lower(policy.name) == lower(insecure_ciphers[_])
    policy.value == true

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy_attribute", j, "value"]
        ],
    }
}

elb_insecure_cipher {
    lower(input.resources[i].type) == "aws_load_balancer_policy"
    not aws_issue["elb_insecure_cipher"]
    not aws_bool_issue["elb_insecure_cipher"]
}

elb_insecure_cipher = false {
    aws_issue["elb_insecure_cipher"]
}

elb_insecure_cipher = false {
    aws_bool_issue["elb_insecure_cipher"]
}

elb_insecure_cipher_err = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers" {
    aws_issue["elb_insecure_cipher"]
} else = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers" {
    aws_bool_issue["elb_insecure_cipher"]
}

elb_insecure_cipher_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers",
    "Policy Description": "This policy identifies Elastic Load Balancers (Classic) which are configured with SSL negotiation policy containing insecure ciphers. An SSL cipher is an encryption algorithm that uses encryption keys to create a coded message. SSL protocols use several SSL ciphers to encrypt data over the Internet. As many of the other ciphers are not secure, it is recommended to use only the ciphers recommended in the following AWS link: https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-ssl-security-policy.html.",
    "Resource Type": "aws_elb",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-TRF-ELB-002
#

default elb_insecure_protocol = null

insecure_ssl_protocols := [
    "protocol-SSLv3",
    "protocol-TLSv1",
    "protocol-TLSv1.1"
]

aws_issue["elb_insecure_protocol"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    policy := resource.properties.policy_attribute[j]
    lower(policy.name) == lower(insecure_ssl_protocols[_])
    lower(policy.value) == "true"
}

source_path[{"elb_insecure_cipher": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    policy := resource.properties.policy_attribute[j]
    lower(policy.name) == lower(insecure_ssl_protocols[_])
    lower(policy.value) == "true"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy_attribute", j, "value"]
        ],
    }
}

aws_bool_issue["elb_insecure_protocol"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    policy := resource.properties.policy_attribute[j]
    lower(policy.name) == lower(insecure_ssl_protocols[_])
    policy.value == true
}

source_path[{"elb_insecure_cipher": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    policy := resource.properties.policy_attribute[j]
    lower(policy.name) == lower(insecure_ssl_protocols[_])
    policy.value == true

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy_attribute", j, "value"]
        ],
    }
}

elb_insecure_protocol {
    lower(input.resources[i].type) == "aws_load_balancer_policy"
    not aws_issue["elb_insecure_protocol"]
    not aws_bool_issue["elb_insecure_protocol"]
}

elb_insecure_protocol = false {
    aws_issue["elb_insecure_protocol"]
}

elb_insecure_protocol = false {
    aws_bool_issue["elb_insecure_protocol"]
}

elb_insecure_protocol_err = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol" {
    aws_issue["elb_insecure_protocol"]
} else = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol" {
    aws_bool_issue["elb_insecure_protocol"]
}

elb_insecure_protocol_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol",
    "Policy Description": "This policy identifies Elastic Load Balancers (Classic) which are configured with SSL negotiation policy containing vulnerable SSL protocol. The SSL protocol establishes a secure connection between a client and a server and ensures that all the data passed between the client and your load balancer is private. As a security best practice, it is recommended to use the latest version SSL protocol.",
    "Resource Type": "aws_elb",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-TRF-ELB-003
#

default elb_access_log = null

aws_attribute_absence["elb_access_log"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    not resource.properties.access_logs
}

source_path[{"elb_access_log": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    not resource.properties.access_logs

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "access_logs"]
        ],
    }
}

aws_issue["elb_access_log"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    count(resource.properties.access_logs) == 0
}

source_path[{"elb_access_log": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    count(resource.properties.access_logs) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "access_logs"]
        ],
    }
}

aws_issue["elb_access_log"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    access_logs := resource.properties.access_logs[j]
    lower(access_logs.enabled) == "false"
}

source_path[{"elb_access_log": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    access_logs := resource.properties.access_logs[j]
    lower(access_logs.enabled) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "access_logs", j, "enabled"]
        ],
    }
}

aws_bool_issue["elb_access_log"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    access_logs := resource.properties.access_logs[j]
    access_logs.enabled == false
}

source_path[{"elb_access_log": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    access_logs := resource.properties.access_logs[j]
    access_logs.enabled == false

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "access_logs", j, "enabled"]
        ],
    }
}

elb_access_log {
    lower(input.resources[i].type) == "aws_elb"
    not aws_issue["elb_access_log"]
    not aws_bool_issue["elb_access_log"]
    not aws_attribute_absence["elb_access_log"]
}

elb_access_log = false {
    aws_issue["elb_access_log"]
} else = false {
    aws_bool_issue["elb_access_log"]
} else = false {
    aws_attribute_absence["elb_access_log"]
}

elb_access_log_err = "AWS Elastic Load Balancer (Classic) with access log disabled" {
    aws_issue["elb_access_log"]
} else = "AWS Elastic Load Balancer (Classic) with access log disabled" {
    aws_bool_issue["elb_access_log"]
} else = "AWS Elastic Load Balancer (Classic) attribute access_logs is missing in the resource" {
    aws_attribute_absence["elb_access_log"]
}

elb_access_log_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elastic Load Balancer (Classic) with access log disabled",
    "Policy Description": "This policy identifies Classic Elastic Load Balancers which have access log disabled. When Access log enabled, Classic load balancer captures detailed information about requests sent to your load balancer. Each log contains information such as the time the request was received, the client's IP address, latencies, request paths, and server responses. You can use these access logs to analyze traffic patterns and to troubleshoot issues.",
    "Resource Type": "aws_elb",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-TRF-ELB-004
#

default elb_conn_drain = null

aws_issue["elb_conn_drain"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    lower(resource.properties.connection_draining) == "false"
}

source_path[{"elb_conn_drain": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    lower(resource.properties.connection_draining) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "connection_draining"]
        ],
    }
}

aws_bool_issue["elb_conn_drain"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    not resource.properties.connection_draining
}

source_path[{"elb_conn_drain": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    not resource.properties.connection_draining

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "connection_draining"]
        ],
    }
}

elb_conn_drain {
    lower(input.resources[i].type) == "aws_elb"
    not aws_issue["elb_conn_drain"]
    not aws_bool_issue["elb_conn_drain"]
}

elb_conn_drain = false {
    aws_issue["elb_conn_drain"]
}

elb_conn_drain = false {
    aws_bool_issue["elb_conn_drain"]
}

elb_conn_drain_err = "AWS Elastic Load Balancer (Classic) with connection draining disabled" {
    aws_issue["elb_conn_drain"]
} else = "AWS Elastic Load Balancer (Classic) with connection draining disabled" {
    aws_bool_issue["elb_conn_drain"]
}

elb_conn_drain_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elastic Load Balancer (Classic) with connection draining disabled",
    "Policy Description": "This policy identifies Classic Elastic Load Balancers which have connection draining disabled. Connection Draining feature ensures that a Classic load balancer stops sending requests to instances that are de-registering or unhealthy, while keeping the existing connections open. This enables the load balancer to complete in-flight requests made to instances that are de-registering or unhealthy.",
    "Resource Type": "aws_elb",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-TRF-ELB-005
#

default elb_crosszone = null

aws_issue["elb_crosszone"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    lower(resource.properties.cross_zone_load_balancing) == "false"
}

source_path[{"elb_crosszone": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    lower(resource.properties.cross_zone_load_balancing) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cross_zone_load_balancing"]
        ],
    }
}

aws_bool_issue["elb_crosszone"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    resource.properties.cross_zone_load_balancing == false
}

source_path[{"elb_crosszone": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    resource.properties.cross_zone_load_balancing == false

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "cross_zone_load_balancing"]
        ],
    }
}

elb_crosszone {
    lower(input.resources[i].type) == "aws_elb"
    not aws_issue["elb_crosszone"]
    not aws_bool_issue["elb_crosszone"]
}

elb_crosszone = false {
    aws_issue["elb_crosszone"]
}

elb_crosszone = false {
    aws_bool_issue["elb_crosszone"]
}

elb_crosszone_err = "AWS Elastic Load Balancer (Classic) with cross-zone load balancing disabled" {
    aws_issue["elb_crosszone"]
} else = "AWS Elastic Load Balancer (Classic) with cross-zone load balancing disabled" {
    aws_bool_issue["elb_crosszone"]
}

elb_crosszone_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elastic Load Balancer (Classic) with cross-zone load balancing disabled",
    "Policy Description": "This policy identifies Classic Elastic Load Balancers which have cross-zone load balancing disabled. When Cross-zone load balancing enabled, classic load balancer distributes requests evenly across the registered instances in all enabled Availability Zones. Cross-zone load balancing reduces the need to maintain equivalent numbers of instances in each enabled Availability Zone, and improves your application's ability to handle the loss of one or more instances.",
    "Resource Type": "aws_elb",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-TRF-ELB-008
#

default elb_not_in_use = null

aws_attribute_absence["elb_not_in_use"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    not resource.properties.instances
}

source_path[{"elb_not_in_use": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    not resource.properties.instances

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "instances"]
        ],
    }
}

aws_issue["elb_not_in_use"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    count(resource.properties.instances) == 0
}

source_path[{"elb_not_in_use": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    count(resource.properties.instances) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "instances"]
        ],
    }
}

elb_not_in_use {
    lower(input.resources[i].type) == "aws_elb"
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
} else = "ELB attribute instances missing in the resource" {
    aws_attribute_absence["elb_not_in_use"]
}

elb_not_in_use_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elastic Load Balancer (ELB) not in use",
    "Policy Description": "This policy identifies unused Elastic Load Balancers (ELBs) in your AWS account. Any Elastic Load Balancer in your AWS account is adding charges to your monthly bill, although it is not used by any resources. As a best practice, it is recommended to remove ELBs that are not associated with any instances, it will also help you avoid unexpected charges on your bill.",
    "Resource Type": "aws_elb",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-TRF-ELB-009
#


default elb_alb_logs = null

aws_attribute_absence["elb_alb_logs"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    not resource.properties.access_logs
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    not resource.properties.access_logs

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "access_logs"]
        ],
    }
}

aws_issue["elb_alb_logs"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    access_logs := resource.properties.access_logs[j]
    lower(access_logs.enabled) == "false"
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    access_logs := resource.properties.access_logs[j]
    lower(access_logs.enabled) == "false"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "access_logs", j, "enabled"]
        ],
    }
}

aws_bool_issue["elb_alb_logs"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    access_logs := resource.properties.access_logs[j]
    not access_logs.enabled
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    access_logs := resource.properties.access_logs[j]
    not access_logs.enabled

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "access_logs", j, "enabled"]
        ],
    }
}

aws_issue["elb_alb_logs"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    count(resource.properties.access_logs) == 0
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    count(resource.properties.access_logs) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "access_logs"]
        ],
    }
}

elb_alb_logs {
    lower(input.resources[i].type) == "aws_lb"
    not aws_attribute_absence["elb_alb_logs"]
    not aws_issue["elb_alb_logs"]
    not aws_bool_issue["elb_alb_logs"]
}

elb_alb_logs = false {
    aws_issue["elb_alb_logs"]
}

elb_alb_logs = false {
    aws_bool_issue["elb_alb_logs"]
}

elb_alb_logs = false {
    aws_attribute_absence["elb_alb_logs"]
}

elb_alb_logs_err = "AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled" {
    aws_issue["elb_alb_logs"]
} else = "AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled" {
    aws_bool_issue["elb_alb_logs"]
} else = "ELBv2 attribute access_logs.enabled missing in the resource" {
    aws_attribute_absence["elb_alb_logs"]
}

elb_alb_logs_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled",
    "Policy Description": "This policy identifies ELBv2 ALBs which have access log disabled. Access logs capture detailed information about requests sent to your load balancer and each log contains information such as the time the request was received, the client's IP address, latencies, request paths, and server responses. You can use these access logs to analyze traffic patterns and troubleshoot issues.",
    "Resource Type": "aws_elb",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-TRF-ELB-010
#

default elb_listener_ssl = null

aws_attribute_absence["elb_listener_ssl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    not resource.properties.listener
}

source_path[{"elb_listener_ssl": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    not resource.properties.listener

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "listener"]
        ],
    }
}

aws_issue["elb_listener_ssl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    listener := resource.properties.listener[j]
    listener.ssl_certificate_id == ""
}

source_path[{"elb_listener_ssl": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    listener := resource.properties.listener[j]
    listener.ssl_certificate_id == ""

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "listener", j, "ssl_certificate_id"]
        ],
    }
}

aws_issue["elb_listener_ssl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    listener := resource.properties.listener[j]
    listener.ssl_certificate_id == null
}

source_path[{"elb_listener_ssl": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    listener := resource.properties.listener[j]
    listener.ssl_certificate_id == null

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "listener", j, "ssl_certificate_id"]
        ],
    }
}

aws_issue["elb_listener_ssl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    listener := resource.properties.listener[j]
    not listener.ssl_certificate_id
}

source_path[{"elb_listener_ssl": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    listener := resource.properties.listener[j]
    not listener.ssl_certificate_id

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "listener", j, "ssl_certificate_id"]
        ],
    }
}

elb_listener_ssl {
    lower(input.resources[i].type) == "aws_elb"
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
} else = "ELB attribute listeners missing in the resource" {
    aws_attribute_absence["elb_listener_ssl"]
}

elb_listener_ssl_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elastic Load Balancer with listener TLS/SSL disabled",
    "Policy Description": "This policy identifies Elastic Load Balancers which have listener TLS/SSL disabled. As Load Balancers will be handling all incoming requests and routing the traffic accordingly; The listeners on the load balancers should always receive traffic over secure channel with a valid SSL certificate configured.",
    "Resource Type": "aws_elb",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-TRF-ELB-011
#

default elb_over_https = null

aws_attribute_absence["elb_over_https"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    listener := resource.properties.listener[j]
    not listener.lb_protocol
}

source_path[{"elb_over_https": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    listener := resource.properties.listener[j]
    not listener.lb_protocol

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "listener", j, "lb_protocol"]
        ],
    }
}

aws_issue["elb_over_https"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    listener := resource.properties.listener[j]
    lower(listener.lb_protocol) == "http"
}

source_path[{"elb_over_https": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    listener := resource.properties.listener[j]
    lower(listener.lb_protocol) == "http"

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "listener", j, "lb_protocol"]
        ],
    }
}

elb_over_https {
    lower(input.resources[i].type) == "aws_elb"
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
} else = "ELBv2 attribute lb_protocol missing in the resource" {
    aws_attribute_absence["elb_over_https"]
}

elb_over_https_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-011",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Application Load Balancer (ALB) listener that allow connection requests over HTTP",
    "Policy Description": "This policy identifies Application Load Balancer (ALB) listeners that are configured to accept connection requests over HTTP instead of HTTPS. As a best practice, use the HTTPS protocol to encrypt the communication between the application clients and the application load balancer.",
    "Resource Type": "aws_elb",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-TRF-ELB-012
#

default elb_v2_listener_ssl = null


aws_issue["elb_v2_listener_ssl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener"
    not resource.properties.certificate_arn
}

source_path[{"elb_v2_listener_ssl": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener"
    not resource.properties.certificate_arn

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "certificate_arn"]
        ],
    }
}

aws_issue["elb_v2_listener_ssl"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener"
    count(resource.properties.certificate_arn) == 0
}

source_path[{"elb_v2_listener_ssl": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener"
    count(resource.properties.certificate_arn) == 0

    metadata := {
        "resource_path": [
            ["resources", i, "properties", "certificate_arn"]
        ],
    }
}

elb_v2_listener_ssl {
    lower(input.resources[i].type) == "aws_lb_listener"
    not aws_issue["elb_v2_listener_ssl"]
}

elb_v2_listener_ssl = false {
    aws_issue["elb_v2_listener_ssl"]
}


elb_v2_listener_ssl_err = "AWS Elastic Load Balancer V2 (ELBV2) with listener TLS/SSL disabled" {
    aws_issue["elb_v2_listener_ssl"]
}

elb_v2_listener_ssl_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-012",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "AWS Elastic Load Balancer V2 (ELBV2) with listener TLS/SSL disabled",
    "Policy Description": "This policy identifies Elastic Load Balancer V2 (ELBV2) which have listener TLS/SSL disabled. As Load Balancers will be handling all incoming requests and routing the traffic accordingly; The listeners on the load balancers should always receive traffic over secure channel with a valid SSL certificate configured.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-certificates"
}


#
# PR-AWS-TRF-ELB-013
#

default elb_drop_invalid_header = null

aws_attribute_absence["elb_drop_invalid_header"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    not resource.properties.policy_attribute
}

source_path[{"elb_drop_invalid_header": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    not resource.properties.policy_attribute
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy_attribute"]
        ],
    }
}

aws_issue["elb_drop_invalid_header"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    item := resource.properties.policy_attribute[j]
    lower(item.name) == "routing.http.drop_invalid_header_fields.enabled"
    lower(item.value) != "true"
}

source_path[{"elb_drop_invalid_header": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    item := resource.properties.policy_attribute[j]
    lower(item.name) == "routing.http.drop_invalid_header_fields.enabled"
    lower(item.value) != "true"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy_attribute", j, "value"]
        ],
    }
}

aws_bool_issue["elb_drop_invalid_header"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    item := resource.properties.policy_attribute[j]
    lower(item.name) == "routing.http.drop_invalid_header_fields.enabled"
    not item.value
}

source_path[{"elb_drop_invalid_header": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_load_balancer_policy"
    item := resource.properties.policy_attribute[j]
    lower(item.name) == "routing.http.drop_invalid_header_fields.enabled"
    not item.value
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "policy_attribute", j, "value"]
        ],
    }
}

elb_drop_invalid_header {
    lower(input.resources[i].type) == "aws_load_balancer_policy"
    not aws_issue["elb_drop_invalid_header"]
    not aws_bool_issue["elb_drop_invalid_header"]
    not aws_attribute_absence["elb_drop_invalid_header"]
}

elb_drop_invalid_header = false {
    aws_issue["elb_drop_invalid_header"]
}

elb_drop_invalid_header = false {
    aws_bool_issue["elb_drop_invalid_header"]
}

elb_drop_invalid_header = false {
    aws_attribute_absence["elb_drop_invalid_header"]
}

elb_drop_invalid_header_err = "Ensure that Application Load Balancer drops HTTP headers" {
    aws_issue["elb_drop_invalid_header"]
} else = "Ensure that Application Load Balancer drops HTTP headers" {
    aws_bool_issue["elb_drop_invalid_header"]
}

elb_drop_invalid_header_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-013",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that Application Load Balancer drops HTTP headers",
    "Policy Description": "Checks if rule evaluates AWS Application Load Balancers (ALB) to ensure they are configured to drop http headers. The rule is NON_COMPLIANT if the value of routing.http.drop_invalid_header_fields.enabled is set to false",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/load_balancer_listener_policy"
}


#
# PR-AWS-TRF-ELB-014
#

default elb_certificate_listner_arn = null

aws_attribute_absence["elb_certificate_listner_arn"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener_certificate"
    not resource.properties.listener_arn
}

source_path[{"elb_certificate_listner_arn": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener_certificate"
    not resource.properties.listener_arn
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "listener_arn"]
        ],
    }
}

aws_issue["elb_certificate_listner_arn"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener_certificate"
    resource.properties.listener_arn == null
}

source_path[{"elb_certificate_listner_arn": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener_certificate"
    resource.properties.listener_arn == null
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "listener_arn"]
        ],
    }
}

aws_issue["elb_certificate_listner_arn"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener_certificate"
    count(resource.properties.listener_arn) == 0
}

source_path[{"elb_certificate_listner_arn": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener_certificate"
    count(resource.properties.listener_arn) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "listener_arn"]
        ],
    }
}

aws_issue["elb_certificate_listner_arn"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener_certificate"
    resource.properties.listener_arn == ""
}

source_path[{"elb_certificate_listner_arn": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener_certificate"
    resource.properties.listener_arn == ""
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "listener_arn"]
        ],
    }
}


elb_certificate_listner_arn {
    lower(input.resources[i].type) == "aws_lb_listener_certificate"
    not aws_issue["elb_certificate_listner_arn"]
    not aws_attribute_absence["elb_certificate_listner_arn"]
}

elb_certificate_listner_arn = false {
    aws_issue["elb_certificate_listner_arn"]
}

elb_certificate_listner_arn = false {
    aws_attribute_absence["elb_certificate_listner_arn"]
}

elb_certificate_listner_arn_err = "Ensure the ELBv2 ListenerCertificate listener_arn value is defined" {
    aws_issue["elb_certificate_listner_arn"]
} else = "Ensure the ELBv2 ListenerCertificate listener_arn value is defined" {
    aws_attribute_absence["elb_certificate_listner_arn"]
}

elb_certificate_listner_arn_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-014",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure the ELBv2 ListenerCertificate listener_arn value is defined",
    "Policy Description": "Ensure the ELBv2 ListenerCertificate listener_arn value is defined, else an Actor can provide access to CA to non-ADATUM principals.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener_certificate"
}


#
# PR-AWS-TRF-ELB-015
#


default elb_listener_sslpolicy = null

allowed_ssl_policies = ["ELBSecurityPolicy-TLS-1-2-2017-01", "ELBSecurityPolicy-TLS-1-2-Ext-2018-06", "ELBSecurityPolicy-FS-1-2-2019-08", "ELBSecurityPolicy-FS-1-2-Res-2019-08", "ELBSecurityPolicy-FS-1-2-Res-2020-10"]

aws_attribute_absence["elb_listener_sslpolicy"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener"
    not resource.properties.ssl_policy
}

source_path[{"elb_listener_sslpolicy": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener"
    not resource.properties.ssl_policy
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ssl_policy"]
        ],
    }
}

aws_issue["elb_listener_sslpolicy"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener"
    count([c | lower(resource.properties.ssl_policy) == lower(allowed_ssl_policies[_]); c:=1 ]) == 0
}

source_path[{"elb_listener_sslpolicy": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener"
    count([c | lower(resource.properties.ssl_policy) == lower(allowed_ssl_policies[_]); c:=1 ]) == 0
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "ssl_policy"]
        ],
    }
}

elb_listener_sslpolicy {
    lower(input.resources[i].type) == "aws_lb_listener"
    not aws_issue["elb_listener_sslpolicy"]
    not aws_attribute_absence["elb_listener_sslpolicy"]
}

elb_listener_sslpolicy = false {
    aws_issue["elb_listener_sslpolicy"]
}

elb_listener_sslpolicy = false {
    aws_attribute_absence["elb_listener_sslpolicy"]
}

elb_listener_sslpolicy_err = "Ensure the Load Balancer Listener SSLPolicy is set to at least one value from approved policies" {
    aws_issue["elb_listener_sslpolicy"]
} else = "ELBv2 attribute ssl_policy is missing from the resource" {
    aws_attribute_absence["elb_listener_sslpolicy"]
}

elb_listener_sslpolicy_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-015",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure the Load Balancer Listener SSLPolicy is set to at least one value from approved policies",
    "Policy Description": "Ensure the Load Balancer Listener SSLPolicy is set to at least one value from approved policies, else an Actor can gain access to ADATUM information due to misconfigured cryptographic settings",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}


#
# PR-AWS-TRF-ELB-016
#

default elb_subnet = null

subnet_issue["elb_subnet"] {
	resource := input.resources[_]
    lower(resource.type) == "aws_lb"
	not resource.properties.subnets
}

subnet_issue["elb_subnet"] {
	resource := input.resources[_]
    lower(resource.type) == "aws_lb"
	resource.properties.subnets == null
}

subnet_issue["elb_subnet"] {
	resource := input.resources[_]
    lower(resource.type) == "aws_lb"
	count(resource.properties.subnets) == 0
}

subnet_mapping_issue["elb_subnet"] {
	resource := input.resources[_]
    lower(resource.type) == "aws_lb"
    not resource.properties.subnet_mapping
}

subnet_mapping_issue["elb_subnet"] {
	resource := input.resources[_]
    lower(resource.type) == "aws_lb"
    resource.properties.subnet_mapping == null
}

subnet_mapping_issue["elb_subnet"] {
	resource := input.resources[_]
    lower(resource.type) == "aws_lb"
    count(resource.properties.subnet_mapping) == 0
}

subnet_mapping_issue["elb_subnet"] {
	resource := input.resources[_]
    lower(resource.type) == "aws_lb"
    subnet_mapping := resource.properties.subnet_mapping[j]
    not subnet_mapping.subnet_id
}

subnet_mapping_issue["elb_subnet"] {
	resource := input.resources[_]
    lower(resource.type) == "aws_lb"
    subnet_mapping := resource.properties.subnet_mapping[j]
    count(subnet_mapping.subnet_id) == 0
}

subnet_mapping_issue["elb_subnet"] {
	resource := input.resources[_]
    lower(resource.type) == "aws_lb"
    subnet_mapping := resource.properties.subnet_mapping[j]
    subnet_mapping.subnet_id == null
}

aws_issue["elb_subnet"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    subnet_issue["elb_subnet"]
    subnet_mapping_issue["elb_subnet"]
}

source_path[{"elb_subnet": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    subnet_issue["elb_subnet"]
    subnet_mapping_issue["elb_subnet"]
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "subnets"],
            ["resources", i, "properties", "subnet_mapping"]
        ],
    }
}

elb_subnet {
    lower(input.resources[i].type) == "aws_lb"
    not aws_issue["elb_subnet"]
}

elb_subnet = false {
    aws_issue["elb_subnet"]
}

elb_subnet_err = "Ensure one of subnets or subnet_mapping is defined for loadbalancer" {
    aws_issue["elb_subnet"]
}

elb_subnet_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-016",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure one of subnets or subnet_mapping is defined for loadbalancer",
    "Policy Description": "Ensure one of subnets or subnet_mapping is defined for loadbalancer",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-subnetmapping.html#cfn-elasticloadbalancingv2-loadbalancer-subnetmapping-subnetid"
}

#
# PR-AWS-TRF-ELB-017
#

default elb_scheme = null

aws_issue["elb_scheme"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    lower(resource.properties.internal) == "true"
}

source_path[{"elb_scheme": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    lower(resource.properties.internal) == "true"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "internal"]
        ],
    }
}

aws_issue["elb_scheme"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    resource.properties.internal == true
}

source_path[{"elb_scheme": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    resource.properties.internal == true
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "internal"]
        ],
    }
}


elb_scheme {
    lower(input.resources[i].type) == "aws_lb"
    not aws_issue["elb_scheme"]
}

elb_scheme = false {
    aws_issue["elb_scheme"]
}

elb_scheme_err = "Ensure LoadBalancer scheme is set to internal and not internet-facing" {
    aws_issue["elb_scheme"]
}

elb_scheme_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-017",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure LoadBalancer scheme is set to internal and not internet-facing",
    "Policy Description": "LoadBalancer scheme must be explicitly set to internal, else an Actor can allow access to ADATUM information through the misconfiguration of an ELB resource",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb"
}


#
# PR-AWS-TRF-ELB-018
#

default elb_type = null

aws_issue["elb_type"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    lower(resource.properties.load_balancer_type) != "application"
}

source_path[{"elb_type": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    lower(resource.properties.load_balancer_type) != "application"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "load_balancer_type"]
        ],
    }
}

aws_issue["elb_type"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    resource.properties.load_balancer_type == null
}

source_path[{"elb_type": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    resource.properties.load_balancer_type == null
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "load_balancer_type"]
        ],
    }
}

elb_type {
    lower(input.resources[i].type) == "aws_lb"
    not aws_issue["elb_type"]
}

elb_type = false {
    aws_issue["elb_type"]
}

elb_type_err = "Ensure all load balancers created are application load balancers" {
    aws_issue["elb_type"]
}

elb_type_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-018",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure all load balancers created are application load balancers",
    "Policy Description": "Ensure the value of Type for each LoadBalancer resource is application or the Type is not set, since it defaults to application",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb"
}


#
# PR-AWS-TRF-ELB-019
#

default elb_protocol = null

aws_issue["elb_protocol"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_target_group"
    allwed_target_type := ["instance" , "ip"]
    lower(resource.properties.target_type) == allwed_target_type[_]
    lower(resource.properties.protocol) != "https"
}

source_path[{"elb_protocol": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_target_group"
    allwed_target_type := ["instance" , "ip"]
    lower(resource.properties.target_type) == allwed_target_type[_]
    lower(resource.properties.protocol) != "https"
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "protocol"]
        ],
    }
}

aws_issue["elb_protocol"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_target_group"
    allwed_target_type := ["instance" , "ip"]
    lower(resource.properties.target_type) == allwed_target_type[_]
    not resource.properties.protocol
}

source_path[{"elb_protocol": metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_target_group"
    allwed_target_type := ["instance" , "ip"]
    lower(resource.properties.target_type) == allwed_target_type[_]
    not resource.properties.protocol
    metadata := {
        "resource_path": [
            ["resources", i, "properties", "protocol"]
        ],
    }
}

elb_protocol {
    lower(input.resources[i].type) == "aws_lb_target_group"
    not aws_issue["elb_protocol"]
}

elb_protocol = false {
    aws_issue["elb_protocol"]
}

elb_protocol_err = "Ensure LoadBalancer TargetGroup protocol values are limited to HTTPS" {
    aws_issue["elb_protocol"]
}

elb_protocol_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-019",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure LoadBalancer TargetGroup protocol values are limited to HTTPS",
    "Policy Description": "The only allowed protocol value for LoadBalancer TargetGroups is HTTPS, though the property is ignored if the target type is lambda.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group"
}


#
# PR-AWS-TRF-ELB-020
#

default elb_deletion_protection = null

aws_issue["elb_deletion_protection"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    not resource.properties.enable_deletion_protection
}

elb_deletion_protection = false {
    aws_issue["elb_deletion_protection"]
}

elb_deletion_protection {
    lower(input.resources[i].type) == "aws_lb"
    not aws_issue["elb_deletion_protection"]
}

elb_deletion_protection_err = "Ensure that AWS Elastic Load Balancer v2 (ELBv2) has deletion protection feature enabled." {
    aws_issue["elb_deletion_protection"]
}

elb_deletion_protection_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-020",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that AWS Elastic Load Balancer v2 (ELBv2) has deletion protection feature enabled.",
    "Policy Description": "This policy checks if the ELB is protected against accidental deletion by enabling deletion protection.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb"
}


#
# PR-AWS-TRF-ELB-021
#

default elb_gateway_load_balancer = null

aws_issue["elb_gateway_load_balancer"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    resource.properties.load_balancer_type == "gateway"
}

elb_gateway_load_balancer = false {
    aws_issue["elb_gateway_load_balancer"]
}

elb_gateway_load_balancer {
    lower(input.resources[i].type) == "aws_lb"
    not aws_issue["elb_gateway_load_balancer"]
}

elb_gateway_load_balancer_err = "Ensure that AWS ensure Gateway Load Balancer (GWLB) is not being used." {
    aws_issue["elb_gateway_load_balancer"]
}

elb_gateway_load_balancer_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-021",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that AWS ensure Gateway Load Balancer (GWLB) is not being used.",
    "Policy Description": "This policy checks if Gateway LB is being used or not.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb"
}


#
# PR-AWS-TRF-ELB-022
#

default elb_internet_facing_load_balancer = null

aws_issue["elb_internet_facing_load_balancer"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_elb"
    not resource.properties.internal
}

elb_internet_facing_load_balancer = false {
    aws_issue["elb_internet_facing_load_balancer"]
}

elb_internet_facing_load_balancer {
    lower(input.resources[i].type) == "aws_elb"
    not aws_issue["elb_internet_facing_load_balancer"]
}

elb_internet_facing_load_balancer_err = "Ensure Internet facing Classic ELB is not in use." {
    aws_issue["elb_internet_facing_load_balancer"]
}

elb_internet_facing_load_balancer_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-022",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Internet facing Classic ELB is not in use.",
    "Policy Description": "This policy checks if classic LB is being used in the environment for internet facing applications.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elb"
}


#
# PR-AWS-TRF-ELB-023
#

default elb2_internet_facing_load_balancer = null

aws_issue["elb2_internet_facing_load_balancer"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    not resource.properties.internal
}

elb2_internet_facing_load_balancer = false {
    aws_issue["elb2_internet_facing_load_balancer"]
}

elb2_internet_facing_load_balancer {
    lower(input.resources[i].type) == "aws_lb"
    not aws_issue["elb2_internet_facing_load_balancer"]
}

elb2_internet_facing_load_balancer_err = "Ensure Internet facing ELBV2 is not in use." {
    aws_issue["elb2_internet_facing_load_balancer"]
}

elb2_internet_facing_load_balancer_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-023",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure Internet facing ELBV2 is not in use.",
    "Policy Description": "This policy checks if ELB v2 is being used in the environment.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb"
}


#
# PR-AWS-TRF-ELB-024
#

default elb_waf_enabled = null

aws_issue["elb_waf_enabled"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb"
    not resource.properties.enable_waf_fail_open
}

elb_waf_enabled = false {
    aws_issue["elb_waf_enabled"]
}

elb_waf_enabled_err = "Ensure that public facing ELB has WAF attached" {
    aws_issue["elb_waf_enabled"]
}

elb_waf_enabled_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-024",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "Terraform",
    "Policy Title": "Ensure that public facing ELB has WAF attached",
    "Policy Description": "This policy checks the usage of a WAF with Internet facing ELB. AWS WAF is a web application firewall service that lets you monitor web requests and protect your web applications from malicious requests.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb#enable_waf_fail_open"
}

#
# PR-AWS-TRF-ELB-025
#

default elbv2_ssl_negotiation_policy = null

aws_issue["elbv2_ssl_negotiation_policy"] {
    resource := input.resources[i]
    lower(resource.type) == "aws_lb_listener"
    contains(resource.properties.ssl_policy, "ELBSecurityPolicy-TLS-1-0-2015-04")
}

elbv2_ssl_negotiation_policy {
    lower(input.resources[i].type) == "aws_lb_listener"
    not aws_issue["elbv2_ssl_negotiation_policy"]
}

elbv2_ssl_negotiation_policy = false {
    aws_issue["elbv2_ssl_negotiation_policy"]
}

elbv2_ssl_negotiation_policy_err = "Ensure Elastic Load Balancer v2 (ELBv2) SSL negotiation policy is not configured with weak ciphers." {
    aws_issue["elbv2_ssl_negotiation_policy"]
}

elbv2_ssl_negotiation_policy_metadata := {
    "Policy Code": "PR-AWS-TRF-ELB-025",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure Elastic Load Balancer v2 (ELBv2) SSL negotiation policy is not configured with weak ciphers.",
    "Policy Description": "This policy identifies Elastic Load Balancers v2 (ELBv2) which are configured with SSL negotiation policy containing weak ciphers. An SSL cipher is an encryption algorithm that uses encryption keys to create a coded message. SSL protocols use several SSL ciphers to encrypt data over the Internet. As many of the other ciphers are not secure/weak, it is recommended to use only the ciphers recommended in the following AWS link: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener"
}
