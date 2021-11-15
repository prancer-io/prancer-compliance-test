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
    "Protocol-SSLv3",
    "Protocol-TLSv1",
    "Protocol-TLSv1.1"
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
