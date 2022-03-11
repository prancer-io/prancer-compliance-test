package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html

#
# PR-AWS-CFR-ELB-001
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
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    policy := resource.Properties.Policies[j]
    attribute := policy.Attributes[k]
    lower(attribute.Name) == lower(insecure_ciphers[_])
    lower(attribute.Value) == "true"
}

source_path[{"elb_insecure_cipher": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    policy := resource.Properties.Policies[j]
    attribute := policy.Attributes[k]
    lower(attribute.Name) == lower(insecure_ciphers[_])
    lower(attribute.Value) == "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Policies", j, "Attributes", k, "Value"]
        ],
    }
}

elb_insecure_cipher {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancing::loadbalancer"
    not aws_issue["elb_insecure_cipher"]
}

elb_insecure_cipher = false {
    aws_issue["elb_insecure_cipher"]
}

elb_insecure_cipher_err = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers" {
    aws_issue["elb_insecure_cipher"]
}

elb_insecure_cipher_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-001",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers",
    "Policy Description": "This policy identifies Elastic Load Balancers (Classic) which are configured with SSL negotiation policy containing insecure ciphers. An SSL cipher is an encryption algorithm that uses encryption keys to create a coded message. SSL protocols use several SSL ciphers to encrypt data over the Internet. As many of the other ciphers are not secure, it is recommended to use only the ciphers recommended in the following AWS link: https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-ssl-security-policy.html.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CFR-ELB-002
#

default elb_insecure_protocol = null

insecure_ssl_protocols := [
    "Protocol-SSLv3",
    "Protocol-TLSv1",
    "Protocol-TLSv1.1"
]

aws_issue["elb_insecure_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    policy := resource.Properties.Policies[j]
    attribute := policy.Attributes[k]
    lower(attribute.Name) == lower(insecure_ssl_protocols[_])
    lower(attribute.Value) == "true"
}

source_path[{"elb_insecure_protocol": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    policy := resource.Properties.Policies[j]
    attribute := policy.Attributes[k]
    lower(attribute.Name) == lower(insecure_ssl_protocols[_])
    lower(attribute.Value) == "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Policies", j, "Attributes", k, "Value"]
        ],
    }
}

elb_insecure_protocol {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancing::loadbalancer"
    not aws_issue["elb_insecure_protocol"]
}

elb_insecure_protocol = false {
    aws_issue["elb_insecure_protocol"]
}

elb_insecure_protocol_err = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol" {
    aws_issue["elb_insecure_protocol"]
}

elb_insecure_protocol_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-002",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol",
    "Policy Description": "This policy identifies Elastic Load Balancers (Classic) which are configured with SSL negotiation policy containing vulnerable SSL protocol. The SSL protocol establishes a secure connection between a client and a server and ensures that all the data passed between the client and your load balancer is private. As a security best practice, it is recommended to use the latest version SSL protocol.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CFR-ELB-003
#

default elb_access_log = null

aws_issue["elb_access_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    lower(resource.Properties.AccessLoggingPolicy.Enabled) == "false"
}

source_path[{"elb_access_log": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    lower(resource.Properties.AccessLoggingPolicy.Enabled) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccessLoggingPolicy", "Enabled"]
        ],
    }
}

aws_bool_issue["elb_access_log"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.AccessLoggingPolicy.Enabled
}

source_path[{"elb_access_log": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.AccessLoggingPolicy.Enabled
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "AccessLoggingPolicy", "Enabled"]
        ],
    }
}

elb_access_log {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancing::loadbalancer"
    not aws_issue["elb_access_log"]
    not aws_bool_issue["elb_access_log"]
}

elb_access_log = false {
    aws_issue["elb_access_log"]
}

elb_access_log = false {
    aws_bool_issue["elb_access_log"]
}

elb_access_log_err = "AWS Elastic Load Balancer (Classic) with access log disabled" {
    aws_issue["elb_access_log"]
} else = "AWS Elastic Load Balancer (Classic) with access log disabled" {
    aws_bool_issue["elb_access_log"]
}

elb_access_log_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-003",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic Load Balancer (Classic) with access log disabled",
    "Policy Description": "This policy identifies Classic Elastic Load Balancers which have access log disabled. When Access log enabled, Classic load balancer captures detailed information about requests sent to your load balancer. Each log contains information such as the time the request was received, the client's IP address, latencies, request paths, and server responses. You can use these access logs to analyze traffic patterns and to troubleshoot issues.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CFR-ELB-004
#

default elb_conn_drain = null

aws_issue["elb_conn_drain"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    lower(resource.Properties.ConnectionDrainingPolicy.Enabled) == "false"
}

source_path[{"elb_conn_drain": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    lower(resource.Properties.ConnectionDrainingPolicy.Enabled) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ConnectionDrainingPolicy", "Enabled"]
        ],
    }
}

aws_bool_issue["elb_conn_drain"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.ConnectionDrainingPolicy.Enabled
}

source_path[{"elb_conn_drain": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.ConnectionDrainingPolicy.Enabled
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ConnectionDrainingPolicy", "Enabled"]
        ],
    }
}

elb_conn_drain {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancing::loadbalancer"
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
    "Policy Code": "PR-AWS-CFR-ELB-004",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic Load Balancer (Classic) with connection draining disabled",
    "Policy Description": "This policy identifies Classic Elastic Load Balancers which have connection draining disabled. Connection Draining feature ensures that a Classic load balancer stops sending requests to instances that are de-registering or unhealthy, while keeping the existing connections open. This enables the load balancer to complete in-flight requests made to instances that are de-registering or unhealthy.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CFR-ELB-005
#

default elb_crosszone = null

aws_issue["elb_crosszone"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    lower(resource.Properties.CrossZone) == "false"
}

source_path[{"elb_crosszone": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    lower(resource.Properties.CrossZone) == "false"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "CrossZone"]
        ],
    }
}

aws_bool_issue["elb_crosszone"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.CrossZone
}

source_path[{"elb_crosszone": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.CrossZone
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "CrossZone"]
        ],
    }
}

elb_crosszone {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancing::loadbalancer"
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
    "Policy Code": "PR-AWS-CFR-ELB-005",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic Load Balancer (Classic) with cross-zone load balancing disabled",
    "Policy Description": "This policy identifies Classic Elastic Load Balancers which have cross-zone load balancing disabled. When Cross-zone load balancing enabled, classic load balancer distributes requests evenly across the registered instances in all enabled Availability Zones. Cross-zone load balancing reduces the need to maintain equivalent numbers of instances in each enabled Availability Zone, and improves your application's ability to handle the loss of one or more instances.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CFR-ELB-006
#
default elb_sec_group_ingress = null

aws_attribute_absence["elb_sec_group_ingress"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.SecurityGroups
}

source_path[{"elb_sec_group_ingress": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.SecurityGroups
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityGroups"]
        ],
    }
}

aws_issue["elb_sec_group_ingress"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) == 0
}

source_path[{"elb_sec_group_ingress": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityGroups"]
        ],
    }
}

aws_ref_absence["elb_sec_group_ingress"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) != 0
    security_groups := resource.Properties.SecurityGroups[j].Ref
    count([c | input.Resources[k].Name == security_groups; c := 1]) == 0
    not input.Parameters[security_groups]
}

source_path[{"elb_sec_group_ingress": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) != 0
    security_groups := resource.Properties.SecurityGroups[j].Ref
    count([c | input.Resources[k].Name == security_groups; c := 1]) == 0
    not input.Parameters[security_groups]
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityGroups", j]
        ],
    }
}

aws_ref_issue["elb_sec_group_ingress"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) != 0
    security_groups := resource.Properties.SecurityGroups[j].Ref
    ref_resource := input.Resources[k]
    security_groups == ref_resource.Name
    count(ref_resource.Properties.SecurityGroupIngress) == 0
}

source_path[{"elb_sec_group_ingress": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) != 0
    security_groups := resource.Properties.SecurityGroups[j].Ref
    ref_resource := input.Resources[k]
    security_groups == ref_resource.Name
    count(ref_resource.Properties.SecurityGroupIngress) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityGroups", j],
            ["Resources", k, "Properties", "SecurityGroupIngress"]
        ],
    }
}

aws_ref_issue["elb_sec_group_ingress"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) != 0
    security_groups := resource.Properties.SecurityGroups[j].Ref
    ref_resource := input.Resources[k]
    security_groups == ref_resource.Name
    not ref_resource.Properties.SecurityGroupIngress
}

source_path[{"elb_sec_group_ingress": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) != 0
    security_groups := resource.Properties.SecurityGroups[j].Ref
    ref_resource := input.Resources[k]
    security_groups == ref_resource.Name
    not ref_resource.Properties.SecurityGroupIngress
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityGroups", j],
            ["Resources", k, "Properties", "SecurityGroupIngress"]
        ],
    }
}

elb_sec_group_ingress {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancing::loadbalancer"
    not aws_issue["elb_sec_group_ingress"]
    not aws_ref_issue["elb_sec_group_ingress"]
    not aws_ref_absence["elb_sec_group_ingress"]
    not aws_attribute_absence["elb_sec_group_ingress"]
}

elb_sec_group_ingress = false {
    aws_issue["elb_sec_group_ingress"]
}

elb_sec_group_ingress = false {
    aws_attribute_absence["elb_sec_group_ingress"]
}

elb_sec_group_ingress = false {
    aws_ref_issue["elb_sec_group_ingress"]
}

elb_sec_group_ingress = false {
    aws_ref_absence["elb_sec_group_ingress"]
}

elb_sec_group_ingress_err = "AWS Elastic Load Balancer (ELB) has security group with no inbound rules" {
    aws_issue["elb_sec_group_ingress"]
} else = "AWS Elastic Load Balancer (ELB) has security group Reference is missing" {
    aws_ref_absence["elb_sec_group_egress"]
} else = "ELB attribute SecurityGroups missing in the resource" {
    aws_attribute_absence["elb_sec_group_ingress"]
} else = "AWS Elastic Load Balancer (ELB) has security group with no inbound/outbound rules" {
    aws_ref_issue["elb_sec_group_ingress"]
}

elb_sec_group_ingress_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-006",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic Load Balancer (ELB) has security group with no inbound rules",
    "Policy Description": "This policy identifies Elastic Load Balancers (ELB) which have security group with no inbound rules. A security group with no inbound rule will deny all incoming requests. ELB security groups should have at least one inbound rule, ELB with no inbound permissions will deny all traffic incoming to ELB; in other words, the ELB is useless without inbound permissions.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CFR-ELB-007
#
default elb_sec_group_egress = null

aws_attribute_absence["elb_sec_group_egress"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.SecurityGroups
}

source_path[{"elb_sec_group_egress": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.SecurityGroups
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityGroups"]
        ],
    }
}

aws_issue["elb_sec_group_egress"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) == 0
}

source_path[{"elb_sec_group_egress": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityGroups"]
        ],
    }
}

aws_ref_absence["elb_sec_group_egress"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) != 0
    security_groups := resource.Properties.SecurityGroups[j].Ref
    count([c | input.Resources[k].Name == security_groups; c := 1]) == 0
    not input.Parameters[security_groups]
}

source_path[{"elb_sec_group_egress": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) != 0
    security_groups := resource.Properties.SecurityGroups[j].Ref
    count([c | input.Resources[k].Name == security_groups; c := 1]) == 0
    not input.Parameters[security_groups]
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityGroups", j]
        ],
    }
}

aws_ref_issue["elb_sec_group_egress"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) != 0
    security_groups := resource.Properties.SecurityGroups[j].Ref
    ref_resource := input.Resources[k]
    security_groups == ref_resource.Name
    count(ref_resource.Properties.SecurityGroupEgress) == 0
}

source_path[{"elb_sec_group_egress": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) != 0
    security_groups := resource.Properties.SecurityGroups[j].Ref
    ref_resource := input.Resources[k]
    security_groups == ref_resource.Name
    count(ref_resource.Properties.SecurityGroupEgress) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityGroups", j],
            ["Resources", k, "Properties", "SecurityGroupEgress", j],
        ],
    }
}

aws_ref_issue["elb_sec_group_egress"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) != 0
    security_groups := resource.Properties.SecurityGroups[j].Ref
    ref_resource := input.Resources[k]
    security_groups == ref_resource.Name
    not ref_resource.Properties.SecurityGroupEgress
}

source_path[{"elb_sec_group_egress": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.SecurityGroups) != 0
    security_groups := resource.Properties.SecurityGroups[j].Ref
    ref_resource := input.Resources[k]
    security_groups == ref_resource.Name
    not ref_resource.Properties.SecurityGroupEgress
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SecurityGroups", j],
            ["Resources", k, "Properties", "SecurityGroupEgress", j],
        ],
    }
}

elb_sec_group_egress {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancing::loadbalancer"
    not aws_issue["elb_sec_group_egress"]
    not aws_ref_issue["elb_sec_group_egress"]
    not aws_ref_absence["elb_sec_group_egress"]
    not aws_attribute_absence["elb_sec_group_egress"]
}

elb_sec_group_egress = false {
    aws_issue["elb_sec_group_egress"]
}

elb_sec_group_egress = false {
    aws_attribute_absence["elb_sec_group_egress"]
}

elb_sec_group_egress = false {
    aws_ref_absence["elb_sec_group_egress"]
}

elb_sec_group_egress = false {
    aws_ref_issue["elb_sec_group_egress"]
}

elb_sec_group_egress_err = "AWS Elastic Load Balancer (ELB) has no security group" {
    aws_issue["elb_sec_group_egress"]
} else = "AWS Elastic Load Balancer (ELB) has security group with no outbound rules" {
    aws_ref_issue["elb_sec_group_egress"]
} else = "ELB attribute SecurityGroups missing in the resource" {
    aws_attribute_absence["elb_sec_group_egress"]
} else = "AWS Elastic Load Balancer (ELB) has no security group" {
    aws_ref_absence["elb_sec_group_egress"]
}


elb_sec_group_egress_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-007",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic Load Balancer (ELB) has security group with no outbound rules",
    "Policy Description": "This policy identifies Elastic Load Balancers (ELB) which have security group with no outbound rules. A security group with no outbound rule will deny all outgoing requests. ELB security groups should have at least one outbound rule, ELB with no outbound permissions will deny all traffic going to any EC2 instances or resources configured behind that ELB; in other words, the ELB is useless without outbound permissions.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CFR-ELB-008
#

default elb_not_in_use = null

aws_attribute_absence["elb_not_in_use"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.Instances
}

source_path[{"elb_not_in_use": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.Instances
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Instances"]
        ],
    }
}

aws_issue["elb_not_in_use"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.Instances) == 0
}

source_path[{"elb_not_in_use": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    count(resource.Properties.Instances) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Instances"]
        ],
    }
}

elb_not_in_use {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancing::loadbalancer"
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

elb_not_in_use_miss_err = "ELB attribute Instances missing in the resource" {
    aws_attribute_absence["elb_not_in_use"]
}

elb_not_in_use_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-008",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic Load Balancer (ELB) not in use",
    "Policy Description": "This policy identifies unused Elastic Load Balancers (ELBs) in your AWS account. Any Elastic Load Balancer in your AWS account is adding charges to your monthly bill, although it is not used by any resources. As a best practice, it is recommended to remove ELBs that are not associated with any instances, it will also help you avoid unexpected charges on your bill.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CFR-ELB-009
#

default elb_alb_logs = null

aws_attribute_absence["elb_alb_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not resource.Properties.LoadBalancerAttributes
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not resource.Properties.LoadBalancerAttributes
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoadBalancerAttributes"]
        ],
    }
}

aws_attribute_absence["elb_alb_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    count([c | resource.Properties.LoadBalancerAttributes[_].Key == "access_logs.s3.enabled"; c:=1]) == 0
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    count([c | resource.Properties.LoadBalancerAttributes[_].Key == "access_logs.s3.enabled"; c:=1]) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoadBalancerAttributes"]
        ],
    }
}

aws_issue["elb_alb_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    lower(item.Key) == "access_logs.s3.enabled"
    lower(item.Value) != "true"
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    lower(item.Key) == "access_logs.s3.enabled"
    lower(item.Value) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoadBalancerAttributes", j, "Value"]
        ],
    }
}

aws_issue["elb_alb_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    item2 := resource.Properties.LoadBalancerAttributes[k]
    lower(item.Key) == "access_logs.s3.enabled"
    lower(item.Value) == "true"
    lower(item2.Key) == "access_logs.s3.bucket"
    not item2.Value
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    item2 := resource.Properties.LoadBalancerAttributes[k]
    lower(item.Key) == "access_logs.s3.enabled"
    lower(item.Value) == "true"
    lower(item2.Key) == "access_logs.s3.bucket"
    not item2.Value
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoadBalancerAttributes", k, "Value"]
        ],
    }
}

aws_issue["elb_alb_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    item2 := resource.Properties.LoadBalancerAttributes[k]
    lower(item.Key) == "access_logs.s3.enabled"
    lower(item.Value) == "true"
    lower(item2.Key) == "access_logs.s3.bucket"
    item2.Value == null
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    item2 := resource.Properties.LoadBalancerAttributes[k]
    lower(item.Key) == "access_logs.s3.enabled"
    lower(item.Value) == "true"
    lower(item2.Key) == "access_logs.s3.bucket"
    item2.Value == null
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoadBalancerAttributes", k, "Value"]
        ],
    }
}


aws_issue["elb_alb_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    item2 := resource.Properties.LoadBalancerAttributes[k]
    lower(item.Key) == "access_logs.s3.enabled"
    lower(item.Value) == "true"
    lower(item2.Key) == "access_logs.s3.bucket"
    item2.Value == ""
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    item2 := resource.Properties.LoadBalancerAttributes[k]
    lower(item.Key) == "access_logs.s3.enabled"
    lower(item.Value) == "true"
    lower(item2.Key) == "access_logs.s3.bucket"
    item2.Value == ""
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoadBalancerAttributes", k, "Value"]
        ],
    }
}

aws_bool_issue["elb_alb_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    lower(item.Key) == "access_logs.s3.enabled"
    not item.Value
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    lower(item.Key) == "access_logs.s3.enabled"
    not item.Value
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoadBalancerAttributes", j, "Value"]
        ],
    }
}

aws_bool_issue["elb_alb_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    item2 := resource.Properties.LoadBalancerAttributes[k]
    lower(item.Key) == "access_logs.s3.enabled"
    item.Value == true
    lower(item2.Key) == "access_logs.s3.bucket"
    not item2.Value
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    item2 := resource.Properties.LoadBalancerAttributes[k]
    lower(item.Key) == "access_logs.s3.enabled"
    item.Value == true
    lower(item2.Key) == "access_logs.s3.bucket"
    not item2.Value
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoadBalancerAttributes", k, "Value"]
        ],
    }
}

aws_bool_issue["elb_alb_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    item2 := resource.Properties.LoadBalancerAttributes[k]
    lower(item.Key) == "access_logs.s3.enabled"
    item.Value == true
    lower(item2.Key) == "access_logs.s3.bucket"
    item2.Value == ""
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    item2 := resource.Properties.LoadBalancerAttributes[k]
    lower(item.Key) == "access_logs.s3.enabled"
    item.Value == true
    lower(item2.Key) == "access_logs.s3.bucket"
    item2.Value == ""
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoadBalancerAttributes", k, "Value"]
        ],
    }
}

aws_bool_issue["elb_alb_logs"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    item2 := resource.Properties.LoadBalancerAttributes[k]
    lower(item.Key) == "access_logs.s3.enabled"
    item.Value == true
    lower(item2.Key) == "access_logs.s3.bucket"
    item2.Value == null
}

source_path[{"elb_alb_logs": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    item2 := resource.Properties.LoadBalancerAttributes[k]
    lower(item.Key) == "access_logs.s3.enabled"
    item.Value == true
    lower(item2.Key) == "access_logs.s3.bucket"
    item2.Value == null
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoadBalancerAttributes", k, "Value"]
        ],
    }
}

elb_alb_logs {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not aws_issue["elb_alb_logs"]
    not aws_bool_issue["elb_alb_logs"]
    not aws_attribute_absence["elb_alb_logs"]
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
}

elb_alb_logs_miss_err = "ELBv2 attribute LoadBalancerAttributes missing in the resource" {
    aws_attribute_absence["elb_alb_logs"]
}

elb_alb_logs_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-009",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled",
    "Policy Description": "This policy identifies ELBv2 ALBs which have access log disabled. Access logs capture detailed information about requests sent to your load balancer and each log contains information such as the time the request was received, the client's IP address, latencies, request paths, and server responses. You can use these access logs to analyze traffic patterns and troubleshoot issues.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CFR-ELB-010
#

default elb_listener_ssl = null

aws_attribute_absence["elb_listener_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.Listeners
}

source_path[{"elb_listener_ssl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    not resource.Properties.Listeners
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Listeners"]
        ],
    }
}

aws_issue["elb_listener_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    resource.Properties.Listeners[j].SSLCertificateId == ""
}

source_path[{"elb_listener_ssl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    resource.Properties.Listeners[j].SSLCertificateId == ""
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Listeners", j, "SSLCertificateId"]
        ],
    }
}

aws_issue["elb_listener_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    resource.Properties.Listeners[j].SSLCertificateId == null
}

source_path[{"elb_listener_ssl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    resource.Properties.Listeners[j].SSLCertificateId == null
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Listeners", j, "SSLCertificateId"]
        ],
    }
}

aws_issue["elb_listener_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    listener := resource.Properties.Listeners[j]
    not listener.SSLCertificateId
}

source_path[{"elb_listener_ssl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    listener := resource.Properties.Listeners[j]
    not listener.SSLCertificateId
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Listeners", j, "SSLCertificateId"]
        ],
    }
}

elb_listener_ssl {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancing::loadbalancer"
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

elb_listener_ssl_miss_err = "ELB attribute Listeners missing in the resource" {
    aws_attribute_absence["elb_listener_ssl"]
}

elb_listener_ssl_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-010",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic Load Balancer with listener TLS/SSL disabled",
    "Policy Description": "This policy identifies Elastic Load Balancers which have listener TLS/SSL disabled. As Load Balancers will be handling all incoming requests and routing the traffic accordingly; The listeners on the load balancers should always receive traffic over secure channel with a valid SSL certificate configured.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CFR-ELB-011
#

default elb_over_https = null

aws_attribute_absence["elb_over_https"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    not resource.Properties.Protocol
}

source_path[{"elb_over_https": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    not resource.Properties.Protocol
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Protocol"]
        ],
    }
}

aws_issue["elb_over_https"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    lower(resource.Properties.Protocol) == "http"
}

source_path[{"elb_over_https": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    lower(resource.Properties.Protocol) == "http"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Protocol"]
        ],
    }
}

elb_over_https {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancingv2::listener"
    not aws_issue["elb_over_https"]
    not aws_attribute_absence["elb_over_https"]
}

elb_over_https = false {
    aws_issue["elb_over_https"]
}

elb_over_https = false {
    aws_attribute_absence["elb_over_https"]
}

elb_over_https_err = "AWS Application Load Balancer (ALB) listener that allow connection requests over HTTP" {
    aws_issue["elb_over_https"]
}

elb_over_https_miss_err = "ELBv2 attribute Protocol missing in the resource" {
    aws_attribute_absence["elb_over_https"]
}

elb_over_https_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-011",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Application Load Balancer (ALB) listener that allow connection requests over HTTP",
    "Policy Description": "This policy identifies Application Load Balancer (ALB) listeners that are configured to accept connection requests over HTTP instead of HTTPS. As a best practice, use the HTTPS protocol to encrypt the communication between the application clients and the application load balancer.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}


#
# PR-AWS-CFR-ELB-012
#

default elb_v2_listener_ssl = null

aws_attribute_absence["elb_v2_listener_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    not resource.Properties.Certificates
}

source_path[{"elb_v2_listener_ssl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    not resource.Properties.Certificates
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Certificates"]
        ],
    }
}

aws_issue["elb_v2_listener_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    count(resource.Properties.Certificates) == 0
}

source_path[{"elb_v2_listener_ssl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    count(resource.Properties.Certificates) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Certificates"]
        ],
    }
}

aws_issue["elb_v2_listener_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    certificate := resource.Properties.Certificates[j]
    not certificate.CertificateArn
}

source_path[{"elb_v2_listener_ssl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    certificate := resource.Properties.Certificates[j]
    not certificate.CertificateArn
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Certificates", j, "CertificateArn"]
        ],
    }
}

aws_issue["elb_v2_listener_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    certificate := resource.Properties.Certificates[j]
    lower(certificate.CertificateArn) == ""
}

source_path[{"elb_v2_listener_ssl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    certificate := resource.Properties.Certificates[j]
    lower(certificate.CertificateArn) == ""
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Certificates", j, "CertificateArn"]
        ],
    }
}

aws_issue["elb_v2_listener_ssl"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    certificate := resource.Properties.Certificates[j]
    count(certificate.CertificateArn) == 0
}

source_path[{"elb_v2_listener_ssl": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    certificate := resource.Properties.Certificates[j]
    count(certificate.CertificateArn) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Certificates", j, "CertificateArn"]
        ],
    }
}

elb_v2_listener_ssl {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancingv2::listener"
    not aws_issue["elb_v2_listener_ssl"]
    not aws_attribute_absence["elb_v2_listener_ssl"]
}

elb_v2_listener_ssl = false {
    aws_issue["elb_v2_listener_ssl"]
}

elb_v2_listener_ssl = false {
    aws_attribute_absence["elb_v2_listener_ssl"]
}

elb_v2_listener_ssl_err = "AWS Elastic Load Balancer V2 (ELBV2) with listener TLS/SSL disabled" {
    aws_issue["elb_v2_listener_ssl"]
} else = "AWS Elastic Load Balancer V2 (ELBV2) with TLS/SSL certificate absent" {
    aws_attribute_absence["elb_v2_listener_ssl"]
}

elb_v2_listener_ssl_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-012",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "AWS Elastic Load Balancer V2 (ELBV2) with listener TLS/SSL disabled",
    "Policy Description": "This policy identifies Elastic Load Balancer V2 (ELBV2) which have listener TLS/SSL disabled. As Load Balancers will be handling all incoming requests and routing the traffic accordingly; The listeners on the load balancers should always receive traffic over secure channel with a valid SSL certificate configured.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-certificates"
}


#
# PR-AWS-CFR-ELB-013
#

default elb_drop_invalid_header = null

aws_attribute_absence["elb_drop_invalid_header"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not resource.Properties.LoadBalancerAttributes
}

source_path[{"elb_drop_invalid_header": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not resource.Properties.LoadBalancerAttributes
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoadBalancerAttributes"]
        ],
    }
}

aws_issue["elb_drop_invalid_header"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    lower(item.Key) == "routing.http.drop_invalid_header_fields.enabled"
    lower(item.Value) != "true"
}

source_path[{"elb_drop_invalid_header": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    lower(item.Key) == "routing.http.drop_invalid_header_fields.enabled"
    lower(item.Value) != "true"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoadBalancerAttributes", j, "Value"]
        ],
    }
}

aws_bool_issue["elb_drop_invalid_header"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    lower(item.Key) == "routing.http.drop_invalid_header_fields.enabled"
    not item.Value
}

source_path[{"elb_drop_invalid_header": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    item := resource.Properties.LoadBalancerAttributes[j]
    lower(item.Key) == "routing.http.drop_invalid_header_fields.enabled"
    not item.Value
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "LoadBalancerAttributes", j, "Value"]
        ],
    }
}

elb_drop_invalid_header {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancingv2::loadbalancer"
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
    "Policy Code": "PR-AWS-CFR-ELB-013",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that Application Load Balancer drops HTTP headers",
    "Policy Description": "Checks if rule evaluates AWS Application Load Balancers (ALB) to ensure they are configured to drop http headers. The rule is NON_COMPLIANT if the value of routing.http.drop_invalid_header_fields.enabled is set to false",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-loadbalancerattributes.html"
}


#
# PR-AWS-CFR-ELB-014
#

default elb_certificate_listner_arn = null

aws_attribute_absence["elb_certificate_listner_arn"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listenercertificate"
    not resource.Properties.ListenerArn
}

source_path[{"elb_certificate_listner_arn": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listenercertificate"
    not resource.Properties.ListenerArn
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ListenerArn"]
        ],
    }
}

aws_issue["elb_certificate_listner_arn"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listenercertificate"
    resource.Properties.ListenerArn == null
}

source_path[{"elb_certificate_listner_arn": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listenercertificate"
    resource.Properties.ListenerArn == null
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ListenerArn"]
        ],
    }
}

aws_issue["elb_certificate_listner_arn"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listenercertificate"
    count(resource.Properties.ListenerArn) == 0
}

source_path[{"elb_certificate_listner_arn": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listenercertificate"
    count(resource.Properties.ListenerArn) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ListenerArn"]
        ],
    }
}

aws_issue["elb_certificate_listner_arn"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listenercertificate"
    resource.Properties.ListenerArn == ""
}

source_path[{"elb_certificate_listner_arn": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listenercertificate"
    resource.Properties.ListenerArn == ""
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "ListenerArn"]
        ],
    }
}


elb_certificate_listner_arn {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancingv2::listenercertificate"
    not aws_issue["elb_certificate_listner_arn"]
    not aws_attribute_absence["elb_certificate_listner_arn"]
}

elb_certificate_listner_arn = false {
    aws_issue["elb_certificate_listner_arn"]
}

elb_certificate_listner_arn = false {
    aws_attribute_absence["elb_certificate_listner_arn"]
}

elb_certificate_listner_arn_err = "Ensure the ELBv2 ListenerCertificate ListenerArn value is defined" {
    aws_issue["elb_certificate_listner_arn"]
} else = "Ensure the ELBv2 ListenerCertificate ListenerArn value is defined" {
    aws_attribute_absence["elb_certificate_listner_arn"]
}

elb_certificate_listner_arn_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-014",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure the ELBv2 ListenerCertificate ListenerArn value is defined",
    "Policy Description": "Ensure the ELBv2 ListenerCertificate ListenerArn value is defined, else an Actor can provide access to CA to non-ADATUM principals.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html"
}


#
# PR-AWS-CFR-ELB-015
#


default elb_listener_sslpolicy = null

allowed_ssl_policies = ["ELBSecurityPolicy-TLS-1-2-2017-01", "ELBSecurityPolicy-TLS-1-2-Ext-2018-06", "ELBSecurityPolicy-FS-1-2-2019-08", "ELBSecurityPolicy-FS-1-2-Res-2019-08", "ELBSecurityPolicy-FS-1-2-Res-2020-10"]

aws_attribute_absence["elb_listener_sslpolicy"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    not resource.Properties.SslPolicy
}

source_path[{"elb_listener_sslpolicy": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    not resource.Properties.SslPolicy
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SslPolicy"]
        ],
    }
}

aws_issue["elb_listener_sslpolicy"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    count([c | lower(resource.Properties.SslPolicy) == lower(allowed_ssl_policies[_]); c:=1 ]) == 0
}

source_path[{"elb_listener_sslpolicy": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    count([c | lower(resource.Properties.SslPolicy) == lower(allowed_ssl_policies[_]); c:=1 ]) == 0
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "SslPolicy"]
        ],
    }
}

elb_listener_sslpolicy {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancingv2::listener"
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
} else = "ELBv2 attribute SslPolicy is missing from the resource" {
    aws_attribute_absence["elb_listener_sslpolicy"]
}

elb_listener_sslpolicy_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-015",
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
# PR-AWS-CFR-ELB-016
#

default elb_subnet = null

subnet_issue["elb_subnet"] {
	resource := input.Resources[_]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
	not resource.Properties.Subnets
}

subnet_issue["elb_subnet"] {
	resource := input.Resources[_]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
	resource.Properties.Subnets == null
}

subnet_issue["elb_subnet"] {
	resource := input.Resources[_]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
	count(resource.Properties.Subnets) == 0
}

subnet_mapping_issue["elb_subnet"] {
	resource := input.Resources[_]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not resource.Properties.SubnetMappings
}

subnet_mapping_issue["elb_subnet"] {
	resource := input.Resources[_]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    resource.Properties.SubnetMappings == null
}

subnet_mapping_issue["elb_subnet"] {
	resource := input.Resources[_]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    count(resource.Properties.SubnetMappings) == 0
}

subnet_mapping_issue["elb_subnet"] {
	resource := input.Resources[_]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    SubnetMappings := resource.Properties.SubnetMappings[j]
    not SubnetMappings.SubnetId
}

subnet_mapping_issue["elb_subnet"] {
	resource := input.Resources[_]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    SubnetMappings := resource.Properties.SubnetMappings[j]
    count(SubnetMappings.SubnetId) == 0
}

subnet_mapping_issue["elb_subnet"] {
	resource := input.Resources[_]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    SubnetMappings := resource.Properties.SubnetMappings[j]
    SubnetMappings.SubnetId == null
}

aws_issue["elb_subnet"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    subnet_issue["elb_subnet"]
    subnet_mapping_issue["elb_subnet"]
}

source_path[{"elb_subnet": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    subnet_issue["elb_subnet"]
    subnet_mapping_issue["elb_subnet"]
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Subnets"],
            ["Resources", i, "Properties", "SubnetMappings"]
        ],
    }
}

elb_subnet {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not aws_issue["elb_subnet"]
}

elb_subnet = false {
    aws_issue["elb_subnet"]
}

elb_subnet_err = "Ensure one of Subnets or SubnetMappings is defined for loadbalancer" {
    aws_issue["elb_subnet"]
}

elb_subnet_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-016",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure one of Subnets or SubnetMappings is defined for loadbalancer",
    "Policy Description": "Ensure one of Subnets or SubnetMappings is defined for loadbalancer",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-subnetmapping.html#cfn-elasticloadbalancingv2-loadbalancer-subnetmapping-subnetid"
}

#
# PR-AWS-CFR-ELB-017
#

default elb_scheme = null

aws_attribute_absence["elb_scheme"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not resource.Properties.Scheme
}

source_path[{"elb_scheme": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not resource.Properties.Scheme
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Scheme"]
        ],
    }
}

aws_issue["elb_scheme"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    lower(resource.Properties.Scheme) != "internal"
}

source_path[{"elb_scheme": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    lower(resource.Properties.Scheme) != "internal"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Scheme"]
        ],
    }
}

aws_issue["elb_scheme"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    resource.Properties.Scheme == null
}

source_path[{"elb_scheme": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    resource.Properties.Scheme == null
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Scheme"]
        ],
    }
}

elb_scheme {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not aws_issue["elb_scheme"]
    not aws_attribute_absence["elb_scheme"]
}

elb_scheme = false {
    aws_issue["elb_scheme"]
}

elb_scheme = false {
    aws_attribute_absence["elb_scheme"]
}

elb_scheme_err = "Ensure LoadBalancer scheme is set to internal and not internet-facing" {
    aws_issue["elb_scheme"]
} else = "Ensure LoadBalancer scheme is set to internal" {
    aws_attribute_absence["elb_scheme"]
}

elb_scheme_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-017",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure LoadBalancer scheme is set to internal and not internet-facing",
    "Policy Description": "LoadBalancer scheme must be explicitly set to internal, else an Actor can allow access to ADATUM information through the misconfiguration of an ELB resource",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html"
}


#
# PR-AWS-CFR-ELB-018
#

default elb_type = null

aws_issue["elb_type"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    lower(resource.Properties.Type) != "application"
}

source_path[{"elb_type": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    lower(resource.Properties.Type) != "application"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Type"]
        ],
    }
}

aws_issue["elb_type"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    resource.Properties.Type == null
}

source_path[{"elb_type": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    resource.Properties.Type == null
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Type"]
        ],
    }
}

elb_type {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not aws_issue["elb_type"]
}

elb_type = false {
    aws_issue["elb_type"]
}

elb_type_err = "Ensure all load balancers created are application load balancers" {
    aws_issue["elb_type"]
}

elb_type_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-018",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure all load balancers created are application load balancers",
    "Policy Description": "Ensure the value of Type for each LoadBalancer resource is application or the Type is not set, since it defaults to application",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-type"
}


#
# PR-AWS-CFR-ELB-019
#

default elb_protocol = null

aws_issue["elb_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::targetgroup"
    TargetTypeAllowed := ["instance" , "ip"]
    lower(resource.Properties.TargetType) == TargetTypeAllowed[_]
    lower(resource.Properties.Protocol) != "https"
}

source_path[{"elb_protocol": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::targetgroup"
    TargetTypeAllowed := ["instance" , "ip"]
    lower(resource.Properties.TargetType) == TargetTypeAllowed[_]
    lower(resource.Properties.Protocol) != "https"
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Protocol"]
        ],
    }
}

aws_issue["elb_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::targetgroup"
    TargetTypeAllowed := ["instance" , "ip"]
    lower(resource.Properties.TargetType) == TargetTypeAllowed[_]
    not resource.Properties.Protocol
}

source_path[{"elb_protocol": metadata}] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::targetgroup"
    TargetTypeAllowed := ["instance" , "ip"]
    lower(resource.Properties.TargetType) == TargetTypeAllowed[_]
    not resource.Properties.Protocol
    metadata := {
        "resource_path": [
            ["Resources", i, "Properties", "Protocol"]
        ],
    }
}

elb_protocol {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancingv2::targetgroup"
    not aws_issue["elb_protocol"]
}

elb_protocol = false {
    aws_issue["elb_protocol"]
}

elb_protocol_err = "Ensure LoadBalancer TargetGroup Protocol values are limited to HTTPS" {
    aws_issue["elb_protocol"]
}

elb_protocol_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-019",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure LoadBalancer TargetGroup Protocol values are limited to HTTPS",
    "Policy Description": "The only allowed Protocol value for LoadBalancer TargetGroups is HTTPS, though the property is ignored if the target type is lambda.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-protocol"
}


#
# PR-AWS-CFR-ELB-020
#

default elb_default_action = null

allowed_action_types = ["fixed-response", "forward", "redirect"]

aws_issue["elb_default_action"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    not resource.Properties.DefaultActions
}

aws_issue["elb_default_action"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    DefaultActions := resource.Properties.DefaultActions[_]
    count([c | lower(DefaultActions.Type) == allowed_action_types[_]; c:=1 ]) == 0
}

elb_default_action {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancingv2::listener"
    not aws_issue["elb_default_action"]
}

elb_default_action = false {
    aws_issue["elb_default_action"]
}

elb_default_action_err = "Ensure that ELB Listener is limited to approved actions." {
    aws_issue["elb_default_action"]
}

elb_default_action_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-020",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that ELB Listener is limited to approved actions.",
    "Policy Description": "Ensure the AWS::ElasticLoadBalancingV2::Listener Action Type is limited to: 'fixed-response', 'forward', 'redirect'",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}


#
# PR-AWS-CFR-ELB-021
#

default elb_listner_redirect_protocol = null

allowed_action_types = ["fixed-response", "forward", "redirect"]

aws_issue["elb_listner_redirect_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    not resource.Properties.DefaultActions
}

aws_issue["elb_listner_redirect_protocol"] {
    resource := input.Resources[i]
    lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    DefaultActions := resource.Properties.DefaultActions[_]
    lower(DefaultActions.Type) == "redirect"
    lower(DefaultActions.RedirectConfig.Protocol) != "https"

}

elb_listner_redirect_protocol {
    lower(input.Resources[i].Type) == "aws::elasticloadbalancingv2::listener"
    not aws_issue["elb_listner_redirect_protocol"]
}

elb_listner_redirect_protocol = false {
    aws_issue["elb_listner_redirect_protocol"]
}

elb_listner_redirect_protocol_err = "Ensure that Listeners redirect using only the HTTPS protocol." {
    aws_issue["elb_listner_redirect_protocol"]
}

elb_listner_redirect_protocol_metadata := {
    "Policy Code": "PR-AWS-CFR-ELB-021",
    "Type": "IaC",
    "Product": "AWS",
    "Language": "AWS Cloud formation",
    "Policy Title": "Ensure that Listeners redirect using only the HTTPS protocol.",
    "Policy Description": "Listeners that use default actions including RedirectConfigs must set the protocol to HTTPS on those RedirectConfigs.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}