package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html

#
# PR-AWS-CLD-ELB-001
#

default elb_insecure_cipher = true

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

elb_insecure_cipher = false {
    # lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    PolicyDescriptions := input.PolicyDescriptions[_]
    PolicyAttributeDescriptions := PolicyDescriptions.PolicyAttributeDescriptions[k]
    lower(PolicyAttributeDescriptions.AttributeName) == lower(insecure_ciphers[_])
    PolicyAttributeDescriptions.AttributeValue == true
}

elb_insecure_cipher = false {
    # lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    PolicyDescriptions := input.PolicyDescriptions[_]
    PolicyAttributeDescriptions := PolicyDescriptions.PolicyAttributeDescriptions[k]
    lower(PolicyAttributeDescriptions.AttributeName) == lower(insecure_ciphers[_])
    lower(PolicyAttributeDescriptions.AttributeValue) == "true"
}

elb_insecure_cipher_err = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers" {
    not elb_insecure_cipher
}

elb_insecure_cipher_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-001",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers",
    "Policy Description": "This policy identifies Elastic Load Balancers (Classic) which are configured with SSL negotiation policy containing insecure ciphers. An SSL cipher is an encryption algorithm that uses encryption keys to create a coded message. SSL protocols use several SSL ciphers to encrypt data over the Internet. As many of the other ciphers are not secure, it is recommended to use only the ciphers recommended in the following AWS link: https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-ssl-security-policy.html.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CLD-ELB-002
#

default elb_insecure_protocol = true

insecure_ssl_protocols := [
    "Protocol-SSLv3",
    "Protocol-TLSv1",
    "Protocol-TLSv1.1"
]

elb_insecure_protocol = false {
    # lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    PolicyDescriptions := input.PolicyDescriptions[_]
    PolicyAttributeDescriptions := PolicyDescriptions.PolicyAttributeDescriptions[k]
    lower(PolicyAttributeDescriptions.AttributeName) == lower(insecure_ssl_protocols[_])
    PolicyAttributeDescriptions.AttributeValue == true
}

elb_insecure_protocol = false {
    # lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    PolicyDescriptions := input.PolicyDescriptions[_]
    PolicyAttributeDescriptions := PolicyDescriptions.PolicyAttributeDescriptions[k]
    lower(PolicyAttributeDescriptions.AttributeName) == lower(insecure_ssl_protocols[_])
    lower(PolicyAttributeDescriptions.AttributeValue) == "true"
}

elb_insecure_protocol_err = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol" {
    not elb_insecure_protocol
}

elb_insecure_protocol_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-002",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol",
    "Policy Description": "This policy identifies Elastic Load Balancers (Classic) which are configured with SSL negotiation policy containing vulnerable SSL protocol. The SSL protocol establishes a secure connection between a client and a server and ensures that all the data passed between the client and your load balancer is private. As a security best practice, it is recommended to use the latest version SSL protocol.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CLD-ELB-003
#

default elb_access_log = true

elb_access_log = false {
    # lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    LoadBalancerAttributes := input.LoadBalancerAttributes[_]
    not LoadBalancerAttributes.AccessLog.Enabled
}

elb_access_log_err = "AWS Elastic Load Balancer (Classic) with access log disabled" {
    not elb_access_log
}

elb_access_log_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-003",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elastic Load Balancer (Classic) with access log disabled",
    "Policy Description": "This policy identifies Classic Elastic Load Balancers which have access log disabled. When Access log enabled, Classic load balancer captures detailed information about requests sent to your load balancer. Each log contains information such as the time the request was received, the client's IP address, latencies, request paths, and server responses. You can use these access logs to analyze traffic patterns and to troubleshoot issues.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CLD-ELB-004
#

default elb_conn_drain = true


elb_conn_drain = false {
    # lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    LoadBalancerAttributes := input.LoadBalancerAttributes[_]
    not LoadBalancerAttributes.ConnectionDraining.Enabled
}

elb_conn_drain_err = "AWS Elastic Load Balancer (Classic) with connection draining disabled" {
    not elb_conn_drain
}

elb_conn_drain_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-004",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elastic Load Balancer (Classic) with connection draining disabled",
    "Policy Description": "This policy identifies Classic Elastic Load Balancers which have connection draining disabled. Connection Draining feature ensures that a Classic load balancer stops sending requests to instances that are de-registering or unhealthy, while keeping the existing connections open. This enables the load balancer to complete in-flight requests made to instances that are de-registering or unhealthy.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CLD-ELB-005
#

default elb_crosszone = true

elb_crosszone = false {
    # lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    LoadBalancerAttributes := input.LoadBalancerAttributes[_]
    not LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled
}

elb_crosszone_err = "AWS Elastic Load Balancer (Classic) with cross-zone load balancing disabled" {
    not elb_crosszone
}

elb_crosszone_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-005",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elastic Load Balancer (Classic) with cross-zone load balancing disabled",
    "Policy Description": "This policy identifies Classic Elastic Load Balancers which have cross-zone load balancing disabled. When Cross-zone load balancing enabled, classic load balancer distributes requests evenly across the registered instances in all enabled Availability Zones. Cross-zone load balancing reduces the need to maintain equivalent numbers of instances in each enabled Availability Zone, and improves your application's ability to handle the loss of one or more instances.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CLD-ELB-008
#

default elb_not_in_use = true

elb_not_in_use = false {
    # lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    LoadBalancerDescriptions := input.LoadBalancerDescriptions[_]
    not LoadBalancerDescriptions.Instances
}

elb_not_in_use = false {
    # lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    LoadBalancerDescriptions := input.LoadBalancerDescriptions[_]
    count(LoadBalancerDescriptions.Instances) == 0
}

elb_not_in_use_err = "AWS Elastic Load Balancer (ELB) not in use" {
    not elb_not_in_use
}

elb_not_in_use_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-008",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elastic Load Balancer (ELB) not in use",
    "Policy Description": "This policy identifies unused Elastic Load Balancers (ELBs) in your AWS account. Any Elastic Load Balancer in your AWS account is adding charges to your monthly bill, although it is not used by any resources. As a best practice, it is recommended to remove ELBs that are not associated with any instances, it will also help you avoid unexpected charges on your bill.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CLD-ELB-009
#

default elb_alb_logs = true

elb_alb_logs = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not input.LoadBalancerAttributes
}

elb_alb_logs = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not input.LoadBalancerAttributes.AccessLog.Enabled
}

elb_alb_logs = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    not input.LoadBalancerAttributes.AccessLog.S3BucketName
}

elb_alb_logs = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    count(input.LoadBalancerAttributes.AccessLog.S3BucketName) == 0
}

elb_alb_logs_err = "AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled" {
    not elb_alb_logs
}

elb_alb_logs_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-009",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled",
    "Policy Description": "This policy identifies ELBv2 ALBs which have access log disabled. Access logs capture detailed information about requests sent to your load balancer and each log contains information such as the time the request was received, the client's IP address, latencies, request paths, and server responses. You can use these access logs to analyze traffic patterns and troubleshoot issues.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CLD-ELB-010
#

default elb_listener_ssl = true

elb_listener_ssl = false {
    # lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    LoadBalancerDescriptions := input.LoadBalancerDescriptions[_]
    ListenerDescriptions := LoadBalancerDescriptions.ListenerDescriptions[_]
    count(ListenerDescriptions.Listener.SSLCertificateId) == 0
}

elb_listener_ssl = false {
    # lower(resource.Type) == "aws::elasticloadbalancing::loadbalancer"
    LoadBalancerDescriptions := input.LoadBalancerDescriptions[_]
    ListenerDescriptions := LoadBalancerDescriptions.ListenerDescriptions[_]
    not ListenerDescriptions.Listener.SSLCertificateId
}

elb_listener_ssl_err = "AWS Elastic Load Balancer with listener TLS/SSL disabled" {
    not elb_listener_ssl
}

elb_listener_ssl_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-010",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elastic Load Balancer with listener TLS/SSL disabled",
    "Policy Description": "This policy identifies Elastic Load Balancers which have listener TLS/SSL disabled. As Load Balancers will be handling all incoming requests and routing the traffic accordingly; The listeners on the load balancers should always receive traffic over secure channel with a valid SSL certificate configured.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}

#
# PR-AWS-CLD-ELB-011
#

default elb_over_https = true

elb_over_https = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    Listeners := input.Listeners
    lower(Listeners.Protocol) == "http"
}

elb_over_https_err = "AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled" {
    not elb_over_https
}

elb_over_https_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-011",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Application Load Balancer (ALB) listener that allow connection requests over HTTP",
    "Policy Description": "This policy identifies Application Load Balancer (ALB) listeners that are configured to accept connection requests over HTTP instead of HTTPS. As a best practice, use the HTTPS protocol to encrypt the communication between the application clients and the application load balancer.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}


#
# PR-AWS-CLD-ELB-012
#

default elb_v2_listener_ssl = true

elb_v2_listener_ssl = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    Listeners := input.Listeners
    not Listeners.Certificates
}

elb_v2_listener_ssl = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    Listeners := input.Listeners
    count(Listeners.Certificates) == 0
}

elb_v2_listener_ssl = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    Listeners := input.Listeners
    Certificates := Listeners.Certificates[j]
    not Certificates.CertificateArn
}

elb_v2_listener_ssl = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    Listeners := input.Listeners
    Certificates := Listeners.Certificates[j]
    count(Certificates.CertificateArn) == 0
}

elb_v2_listener_ssl_err = "AWS Elastic Load Balancer V2 (ELBV2) with listener TLS/SSL disabled" {
    not elb_v2_listener_ssl
}

elb_v2_listener_ssl_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-012",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "AWS Elastic Load Balancer V2 (ELBV2) with listener TLS/SSL disabled",
    "Policy Description": "This policy identifies Elastic Load Balancer V2 (ELBV2) which have listener TLS/SSL disabled. As Load Balancers will be handling all incoming requests and routing the traffic accordingly; The listeners on the load balancers should always receive traffic over secure channel with a valid SSL certificate configured.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-certificates"
}


#
# PR-AWS-CLD-ELB-013
#

default elb_drop_invalid_header = true

elb_drop_invalid_header = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    Attribute := input.Attributes[j]
    lower(Attribute.Key) == "routing.http.drop_invalid_header_fields.enabled"
    lower(Attribute.Value) != "true"
}

elb_drop_invalid_header_err = "Ensure that Application Load Balancer drops HTTP headers" {
    not elb_drop_invalid_header
}

elb_drop_invalid_header_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-013",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that Application Load Balancer drops HTTP headers",
    "Policy Description": "Checks if rule evaluates AWS Application Load Balancers (ALB) to ensure they are configured to drop http headers. The rule is NON_COMPLIANT if the value of routing.http.drop_invalid_header_fields.enabled is set to false",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-loadbalancerattributes.html"
}


#
# PR-AWS-CLD-ELB-014
#

default elb_certificate_listner_arn = true

elb_certificate_listner_arn = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::listenercertificate"
    Listeners := input.Listeners[_]
    not Listeners.ListenerArn
}

elb_certificate_listner_arn = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::listenercertificate"
    Listeners := input.Listeners[_]
    Listeners.ListenerArn == null
}

elb_certificate_listner_arn = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::listenercertificate"
    Listeners := input.Listeners[_]
    count(Listeners.ListenerArn) == 0
}

elb_certificate_listner_arn_err = "Ensure the ELBv2 ListenerCertificate ListenerArn value is defined" {
    not elb_certificate_listner_arn
}

elb_certificate_listner_arn_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-014",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure the ELBv2 ListenerCertificate ListenerArn value is defined",
    "Policy Description": "Ensure the ELBv2 ListenerCertificate ListenerArn value is defined, else an Actor can provide access to CA to non-ADATUM principals.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html"
}


#
# PR-AWS-CLD-ELB-015
#


default elb_listener_sslpolicy = true

allowed_ssl_policies = ["ELBSecurityPolicy-TLS-1-2-2017-01", "ELBSecurityPolicy-TLS-1-2-Ext-2018-06", "ELBSecurityPolicy-FS-1-2-2019-08", "ELBSecurityPolicy-FS-1-2-Res-2019-08", "ELBSecurityPolicy-FS-1-2-Res-2020-10"]

elb_listener_sslpolicy = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    Listeners := input.Listeners[_]
    not Listeners.SslPolicy
}

elb_listener_sslpolicy = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::listener"
    Listeners := input.Listeners[_]
    count([c | lower(Listeners.SslPolicy) == lower(allowed_ssl_policies[_]); c:=1 ]) == 0
}

elb_listener_sslpolicy_err = "Ensure the Load Balancer Listener SSLPolicy is set to at least one value from approved policies" {
    not elb_listener_sslpolicy
}

elb_listener_sslpolicy_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-015",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure the Load Balancer Listener SSLPolicy is set to at least one value from approved policies",
    "Policy Description": "Ensure the Load Balancer Listener SSLPolicy is set to at least one value from approved policies, else an Actor can gain access to ADATUM information due to misconfigured cryptographic settings",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}


#
# PR-AWS-CLD-ELB-016
#

default elb_subnet = true

elb_subnet = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    LoadBalancerDescriptions := input.LoadBalancerDescriptions[_]
	not LoadBalancerDescriptions.Subnets
}

elb_subnet = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    LoadBalancerDescriptions := input.LoadBalancerDescriptions[_]
	LoadBalancerDescriptions.Subnets == null
}

elb_subnet = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    LoadBalancerDescriptions := input.LoadBalancerDescriptions[_]
	count(LoadBalancerDescriptions.Subnets) == 0
}

elb_subnet_err = "Ensure one of Subnets or SubnetMappings is defined for loadbalancer" {
    not elb_subnet
}

elb_subnet_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-016",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure one of Subnets or SubnetMappings is defined for loadbalancer",
    "Policy Description": "Ensure one of Subnets or SubnetMappings is defined for loadbalancer",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-subnetmapping.html#cfn-elasticloadbalancingv2-loadbalancer-subnetmapping-subnetid"
}

#
# PR-AWS-CLD-ELB-017
#

default elb_scheme = true

elb_scheme = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    LoadBalancers := input.LoadBalancers[_]
    not LoadBalancers.Scheme
}

elb_scheme = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    LoadBalancers := input.LoadBalancers[_]
    lower(LoadBalancers.Scheme) != "internal"
}

elb_scheme = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    LoadBalancers := input.LoadBalancers[_]
    LoadBalancers.Scheme == null
}

elb_scheme_err = "Ensure LoadBalancer scheme is set to internal and not internet-facing" {
    not elb_scheme
}

elb_scheme_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-017",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure LoadBalancer scheme is set to internal and not internet-facing",
    "Policy Description": "LoadBalancer scheme must be explicitly set to internal, else an Actor can allow access to ADATUM information through the misconfiguration of an ELB resource",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html"
}


#
# PR-AWS-CLD-ELB-018
#

default elb_type = true

elb_type = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    LoadBalancers := input.LoadBalancers[_]
    lower(LoadBalancers.Type) != "application"
}

elb_type = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::loadbalancer"
    LoadBalancers := input.LoadBalancers[_]
    LoadBalancers.Type == null
}

elb_type_err = "Ensure all load balancers created are application load balancers" {
    not elb_type
}

elb_type_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-018",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure all load balancers created are application load balancers",
    "Policy Description": "Ensure the value of Type for each LoadBalancer resource is application or the Type is not set, since it defaults to application",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-type"
}


#
# PR-AWS-CLD-ELB-019
#

default elb_protocol = true

elb_protocol = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::targetgroup"
    TargetGroups := input.TargetGroups
    TargetTypeAllowed := ["instance" , "ip"]
    lower(TargetGroups.TargetType) == TargetTypeAllowed[_]
    lower(TargetGroups.Protocol) != "https"
}

elb_protocol = false {
    # lower(resource.Type) == "aws::elasticloadbalancingv2::targetgroup"
    TargetGroups := input.TargetGroups
    TargetTypeAllowed := ["instance" , "ip"]
    lower(TargetGroups.TargetType) == TargetTypeAllowed[_]
    not TargetGroups.Protocol
}

elb_protocol_err = "Ensure LoadBalancer TargetGroup Protocol values are limited to HTTPS" {
    not elb_protocol
}

elb_protocol_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-019",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure LoadBalancer TargetGroup Protocol values are limited to HTTPS",
    "Policy Description": "The only allowed Protocol value for LoadBalancer TargetGroups is HTTPS, though the property is ignored if the target type is lambda.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-protocol"
}

#
# PR-AWS-CLD-ELB-020
# aws::elasticloadbalancingv2::loadbalancer
#

default elb_deletion_protection = true

elb_deletion_protection = false {
    Attribute := input.Attributes[j]
    lower(Attribute.Key) == "deletion_protection.enabled"
    lower(Attribute.Value) == "false"
}

elb_deletion_protection_err = "Ensure that AWS Elastic Load Balancer v2 (ELBv2) has deletion protection feature enabled" {
    not elb_deletion_protection
}

elb_deletion_protection_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-020",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that AWS Elastic Load Balancer v2 (ELBv2) has deletion protection feature enabled",
    "Policy Description": "This policy checks if the ELB is protected against accidental deletion by enabling deletion protection.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-loadbalancerattributes.html"
}


#
# PR-AWS-CLD-ELB-021
# aws::elasticloadbalancingv2::loadbalancer
#

default elb_gateway_load_balancer = true

elb_gateway_load_balancer = false {
    LoadBalancer := input.LoadBalancers[_]
    lower(LoadBalancer.Type) == "gateway"
}

elb_gateway_load_balancer_err = "Ensure that AWS ensure Gateway Load Balancer (GWLB) is not being used" {
    not elb_gateway_load_balancer
}

elb_gateway_load_balancer_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-021",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that AWS ensure Gateway Load Balancer (GWLB) is not being used",
    "Policy Description": "This policy checks if Gateway LB is being used or not",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html"
}


#
# PR-AWS-CLD-ELB-022
# aws::elasticloadbalancing::loadbalancer
#

default elb_internet_facing_load_balancer = true

elb_internet_facing_load_balancer = false {
    LoadBalancer := input.LoadBalancers[_]
    contains(lower(LoadBalancer.Scheme), "internet-facing")
}

elb_internet_facing_load_balancer_err = "Ensure Internet facing Classic ELB is not in use" {
    not elb_internet_facing_load_balancer
}

elb_internet_facing_load_balancer_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-022",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Internet facing Classic ELB is not in use",
    "Policy Description": "This policy checks if classic LB is being used in the environment for internet facing applications",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb.html"
}



#
# PR-AWS-CLD-ELB-023
# aws::elasticloadbalancingv2::loadbalancer
#

default elb2_internet_facing_load_balancer = true

elb2_internet_facing_load_balancer = false {
    LoadBalancer := input.LoadBalancers[_]
    contains(lower(LoadBalancer.Scheme), "internet-facing")
}

elb2_internet_facing_load_balancer_err = "Ensure Internet facing Classic ELBV2 is not in use" {
    not elb2_internet_facing_load_balancer
}

elb2_internet_facing_load_balancer_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-023",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Internet facing Classic ELBV2 is not in use",
    "Policy Description": "This policy checks if ELB v2 is being used in the environment",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html"
}


#
# PR-AWS-CLD-ELB-024
# aws::elasticloadbalancingv2::loadbalancer
#

default elb_waf_enabled = true

elb_waf_enabled = false {
    Attribute := input.Attributes[j]
    lower(Attribute.Key) == "waf.fail_open.enabled"
    lower(Attribute.Value) == "false"
}

elb_waf_enabled_err = "Ensure that public facing ELB has WAF attached" {
    not elb_waf_enabled
}

elb_waf_enabled_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-024",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure that public facing ELB has WAF attached",
    "Policy Description": "This policy checks the usage of a WAF with Internet facing ELB. AWS WAF is a web application firewall service that lets you monitor web requests and protect your web applications from malicious requests.",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html#ElasticLoadBalancingv2.Client.describe_load_balancer_attributes"
}


#
# PR-AWS-CLD-ELB-025
# aws::elasticloadbalancingv2::listener

default elbv2_ssl_negotiation_policy = true

elbv2_ssl_negotiation_policy = false {
    Listener := input.Listeners[_]
    contains(Listener.SslPolicy, "ELBSecurityPolicy-TLS-1-0-2015-04")
}

elbv2_ssl_negotiation_policy_err = "Ensure Elastic Load Balancer v2 (ELBv2) SSL negotiation policy is not configured with weak ciphers." {
    not elbv2_ssl_negotiation_policy
}

elbv2_ssl_negotiation_policy_metadata := {
    "Policy Code": "PR-AWS-CLD-ELB-025",
    "Type": "cloud",
    "Product": "AWS",
    "Language": "AWS Cloud",
    "Policy Title": "Ensure Elastic Load Balancer v2 (ELBv2) SSL negotiation policy is not configured with weak ciphers.",
    "Policy Description": "This policy identifies Elastic Load Balancers v2 (ELBv2) which are configured with SSL negotiation policy containing weak ciphers. An SSL cipher is an encryption algorithm that uses encryption keys to create a coded message. SSL protocols use several SSL ciphers to encrypt data over the Internet. As many of the other ciphers are not secure/weak, it is recommended to use only the ciphers recommended in the following AWS link: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html",
    "Resource Type": "",
    "Policy Help URL": "",
    "Resource Help URL": "https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html#ElasticLoadBalancingv2.Client.describe_listeners"
}