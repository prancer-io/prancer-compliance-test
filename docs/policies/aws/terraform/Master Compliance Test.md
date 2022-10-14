



# Prancer Compliance test

## Introduction

### Prancer is a pre-deployment and post-deployment multi-cloud security platform for your Infrastructure as Code (IaC) and live cloud environment. It shifts the security to the left and provides end-to-end security scanning based on the Policy as Code concept. DevOps engineers can use it for static code analysis on IaC to find security drifts and maintain their cloud security posture with continuous compliance features.


----------------------------------------------------


#### These are list of policies related to ```Terraform Infrastructure as Code``` for ```Aws```


----------------------------------------------------


***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-KMS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-KMS-001

***Title: [AWS Customer Master Key (CMK) rotation is not enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-KMS-002

***<font color="white">ID:</font>*** PR-AWS-TRF-KMS-002

***Title: [AWS KMS Customer Managed Key not in use]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-KMS-003

***<font color="white">ID:</font>*** PR-AWS-TRF-KMS-003

***Title: [Ensure no KMS key policy contain wildcard (*) principal]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CT-002

***<font color="white">ID:</font>*** PR-AWS-TRF-CT-002

***Title: [AWS CloudTrail log validation is not enabled in all regions]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CT-004

***<font color="white">ID:</font>*** PR-AWS-TRF-CT-004

***Title: [CloudTrail trail is not integrated with CloudWatch Log]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CT-005

***<font color="white">ID:</font>*** PR-AWS-TRF-CT-005

***Title: [Ensure AWS CloudTrail is logging data events for S3 and Lambda.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-AG-007

***<font color="white">ID:</font>*** PR-AWS-TRF-AG-007

***Title: [AWS API Gateway endpoints without client certificate authentication]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-AG-008

***<font color="white">ID:</font>*** PR-AWS-TRF-AG-008

***Title: [AWS API Gateway REST API is not configured with AWS Web Application Firewall v2 (AWS WAFv2)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-AG-009

***<font color="white">ID:</font>*** PR-AWS-TRF-AG-009

***Title: [Ensure AWS API Gateway uses TLS 1.2 in transit]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-AG-010

***<font color="white">ID:</font>*** PR-AWS-TRF-AG-010

***Title: [Ensure content encoding is enabled for API Gateway.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-AG-001

***<font color="white">ID:</font>*** PR-AWS-TRF-AG-001

***Title: [API Gateway should have API Endpoint type as private and not exposed to internet]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-AG-002

***<font color="white">ID:</font>*** PR-AWS-TRF-AG-002

***Title: [AWS API gateway request parameter is not validated]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-AG-003

***<font color="white">ID:</font>*** PR-AWS-TRF-AG-003

***Title: [AWS API gateway request authorization is not set]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-AG-004

***<font color="white">ID:</font>*** PR-AWS-TRF-AG-004

***Title: [Ensure that API Gateway has enabled access logging]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-AG-005

***<font color="white">ID:</font>*** PR-AWS-TRF-AG-005

***Title: [Ensure API Gateway has tracing enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-AG-006

***<font color="white">ID:</font>*** PR-AWS-TRF-AG-006

***Title: [Ensure API gateway methods are not publicly accessible]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SM-001

***<font color="white">ID:</font>*** PR-AWS-TRF-SM-001

***Title: [Ensure that Secrets Manager secret is encrypted using KMS]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SM-003

***<font color="white">ID:</font>*** PR-AWS-TRF-SM-003

***Title: [Ensure AWS Secrets Manager automatic rotation is enabled.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SM-004

***<font color="white">ID:</font>*** PR-AWS-TRF-SM-004

***Title: [Ensure AWS secret rotation period is per the GS standard (Ex: 30 days).]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-AS-002

***<font color="white">ID:</font>*** PR-AWS-TRF-AS-002

***Title: [Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-AS-003

***<font color="white">ID:</font>*** PR-AWS-TRF-AS-003

***Title: [Ensure EC2 Auto Scaling Group does not launch IMDSv1]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-LG-001

***<font color="white">ID:</font>*** PR-AWS-TRF-LG-001

***Title: [Ensure CloudWatch log groups are encrypted with KMS CMKs]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-LG-002

***<font color="white">ID:</font>*** PR-AWS-TRF-LG-002

***Title: [Ensure CloudWatch log groups has retention days defined]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-WS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-WS-001

***Title: [Ensure that Workspace user volumes is encrypted]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-WS-002

***<font color="white">ID:</font>*** PR-AWS-TRF-WS-002

***Title: [Ensure that Workspace root volumes is encrypted.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-WS-003

***<font color="white">ID:</font>*** PR-AWS-TRF-WS-003

***Title: [Ensure AWS WorkSpaces do not use directory type Simple AD.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CFR-001

***<font color="white">ID:</font>*** PR-AWS-TRF-CFR-001

***Title: [AWS CloudFormation stack configured without SNS topic]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CFR-002

***<font color="white">ID:</font>*** PR-AWS-TRF-CFR-002

***Title: [Ensure CloudFormation template is configured with stack policy.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CFR-003

***<font color="white">ID:</font>*** PR-AWS-TRF-CFR-003

***Title: [Ensure Cloudformation rollback is disabled.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CFR-004

***<font color="white">ID:</font>*** PR-AWS-TRF-CFR-004

***Title: [Ensure an IAM policy is defined with the stack.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CFR-005

***<font color="white">ID:</font>*** PR-AWS-TRF-CFR-005

***Title: [Ensure capabilities in stacks do not have * in it.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CFG-001

***<font color="white">ID:</font>*** PR-AWS-TRF-CFG-001

***Title: [AWS Config must record all possible resources]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CFG-002

***<font color="white">ID:</font>*** PR-AWS-TRF-CFG-002

***Title: [Ensure AWS config is enabled in all regions]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CFG-004

***<font color="white">ID:</font>*** PR-AWS-TRF-CFG-004

***Title: [Ensure AWS Config includes global resources types (IAM).]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-KNS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-KNS-001

***Title: [AWS Kinesis streams are not encrypted using Server Side Encryption]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-KNS-002

***<font color="white">ID:</font>*** PR-AWS-TRF-KNS-002

***Title: [AWS Kinesis streams encryption using default KMS keys instead of Customer's Managed Master Keys]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-MQ-001

***<font color="white">ID:</font>*** PR-AWS-TRF-MQ-001

***Title: [AWS MQ is publicly accessible]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-MQ-002

***<font color="white">ID:</font>*** PR-AWS-TRF-MQ-002

***Title: [Ensure Amazon MQ Broker logging is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-MQ-003

***<font color="white">ID:</font>*** PR-AWS-TRF-MQ-003

***Title: [Ensure ActiveMQ engine version is approved by GS.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-MQ-004

***<font color="white">ID:</font>*** PR-AWS-TRF-MQ-004

***Title: [Ensure RabbitMQ engine version is approved by GS.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-MQ-005

***<font color="white">ID:</font>*** PR-AWS-TRF-MQ-005

***Title: [Ensure General and Audit logs are published to CloudWatch.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-R53-001

***<font color="white">ID:</font>*** PR-AWS-TRF-R53-001

***Title: [Ensure Route53 DNS evaluateTargetHealth is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-GLUE-001

***<font color="white">ID:</font>*** PR-AWS-TRF-GLUE-001

***Title: [Ensure Glue Data Catalog encryption is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-GLUE-002

***<font color="white">ID:</font>*** PR-AWS-TRF-GLUE-002

***Title: [Ensure AWS Glue security configuration encryption is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-GLUE-003

***<font color="white">ID:</font>*** PR-AWS-TRF-GLUE-003

***Title: [Ensure AWS Glue encrypt data at rest]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-AS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-AS-001

***Title: [Ensure EBS volumes have encrypted launch configurations]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-WAF-001

***<font color="white">ID:</font>*** PR-AWS-TRF-WAF-001

***Title: [JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-INS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-INS-001

***Title: [Enable AWS Inspector to detect Vulnerability]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-APS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-APS-001

***Title: [Ensure AppSync is configured with AWS Web Application Firewall v2.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-VPC-001

***<font color="white">ID:</font>*** PR-AWS-TRF-VPC-001

***Title: [AWS VPC subnets should not allow automatic public IP assignment]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-VPC-002

***<font color="white">ID:</font>*** PR-AWS-TRF-VPC-002

***Title: [Ensure all EIP addresses allocated to a VPC are attached related EC2 instances]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-VPC-003

***<font color="white">ID:</font>*** PR-AWS-TRF-VPC-003

***Title: [Ensure VPC endpoint service is configured for manual acceptance]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-VPC-006

***<font color="white">ID:</font>*** PR-AWS-TRF-VPC-006

***Title: [Ensure AWS VPC endpoint policy is not overly permissive.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EKS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-EKS-001

***Title: [AWS EKS cluster control plane assigned multiple security groups]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EKS-002

***<font color="white">ID:</font>*** PR-AWS-TRF-EKS-002

***Title: [AWS EKS unsupported Master node version.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EKS-003

***<font color="white">ID:</font>*** PR-AWS-TRF-EKS-003

***Title: [Ensure AWS EKS cluster has secrets encryption enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EKS-004

***<font color="white">ID:</font>*** PR-AWS-TRF-EKS-004

***Title: [Ensure Kubernetes secrets are encrypted using CMKs managed in AWS KMS]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EKS-006

***<font color="white">ID:</font>*** PR-AWS-TRF-EKS-006

***Title: [Ensure AWS EKS only uses latest versions of Kubernetes.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EKS-007

***<font color="white">ID:</font>*** PR-AWS-TRF-EKS-007

***Title: [Ensure EKS cluster is configured with control plane security group attached to it.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EKS-008

***<font color="white">ID:</font>*** PR-AWS-TRF-EKS-008

***Title: [Ensure only private access for Amazon EKS cluster's Kubernetes API is enabled.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EKS-009

***<font color="white">ID:</font>*** PR-AWS-TRF-EKS-009

***Title: [Ensure AWS EKS control plane logging is enabled.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ES-001

***<font color="white">ID:</font>*** PR-AWS-TRF-ES-001

***Title: [AWS ElasticSearch cluster not in a VPC]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ES-002

***<font color="white">ID:</font>*** PR-AWS-TRF-ES-002

***Title: [AWS Elasticsearch domain Encryption for data at rest is disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ES-003

***<font color="white">ID:</font>*** PR-AWS-TRF-ES-003

***Title: [AWS Elasticsearch domain has Dedicated master set to disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ES-004

***<font color="white">ID:</font>*** PR-AWS-TRF-ES-004

***Title: [AWS Elasticsearch domain has Index slow logs set to disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ES-005

***<font color="white">ID:</font>*** PR-AWS-TRF-ES-005

***Title: [AWS Elasticsearch domain has Search slow logs set to disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ES-006

***<font color="white">ID:</font>*** PR-AWS-TRF-ES-006

***Title: [AWS Elasticsearch domain has Zone Awareness set to disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ES-007

***<font color="white">ID:</font>*** PR-AWS-TRF-ES-007

***Title: [Ensure node-to-node encryption is enabled on each ElasticSearch Domain]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ES-008

***<font color="white">ID:</font>*** PR-AWS-TRF-ES-008

***Title: [AWS Elasticsearch domain is not configured with HTTPS]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ES-009

***<font color="white">ID:</font>*** PR-AWS-TRF-ES-009

***Title: [Elasticsearch Domain should not have Encrytion using AWS Managed Keys]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ES-010

***<font color="white">ID:</font>*** PR-AWS-TRF-ES-010

***Title: [Ensure ElasticSearch has a custom endpoint configured.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ES-011

***<font color="white">ID:</font>*** PR-AWS-TRF-ES-011

***Title: [Ensure Slow Logs feature is enabled for ElasticSearch cluster.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ES-013

***<font color="white">ID:</font>*** PR-AWS-TRF-ES-013

***Title: [Ensure fine-grained access control is enabled during domain creation in ElasticSearch.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-NACL-001

***<font color="white">ID:</font>*** PR-AWS-TRF-NACL-001

***Title: [AWS Network ACLs with Inbound rule to allow All ICMP IPv4]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-NACL-002

***<font color="white">ID:</font>*** PR-AWS-TRF-NACL-002

***Title: [AWS Network ACLs with Inbound rule to allow All ICMP IPv6]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-NACL-003

***<font color="white">ID:</font>*** PR-AWS-TRF-NACL-003

***Title: [AWS Network ACLs with Inbound rule to allow All Traffic]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-NACL-004

***<font color="white">ID:</font>*** PR-AWS-TRF-NACL-004

***Title: [AWS Network ACLs with Outbound rule to allow All ICMP IPv4]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-NACL-005

***<font color="white">ID:</font>*** PR-AWS-TRF-NACL-005

***Title: [AWS Network ACLs with Outbound rule to allow All ICMP IPv6]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-NACL-006

***<font color="white">ID:</font>*** PR-AWS-TRF-NACL-006

***Title: [AWS Network ACLs with Outbound rule to allow All Traffic]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-NACL-007

***<font color="white">ID:</font>*** PR-AWS-TRF-NACL-007

***Title: [Unrestricted Inbound Traffic on Remote Server Administration Ports]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SGM-001

***<font color="white">ID:</font>*** PR-AWS-TRF-SGM-001

***Title: [AWS SageMaker notebook instance not configured with data encryption at rest using KMS key]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SGM-002

***<font color="white">ID:</font>*** PR-AWS-TRF-SGM-002

***Title: [AWS SageMaker notebook instance with root access enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SGM-003

***<font color="white">ID:</font>*** PR-AWS-TRF-SGM-003

***Title: [AWS SageMaker notebook instance configured with direct internet access feature]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SGM-004

***<font color="white">ID:</font>*** PR-AWS-TRF-SGM-004

***Title: [AWS SageMaker notebook instance is not placed in VPC]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CB-001

***<font color="white">ID:</font>*** PR-AWS-TRF-CB-001

***Title: [Ensure CodeBuild project Artifact encryption is not disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CB-002

***<font color="white">ID:</font>*** PR-AWS-TRF-CB-002

***Title: [Ensure that CodeBuild projects are encrypted using CMK]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CD-001

***<font color="white">ID:</font>*** PR-AWS-TRF-CD-001

***Title: [AWS CodeDeploy application compute platform must be ECS or Lambda]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CP-001

***<font color="white">ID:</font>*** PR-AWS-TRF-CP-001

***Title: [Code Pipeline Encryption at rest with customer-managed key (CMK) should be enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-001

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-001

***Title: [AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-002

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-002

***Title: [AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-003

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-003

***Title: [AWS Elastic Load Balancer (Classic) with access log disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-004

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-004

***Title: [AWS Elastic Load Balancer (Classic) with connection draining disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-005

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-005

***Title: [AWS Elastic Load Balancer (Classic) with cross-zone load balancing disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-008

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-008

***Title: [AWS Elastic Load Balancer (ELB) not in use]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-009

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-009

***Title: [AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-010

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-010

***Title: [AWS Elastic Load Balancer with listener TLS/SSL disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-011

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-011

***Title: [AWS Application Load Balancer (ALB) listener that allow connection requests over HTTP]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-012

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-012

***Title: [AWS Elastic Load Balancer V2 (ELBV2) with listener TLS/SSL disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-013

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-013

***Title: [Ensure that Application Load Balancer drops HTTP headers]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-014

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-014

***Title: [Ensure the ELBv2 ListenerCertificate listener_arn value is defined]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-015

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-015

***Title: [Ensure the Load Balancer Listener SSLPolicy is set to at least one value from approved policies]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-016

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-016

***Title: [Ensure one of subnets or subnet_mapping is defined for loadbalancer]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-017

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-017

***Title: [Ensure LoadBalancer scheme is set to internal and not internet-facing]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-018

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-018

***Title: [Ensure all load balancers created are application load balancers]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-019

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-019

***Title: [Ensure LoadBalancer TargetGroup protocol values are limited to HTTPS]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-020

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-020

***Title: [Ensure that AWS Elastic Load Balancer v2 (ELBv2) has deletion protection feature enabled.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-021

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-021

***Title: [Ensure that AWS ensure Gateway Load Balancer (GWLB) is not being used.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-022

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-022

***Title: [Ensure Internet facing Classic ELB is not in use.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-023

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-023

***Title: [Ensure Internet facing ELBV2 is not in use.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-024

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-024

***Title: [Ensure that public facing ELB has WAF attached]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ELB-025

***<font color="white">ID:</font>*** PR-AWS-TRF-ELB-025

***Title: [Ensure Elastic Load Balancer v2 (ELBv2) SSL negotiation policy is not configured with weak ciphers.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EBS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-EBS-001

***Title: [AWS EBS volumes are not encrypted]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EFS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-EFS-001

***Title: [AWS Elastic File System (EFS) not encrypted using Customer Managed Key]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EFS-002

***<font color="white">ID:</font>*** PR-AWS-TRF-EFS-002

***Title: [AWS Elastic File System (EFS) with encryption for data at rest disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-TRF-002

***<font color="white">ID:</font>*** PR-AWS-TRF-TRF-002

***Title: [Ensure Transfer Server is not use FTP protocol.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-001

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-001

***Title: [AWS Access logging not enabled on S3 buckets]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-001V4

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-001V4

***Title: [AWS Access logging not enabled on S3 buckets]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-002

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-002

***Title: [AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-003

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-003

***Title: [AWS S3 Bucket has Global GET Permissions enabled via bucket policy]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-004

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-004

***Title: [AWS S3 Bucket has Global LIST Permissions enabled via bucket policy]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-005

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-005

***Title: [AWS S3 Bucket has Global PUT Permissions enabled via bucket policy]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-007

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-007

***Title: [AWS S3 Object Versioning is disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-007V4

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-007V4

***Title: [AWS S3 Object Versioning is disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-009

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-009

***Title: [AWS S3 bucket not configured with secure data transport policy]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-013

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-013

***Title: [S3 buckets with configurations set to host websites]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-013V4

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-013V4

***Title: [S3 buckets with configurations set to host websites]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-006

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-006

***Title: [AWS S3 CloudTrail buckets for which access logging is disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-008

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-008

***Title: [AWS S3 bucket has global view ACL permissions enabled.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-008V4

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-008V4

***Title: [AWS S3 bucket has global view ACL permissions enabled.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-010

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-010

***Title: [AWS S3 buckets are accessible to any authenticated user.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-011

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-011

***Title: [AWS S3 buckets are accessible to public]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-012

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-012

***Title: [AWS S3 buckets do not have server side encryption.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-014

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-014

***Title: [Ensure S3 hosted sites supported hardened CORS]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-014V4

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-014V4

***Title: [Ensure S3 hosted sites supported hardened CORS]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-BKP-001

***<font color="white">ID:</font>*** PR-AWS-TRF-BKP-001

***Title: [Ensure Glacier Backup policy is not publicly accessible]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-015

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-015

***Title: [Ensure S3 bucket is encrypted using KMS]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-015V4

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-015V4

***Title: [Ensure S3 bucket is encrypted using KMS]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-016

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-016

***Title: [Ensure S3 bucket has enabled lock configuration]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-016V4

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-016V4

***Title: [Ensure S3 bucket has enabled lock configuration]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-017

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-017

***Title: [Ensure S3 bucket cross-region replication is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-017V4

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-017V4

***Title: [Ensure S3 bucket cross-region replication is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-018

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-018

***Title: [Ensure S3 Bucket has public access blocks]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-019

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-019

***Title: [Ensure S3 bucket RestrictPublicBucket is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-020

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-020

***Title: [Ensure S3 bucket ignore_public_acls is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-021

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-021

***Title: [Ensure S3 Bucket block_public_policy is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-023

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-023

***Title: [Ensure AWS S3 bucket policy is not overly permissive to any principal.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-024

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-024

***Title: [Ensure AWS S3 bucket policy is not overly permissive to any principal.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-S3-025

***<font color="white">ID:</font>*** PR-AWS-TRF-S3-025

***Title: [Ensure AWS S3 bucket do not have policy that is overly permissive to VPC endpoints.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EMR-001

***<font color="white">ID:</font>*** PR-AWS-TRF-EMR-001

***Title: [AWS EMR cluster is not configured with security configuration]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EMR-002

***<font color="white">ID:</font>*** PR-AWS-TRF-EMR-002

***Title: [AWS EMR cluster is not configured with Kerberos Authentication]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EMR-003

***<font color="white">ID:</font>*** PR-AWS-TRF-EMR-003

***Title: [AWS EMR cluster is not configured with CSE CMK for data at rest encryption (Amazon S3 with EMRFS)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EMR-004

***<font color="white">ID:</font>*** PR-AWS-TRF-EMR-004

***Title: [AWS EMR cluster is not enabled with local disk encryption using CMK]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EMR-006

***<font color="white">ID:</font>*** PR-AWS-TRF-EMR-006

***Title: [AWS EMR cluster is not enabled with data encryption at rest]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EMR-007

***<font color="white">ID:</font>*** PR-AWS-TRF-EMR-007

***Title: [AWS EMR cluster is not enabled with data encryption in transit]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EMR-008

***<font color="white">ID:</font>*** PR-AWS-TRF-EMR-008

***Title: [Ensure Cluster level logging is enabled for EMR.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EMR-009

***<font color="white">ID:</font>*** PR-AWS-TRF-EMR-009

***Title: [Ensure EMR cluster is not visible to all IAM users.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EMR-010

***<font color="white">ID:</font>*** PR-AWS-TRF-EMR-010

***Title: [Ensure Termination protection is enabled for instances in the cluster for EMR.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SQS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-SQS-001

***Title: [AWS SQS does not have a dead letter queue configured]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SQS-002

***<font color="white">ID:</font>*** PR-AWS-TRF-SQS-002

***Title: [AWS SQS queue encryption using default KMS key instead of CMK]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SQS-003

***<font color="white">ID:</font>*** PR-AWS-TRF-SQS-003

***Title: [AWS SQS server side encryption not enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SQS-004

***<font color="white">ID:</font>*** PR-AWS-TRF-SQS-004

***Title: [Ensure SQS queue policy is not publicly accessible]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SQS-005

***<font color="white">ID:</font>*** PR-AWS-TRF-SQS-005

***Title: [Ensure SQS policy documents do not allow all actions]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SQS-006

***<font color="white">ID:</font>*** PR-AWS-TRF-SQS-006

***Title: [Ensure AWS SQS queue access policy is not overly permissive.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SQS-007

***<font color="white">ID:</font>*** PR-AWS-TRF-SQS-007

***Title: [Ensure SQS is only accessible via specific VPCe service.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SQS-008

***<font color="white">ID:</font>*** PR-AWS-TRF-SQS-008

***Title: [Ensure SQS data is encrypted in Transit using SSL/TLS.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-MSK-001

***<font color="white">ID:</font>*** PR-AWS-TRF-MSK-001

***Title: [Use KMS Customer Master Keys for AWS MSK Clusters]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-MSK-002

***<font color="white">ID:</font>*** PR-AWS-TRF-MSK-002

***Title: [Ensure data is Encrypted in transit (TLS)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-MSK-003

***<font color="white">ID:</font>*** PR-AWS-TRF-MSK-003

***Title: [Ensure client authentication is enabled with TLS (mutual TLS authentication)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-MSK-004

***<font color="white">ID:</font>*** PR-AWS-TRF-MSK-004

***Title: [Ensure MSK cluster is setup in GS VPC]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-MSK-005

***<font color="white">ID:</font>*** PR-AWS-TRF-MSK-005

***Title: [Ensure Amazon MSK cluster has logging enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-MSK-006

***<font color="white">ID:</font>*** PR-AWS-TRF-MSK-006

***Title: [Ensure enhanaced monitoring for AWS MSK is not set to default.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-MSK-007

***<font color="white">ID:</font>*** PR-AWS-TRF-MSK-007

***Title: [Ensure public access is disabled for AWS MSK.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-001

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-001

***Title: [Ensure no wildcards are specified in IAM policy with 'Resource' section]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-002

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-002

***Title: [Ensure no wildcards are specified in IAM policy with 'Action' section]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-003

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-003

***Title: [Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-004

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-004

***Title: [Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*']***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-005

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-005

***Title: [AWS IAM policy allows assume role permission across all services]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-006

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-006

***Title: [AWS IAM policy is overly permissive to all traffic via condition clause]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-007

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-007

***Title: [AWS IAM policy allows full administrative privileges]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-008

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-008

***Title: [Ensure IAM groups contains at least one IAM user]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-011

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-011

***Title: [Ensure Lambda IAM policy is not overly permissive to all traffic]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-012

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-012

***Title: [Ensure IAM policy is not overly permissive to Lambda service]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-013

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-013

***Title: [Ensure that the AWS EC2 instances don't have a risky set of permissions management access to minimize security risks.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-014

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-014

***Title: [Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-015

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-015

***Title: [Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of permissions management access permissions to minimize security risks.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-016

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-016

***Title: [Ensure that the AWS EC2 instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-017

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-017

***Title: [Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of org write permissions to minimize security risks.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-018

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-018

***Title: [Ensure that the AWS policies don't have '*' in the resource section of the policy statement of elastic bean stalk.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-019

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-019

***Title: [Ensure that the AWS policies don't have '*' in the resource section of the policy statement of ec2.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-020

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-020

***Title: [Ensure that the AWS policies don't have '*' in the resource section of the policy statement of lambda function.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-021

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-021

***Title: [Ensure that the AWS policies don't have '*' in the resource section of the policy statement of ecs task definition.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-022

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-022

***Title: [Ensure that the AWS ECR Repository resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-023

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-023

***Title: [Ensure that the AWS Lambda Function resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-024

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-024

***Title: [Ensure that the AWS S3 bucket resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-025

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-025

***Title: [Ensure that the AWS SQS Queue resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-026

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-026

***Title: [Ensure that the AWS Secret Manager Secret resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-027

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-027

***Title: [Ensure AWS IAM policy do not have permission which may cause privilege escalation.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-029

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-029

***Title: [Ensure IAM policy is not overly permissive to all traffic for ecs.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-030

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-030

***Title: [Ensure IAM policy is not overly permissive to all traffic for elasticsearch.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-041

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-041

***Title: [Ensure AWS IAM policy does not allows decryption actions on all KMS keys.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-042

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-042

***Title: [Ensure IAM policy is attached to group rather than user.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-043

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-043

***Title: [Ensure IAM policy is not overly permissive to all traffic via condition clause.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-044

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-044

***Title: [Ensure AWS IAM policy is not overly permissive to STS services.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-045

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-045

***Title: [Ensure AWS SNS Topic is not publicly accessible through IAM policies.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-IAM-046

***<font color="white">ID:</font>*** PR-AWS-TRF-IAM-046

***Title: [Ensure AWS SageMaker notebook instance IAM policy is not overly permissive to all traffic.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RSH-001

***<font color="white">ID:</font>*** PR-AWS-TRF-RSH-001

***Title: [AWS Redshift Cluster not encrypted using Customer Managed Key]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RSH-002

***<font color="white">ID:</font>*** PR-AWS-TRF-RSH-002

***Title: [AWS Redshift clusters should not be publicly accessible]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RSH-007

***<font color="white">ID:</font>*** PR-AWS-TRF-RSH-007

***Title: [AWS Redshift database does not have audit logging enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RSH-008

***<font color="white">ID:</font>*** PR-AWS-TRF-RSH-008

***Title: [Ensure AWS Redshift - Enhanced VPC routing must be enabled.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RSH-011

***<font color="white">ID:</font>*** PR-AWS-TRF-RSH-011

***Title: [Ensure Redshift database clusters are not using default master username.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RSH-012

***<font color="white">ID:</font>*** PR-AWS-TRF-RSH-012

***Title: [Ensure Redshift database clusters are not using default port(5439) for database connection.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RSH-013

***<font color="white">ID:</font>*** PR-AWS-TRF-RSH-013

***Title: [Ensure automated backups are enabled for Redshift cluster.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RSH-003

***<font color="white">ID:</font>*** PR-AWS-TRF-RSH-003

***Title: [AWS Redshift does not have require_ssl configured]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RSH-004

***<font color="white">ID:</font>*** PR-AWS-TRF-RSH-004

***Title: [AWS Redshift instances are not encrypted]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RSH-005

***<font color="white">ID:</font>*** PR-AWS-TRF-RSH-005

***Title: [Ensure Redshift cluster allow version upgrade by default]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RSH-006

***<font color="white">ID:</font>*** PR-AWS-TRF-RSH-006

***Title: [Ensure Redshift is not deployed outside of a VPC]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SNS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-SNS-001

***Title: [AWS SNS subscription is not configured with HTTPS]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SNS-002

***<font color="white">ID:</font>*** PR-AWS-TRF-SNS-002

***Title: [AWS SNS topic encrypted using default KMS key instead of CMK]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SNS-003

***<font color="white">ID:</font>*** PR-AWS-TRF-SNS-003

***Title: [AWS SNS topic with server-side encryption disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SNS-004

***<font color="white">ID:</font>*** PR-AWS-TRF-SNS-004

***Title: [Ensure SNS Topic policy is not publicly accessible]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SNS-005

***<font color="white">ID:</font>*** PR-AWS-TRF-SNS-005

***Title: [Ensure AWS SNS topic is not exposed to unauthorized access.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SNS-006

***<font color="white">ID:</font>*** PR-AWS-TRF-SNS-006

***Title: [Ensure AWS SNS topic policy is not overly permissive for publishing.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SNS-007

***<font color="white">ID:</font>*** PR-AWS-TRF-SNS-007

***Title: [Ensure AWS SNS topic policy is not overly permissive for subscription.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SNS-008

***<font color="white">ID:</font>*** PR-AWS-TRF-SNS-008

***Title: [Ensure AWS SNS topic do not have cross-account access.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SNS-009

***<font color="white">ID:</font>*** PR-AWS-TRF-SNS-009

***Title: [Ensure SNS is only accessible via specific VPCe service.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SNS-010

***<font color="white">ID:</font>*** PR-AWS-TRF-SNS-010

***Title: [Ensure SNS topic is configured with secure data transport policy.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ACM-001

***<font color="white">ID:</font>*** PR-AWS-TRF-ACM-001

***Title: [AWS ACM Certificate with wildcard domain name]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ACM-002

***<font color="white">ID:</font>*** PR-AWS-TRF-ACM-002

***Title: [AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ACM-003

***<font color="white">ID:</font>*** PR-AWS-TRF-ACM-003

***Title: [Ensure that the CertificateManager certificates reference only Private ACMPCA certificate authorities]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECR-001

***<font color="white">ID:</font>*** PR-AWS-TRF-ECR-001

***Title: [Ensure ECR image tags are immutable]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECR-002

***<font color="white">ID:</font>*** PR-AWS-TRF-ECR-002

***Title: [Ensure ECR repositories are encrypted]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECR-003

***<font color="white">ID:</font>*** PR-AWS-TRF-ECR-003

***Title: [Ensure ECR image scan on push is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECR-004

***<font color="white">ID:</font>*** PR-AWS-TRF-ECR-004

***Title: [Ensure AWS ECR Repository is not publicly accessible]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECR-005

***<font color="white">ID:</font>*** PR-AWS-TRF-ECR-005

***Title: [Enable Enhanced scan type for AWS ECR registry to detect vulnerability]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECR-006

***<font color="white">ID:</font>*** PR-AWS-TRF-ECR-006

***Title: [Ensure ECR resources are accessible only via private endpoint.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECR-007

***<font color="white">ID:</font>*** PR-AWS-TRF-ECR-007

***Title: [Ensure lifecycle policy is enabled for ECR image repositories.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC2-001

***<font color="white">ID:</font>*** PR-AWS-TRF-EC2-001

***Title: [AWS EC2 Instance IAM Role not enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC2-002

***<font color="white">ID:</font>*** PR-AWS-TRF-EC2-002

***Title: [AWS EC2 instance is not configured with VPC]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC2-003

***<font color="white">ID:</font>*** PR-AWS-TRF-EC2-003

***Title: [AWS EC2 instances with Public IP and associated with Security Groups have Internet Access]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC2-004

***<font color="white">ID:</font>*** PR-AWS-TRF-EC2-004

***Title: [Ensure that EC2 instace is EBS Optimized]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC2-005

***<font color="white">ID:</font>*** PR-AWS-TRF-EC2-005

***Title: [Ensure detailed monitoring is enabled for EC2 instances]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC2-006

***<font color="white">ID:</font>*** PR-AWS-TRF-EC2-006

***Title: [Ensure AWS EC2 EBS and Network components' deletion protection is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC2-007

***<font color="white">ID:</font>*** PR-AWS-TRF-EC2-007

***Title: [Ensure Amazon Machine Image (AMI) is not infected with mining malware.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC2-010

***<font color="white">ID:</font>*** PR-AWS-TRF-EC2-010

***Title: [Ensure EBS volumes are encrypted using Customer Managed Key (CMK)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-001

***Title: [AWS ECS task definition elevated privileges enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-002

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-002

***Title: [AWS ECS/Fargate task definition execution IAM Role not found]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-003

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-003

***Title: [AWS ECS/ Fargate task definition root user found]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-004

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-004

***Title: [AWS ECS Task Definition readonlyRootFilesystem Not Enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-005

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-005

***Title: [AWS ECS task definition resource limits not set.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-006

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-006

***Title: [AWS ECS task definition logging not enabled.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-007

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-007

***Title: [Ensure EFS volumes in ECS task definitions have encryption in transit enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-008

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-008

***Title: [Ensure container insights are enabled on ECS cluster]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-009

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-009

***Title: [Ensure ECS Services and Task Set enable_execute_command property set to False]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-010

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-010

***Title: [Ensure that ECS Service and Task Set network configuration disallows the assignment of public IPs]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-011

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-011

***Title: [Ensure that ECS services and Task Sets are launched as Fargate type]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-012

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-012

***Title: [Value(s) of subnets attached to aws ecs service subnets are vended]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-013

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-013

***Title: [VPC configurations on ECS Services must use either vended security groups]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-014

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-014

***Title: [Ensure that ECS Task Definition have their network mode property set to awsvpc]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-015

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-015

***Title: [AWS ECS - Ensure Fargate task definition logging is enabled.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-016

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-016

***Title: [Ensure there are no undefined ECS task definition empty roles for ECS.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ECS-017

***<font color="white">ID:</font>*** PR-AWS-TRF-ECS-017

***Title: [Ensure that a log driver has been configured for each ECS task definition.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-LMD-001

***<font color="white">ID:</font>*** PR-AWS-TRF-LMD-001

***Title: [AWS Lambda Environment Variables not encrypted at-rest using CMK]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-LMD-002

***<font color="white">ID:</font>*** PR-AWS-TRF-LMD-002

***Title: [AWS Lambda Function is not assigned to access within VPC]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-LMD-003

***<font color="white">ID:</font>*** PR-AWS-TRF-LMD-003

***Title: [AWS Lambda functions with tracing not enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-LMD-004

***<font color="white">ID:</font>*** PR-AWS-TRF-LMD-004

***Title: [Ensure AWS Lambda function is configured for function-level concurrent execution limit]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-LMD-005

***<font color="white">ID:</font>*** PR-AWS-TRF-LMD-005

***Title: [Ensure AWS Lambda function is configured for a DLQ]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CF-001

***<font color="white">ID:</font>*** PR-AWS-TRF-CF-001

***Title: [AWS CloudFront Distributions with Field-Level Encryption not enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CF-002

***<font color="white">ID:</font>*** PR-AWS-TRF-CF-002

***Title: [AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CF-003

***<font color="white">ID:</font>*** PR-AWS-TRF-CF-003

***Title: [AWS CloudFront distribution with access logging disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CF-004

***<font color="white">ID:</font>*** PR-AWS-TRF-CF-004

***Title: [AWS CloudFront origin protocol policy does not enforce HTTPS-only]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CF-005

***<font color="white">ID:</font>*** PR-AWS-TRF-CF-005

***Title: [AWS CloudFront viewer protocol policy is not configured with HTTPS]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CF-006

***<font color="white">ID:</font>*** PR-AWS-TRF-CF-006

***Title: [AWS CloudFront web distribution that allow TLS versions 1.0 or lower]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CF-007

***<font color="white">ID:</font>*** PR-AWS-TRF-CF-007

***Title: [AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CF-008

***<font color="white">ID:</font>*** PR-AWS-TRF-CF-008

***Title: [AWS CloudFront web distribution with default SSL certificate]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CF-009

***<font color="white">ID:</font>*** PR-AWS-TRF-CF-009

***Title: [AWS CloudFront web distribution with geo restriction disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-CF-010

***<font color="white">ID:</font>*** PR-AWS-TRF-CF-010

***Title: [AWS Cloudfront Distribution with S3 have Origin Access set to disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-DD-001

***<font color="white">ID:</font>*** PR-AWS-TRF-DD-001

***Title: [AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC-001

***<font color="white">ID:</font>*** PR-AWS-TRF-EC-001

***Title: [AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC-002

***<font color="white">ID:</font>*** PR-AWS-TRF-EC-002

***Title: [AWS ElastiCache Redis cluster with Redis AUTH feature disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC-003

***<font color="white">ID:</font>*** PR-AWS-TRF-EC-003

***Title: [AWS ElastiCache Redis cluster with encryption for data at rest disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC-004

***<font color="white">ID:</font>*** PR-AWS-TRF-EC-004

***Title: [AWS ElastiCache Redis cluster with in-transit encryption disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC-007

***<font color="white">ID:</font>*** PR-AWS-TRF-EC-007

***Title: [Ensure in AWS ElastiCache, automatic backups is enabled for Redis cluster.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ATH-002

***<font color="white">ID:</font>*** PR-AWS-TRF-ATH-002

***Title: [Ensure Athena logging is enabled for athena workgroup.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-001

***Title: [AWS RDS DB cluster encryption is disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-002

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-002

***Title: [AWS RDS database instance is publicly accessible]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-006

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-006

***Title: [AWS RDS instance is not encrypted]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-007

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-007

***Title: [AWS RDS instance with Multi-Availability Zone disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-008

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-008

***Title: [AWS RDS instance with copy tags to snapshots disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-009

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-009

***Title: [AWS RDS instance without Automatic Backup setting]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-010

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-010

***Title: [AWS RDS minor upgrades not enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-011

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-011

***Title: [AWS RDS retention policy less than 7 days]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-003

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-003

***Title: [AWS RDS database not encrypted using Customer Managed Key]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-004

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-004

***Title: [AWS RDS event subscription disabled for DB instance]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-005

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-005

***Title: [AWS RDS event subscription disabled for DB security groups]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-DMS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-DMS-001

***Title: [Ensure DMS endpoints are supporting SSL configuration]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC-005

***<font color="white">ID:</font>*** PR-AWS-TRF-EC-005

***Title: [Ensure that ElastiCache replication Group (Redis) are encrypted at rest with customer managed CMK key]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-EC-006

***<font color="white">ID:</font>*** PR-AWS-TRF-EC-006

***Title: [Ensure 'default' value is not used on Security Group setting for Redis cache engines]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-012

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-012

***Title: [AWS RDS cluster retention policy less than 7 days]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-DAX-001

***<font color="white">ID:</font>*** PR-AWS-TRF-DAX-001

***Title: [Ensure DAX is securely encrypted at rest]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-DAX-002

***<font color="white">ID:</font>*** PR-AWS-TRF-DAX-002

***Title: [Ensure AWS DAX data is encrypted in transit]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-DD-002

***<font color="white">ID:</font>*** PR-AWS-TRF-DD-002

***Title: [Ensure DynamoDB PITR is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-DD-003

***<font color="white">ID:</font>*** PR-AWS-TRF-DD-003

***Title: [Dynamo DB kinesis specification property should not be null]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-QLDB-001

***<font color="white">ID:</font>*** PR-AWS-TRF-QLDB-001

***Title: [Ensure QLDB ledger permissions mode is set to STANDARD]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-DDB-001

***<font color="white">ID:</font>*** PR-AWS-TRF-DDB-001

***Title: [Ensure DocumentDB cluster is encrypted at rest]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-DDB-002

***<font color="white">ID:</font>*** PR-AWS-TRF-DDB-002

***Title: [Ensure AWS DocumentDB logging is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-DDB-003

***<font color="white">ID:</font>*** PR-AWS-TRF-DDB-003

***Title: [Ensure DocDB ParameterGroup has TLS enable]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-DDB-004

***<font color="white">ID:</font>*** PR-AWS-TRF-DDB-004

***Title: [Ensure DocDB has audit logs enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-ATH-001

***<font color="white">ID:</font>*** PR-AWS-TRF-ATH-001

***Title: [Ensure to enable enforce_workgroup_configuration for athena workgroup]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-TS-001

***<font color="white">ID:</font>*** PR-AWS-TRF-TS-001

***Title: [Ensure Timestream database is encrypted using KMS]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-013

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-013

***Title: [Ensure RDS clusters and instances have deletion protection enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-DMS-002

***<font color="white">ID:</font>*** PR-AWS-TRF-DMS-002

***Title: [Ensure DMS replication instance is not publicly accessible]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-NPT-001

***<font color="white">ID:</font>*** PR-AWS-TRF-NPT-001

***Title: [Ensure Neptune logging is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-014

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-014

***Title: [Ensure PGAudit is enabled on RDS Postgres instances]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-015

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-015

***Title: [AWS RDS Global DB cluster encryption is disabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-016

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-016

***Title: [Ensure RDS cluster has IAM authentication enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-017

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-017

***Title: [Ensure RDS instace has IAM authentication enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-018

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-018

***Title: [Ensure respective logs of Amazon RDS instance are enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-019

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-019

***Title: [Enhanced monitoring for Amazon RDS instances is enabled]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-021

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-021

***Title: [Ensure RDS instances do not use a deprecated version of Aurora-PostgreSQL.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-022

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-022

***Title: [Ensure RDS cluster do not use a deprecated version of Aurora-PostgreSQL.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-023

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-023

***Title: [Ensure RDS instances do not use a deprecated version of PostgreSQL.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-024

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-024

***Title: [Ensure RDS dbcluster do not use a deprecated version of PostgreSQL.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-027

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-027

***Title: [Ensure AWS RDS DB authentication is only enabled via IAM.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-028

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-028

***Title: [Ensure AWS RDS Cluster has setup backup retention period of at least 30 days.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-029

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-029

***Title: [Ensure AWS RDS DB instance has deletion protection enabled.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-RDS-030

***<font color="white">ID:</font>*** PR-AWS-TRF-RDS-030

***Title: [Ensure RDS DB instance has setup backup retention period of at least 30 days.]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-030

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-030

***Title: [Publicly exposed DB Ports]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-031

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-031

***Title: [Instance is communicating with ports known to mine Bitcoin]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-032

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-032

***Title: [Instance is communicating with ports known to mine Ethereum]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-001

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-001

***Title: [AWS Security Groups allow internet traffic from internet to Windows RPC port (135)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-002

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-002

***Title: [AWS Security Groups allow internet traffic from internet to NetBIOS port (137)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-003

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-003

***Title: [AWS Security Groups allow internet traffic from internet to NetBIOS port (138)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-004

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-004

***Title: [AWS Security Groups allow internet traffic from internet to SQLServer port (1433)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-005

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-005

***Title: [AWS Security Groups allow internet traffic from internet to SQLServer port (1434)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-006

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-006

***Title: [AWS Security Groups allow internet traffic from internet to FTP-Data port (20)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-007

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-007

***Title: [AWS Security Groups allow internet traffic from internet to FTP port (21)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-008

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-008

***Title: [AWS Security Groups allow internet traffic to SSH port (22)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-009

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-009

***Title: [AWS Security Groups allow internet traffic from internet to Telnet port (23)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-010

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-010

***Title: [AWS Security Groups allow internet traffic from internet to SMTP port (25)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-011

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-011

***Title: [AWS Security Groups allow internet traffic from internet to MYSQL port (3306)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-012

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-012

***Title: [AWS Security Groups allow internet traffic from internet to RDP port (3389)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-013

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-013

***Title: [AWS Security Groups allow internet traffic from internet to MSQL port (4333)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-014

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-014

***Title: [AWS Security Groups allow internet traffic from internet to CIFS port (445)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-015

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-015

***Title: [AWS Security Groups allow internet traffic from internet to DNS port (53)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-016

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-016

***Title: [AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-017

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-017

***Title: [AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-018

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-018

***Title: [AWS Security Groups allow internet traffic from internet to VNC Server port (5900)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-019

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-019

***Title: [AWS Default Security Group does not restrict all traffic]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-020

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-020

***Title: [AWS Security Groups with Inbound rule overly permissive to All Traffic]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-021

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-021

***Title: [AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-022

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-022

***Title: [Ensure AWS resources that support tags have Tags]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-023

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-023

***Title: [Ensure every Security Group rule contains a description]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-024

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-024

***Title: [AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-025

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-025

***Title: [AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-026

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-026

***Title: [AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-027

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-027

***Title: [AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-028

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-028

***Title: [AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-029

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-029

***Title: [AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-TRF-SG-034

***<font color="white">ID:</font>*** PR-AWS-TRF-SG-034

***Title: [Ensure EC2 instance that is not internet reachable with unrestricted access (0.0.0.0/0) other than HTTP/HTTPS port monitoring is enabled for EC2 instances]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-0028-RGX

***<font color="white">ID:</font>*** PR-AWS-0028-RGX

***Title: [There is a possibility that AWS secret access key has leaked]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-0029-RGX

***<font color="white">ID:</font>*** PR-AWS-0029-RGX

***Title: [There is a possibility that AWS account ID has leaked]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-0030-RGX

***<font color="white">ID:</font>*** PR-AWS-0030-RGX

***Title: [There is a possibility that Aws access key id is exposed]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-0031-RGX

***<font color="white">ID:</font>*** PR-AWS-0031-RGX

***Title: [Ensure no hardcoded password set in the template]***

----------------------------------------------------

***<font color="white">Master Test ID:</font>*** PR-AWS-0032-RGX

***<font color="white">ID:</font>*** PR-AWS-0032-RGX

***Title: [There is a possibility that a value might contains a secret string or password]***

----------------------------------------------------


[API Gateway should have API Endpoint type as private and not exposed to internet]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-AG-001.md
[AWS ACM Certificate with wildcard domain name]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ACM-001.md
[AWS API Gateway REST API is not configured with AWS Web Application Firewall v2 (AWS WAFv2)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-AG-008.md
[AWS API Gateway endpoints without client certificate authentication]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-AG-007.md
[AWS API gateway request authorization is not set]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-AG-003.md
[AWS API gateway request parameter is not validated]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-AG-002.md
[AWS Access logging not enabled on S3 buckets]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-001.md
[AWS Application Load Balancer (ALB) listener that allow connection requests over HTTP]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-011.md
[AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ACM-002.md
[AWS CloudFormation stack configured without SNS topic]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CFR-001.md
[AWS CloudFront Distributions with Field-Level Encryption not enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CF-001.md
[AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CF-002.md
[AWS CloudFront distribution with access logging disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CF-003.md
[AWS CloudFront origin protocol policy does not enforce HTTPS-only]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CF-004.md
[AWS CloudFront viewer protocol policy is not configured with HTTPS]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CF-005.md
[AWS CloudFront web distribution that allow TLS versions 1.0 or lower]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CF-006.md
[AWS CloudFront web distribution with AWS Web Application Firewall (AWS WAF) service disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CF-007.md
[AWS CloudFront web distribution with default SSL certificate]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CF-008.md
[AWS CloudFront web distribution with geo restriction disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CF-009.md
[AWS CloudTrail log validation is not enabled in all regions]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CT-002.md
[AWS Cloudfront Distribution with S3 have Origin Access set to disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CF-010.md
[AWS CodeDeploy application compute platform must be ECS or Lambda]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CD-001.md
[AWS Config must record all possible resources]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CFG-001.md
[AWS Customer Master Key (CMK) rotation is not enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-KMS-001.md
[AWS Default Security Group does not restrict all traffic]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-019.md
[AWS DynamoDB encrypted using AWS owned CMK instead of AWS managed CMK]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-DD-001.md
[AWS EBS volumes are not encrypted]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EBS-001.md
[AWS EC2 Instance IAM Role not enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC2-001.md
[AWS EC2 instance is not configured with VPC]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC2-002.md
[AWS EC2 instances with Public IP and associated with Security Groups have Internet Access]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC2-003.md
[AWS ECS - Ensure Fargate task definition logging is enabled.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-015.md
[AWS ECS Task Definition readonlyRootFilesystem Not Enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-004.md
[AWS ECS task definition elevated privileges enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-001.md
[AWS ECS task definition logging not enabled.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-006.md
[AWS ECS task definition resource limits not set.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-005.md
[AWS ECS/ Fargate task definition root user found]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-003.md
[AWS ECS/Fargate task definition execution IAM Role not found]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-002.md
[AWS EKS cluster control plane assigned multiple security groups]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EKS-001.md
[AWS EKS unsupported Master node version.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EKS-002.md
[AWS EMR cluster is not configured with CSE CMK for data at rest encryption (Amazon S3 with EMRFS)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EMR-003.md
[AWS EMR cluster is not configured with Kerberos Authentication]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EMR-002.md
[AWS EMR cluster is not configured with security configuration]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EMR-001.md
[AWS EMR cluster is not enabled with data encryption at rest]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EMR-006.md
[AWS EMR cluster is not enabled with data encryption in transit]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EMR-007.md
[AWS EMR cluster is not enabled with local disk encryption using CMK]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EMR-004.md
[AWS ElastiCache Redis cluster with Multi-AZ Automatic Failover feature set to disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC-001.md
[AWS ElastiCache Redis cluster with Redis AUTH feature disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC-002.md
[AWS ElastiCache Redis cluster with encryption for data at rest disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC-003.md
[AWS ElastiCache Redis cluster with in-transit encryption disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC-004.md
[AWS Elastic File System (EFS) not encrypted using Customer Managed Key]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EFS-001.md
[AWS Elastic File System (EFS) with encryption for data at rest disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EFS-002.md
[AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-001.md
[AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-002.md
[AWS Elastic Load Balancer (Classic) with access log disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-003.md
[AWS Elastic Load Balancer (Classic) with connection draining disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-004.md
[AWS Elastic Load Balancer (Classic) with cross-zone load balancing disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-005.md
[AWS Elastic Load Balancer (ELB) not in use]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-008.md
[AWS Elastic Load Balancer V2 (ELBV2) with listener TLS/SSL disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-012.md
[AWS Elastic Load Balancer v2 (ELBv2) Application Load Balancer (ALB) with access log disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-009.md
[AWS Elastic Load Balancer with listener TLS/SSL disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-010.md
[AWS ElasticSearch cluster not in a VPC]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ES-001.md
[AWS Elasticsearch domain Encryption for data at rest is disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ES-002.md
[AWS Elasticsearch domain has Dedicated master set to disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ES-003.md
[AWS Elasticsearch domain has Index slow logs set to disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ES-004.md
[AWS Elasticsearch domain has Search slow logs set to disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ES-005.md
[AWS Elasticsearch domain has Zone Awareness set to disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ES-006.md
[AWS Elasticsearch domain is not configured with HTTPS]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ES-008.md
[AWS IAM policy allows assume role permission across all services]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-005.md
[AWS IAM policy allows full administrative privileges]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-007.md
[AWS IAM policy is overly permissive to all traffic via condition clause]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-006.md
[AWS KMS Customer Managed Key not in use]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-KMS-002.md
[AWS Kinesis streams are not encrypted using Server Side Encryption]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-KNS-001.md
[AWS Kinesis streams encryption using default KMS keys instead of Customer's Managed Master Keys]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-KNS-002.md
[AWS Lambda Environment Variables not encrypted at-rest using CMK]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-LMD-001.md
[AWS Lambda Function is not assigned to access within VPC]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-LMD-002.md
[AWS Lambda functions with tracing not enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-LMD-003.md
[AWS MQ is publicly accessible]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-MQ-001.md
[AWS Network ACLs with Inbound rule to allow All ICMP IPv4]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-NACL-001.md
[AWS Network ACLs with Inbound rule to allow All ICMP IPv6]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-NACL-002.md
[AWS Network ACLs with Inbound rule to allow All Traffic]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-NACL-003.md
[AWS Network ACLs with Outbound rule to allow All ICMP IPv4]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-NACL-004.md
[AWS Network ACLs with Outbound rule to allow All ICMP IPv6]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-NACL-005.md
[AWS Network ACLs with Outbound rule to allow All Traffic]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-NACL-006.md
[AWS RDS DB cluster encryption is disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-001.md
[AWS RDS Global DB cluster encryption is disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-015.md
[AWS RDS cluster retention policy less than 7 days]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-012.md
[AWS RDS database instance is publicly accessible]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-002.md
[AWS RDS database not encrypted using Customer Managed Key]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-003.md
[AWS RDS event subscription disabled for DB instance]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-004.md
[AWS RDS event subscription disabled for DB security groups]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-005.md
[AWS RDS instance is not encrypted]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-006.md
[AWS RDS instance with Multi-Availability Zone disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-007.md
[AWS RDS instance with copy tags to snapshots disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-008.md
[AWS RDS instance without Automatic Backup setting]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-009.md
[AWS RDS minor upgrades not enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-010.md
[AWS RDS retention policy less than 7 days]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-011.md
[AWS Redshift Cluster not encrypted using Customer Managed Key]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RSH-001.md
[AWS Redshift clusters should not be publicly accessible]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RSH-002.md
[AWS Redshift database does not have audit logging enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RSH-007.md
[AWS Redshift does not have require_ssl configured]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RSH-003.md
[AWS Redshift instances are not encrypted]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RSH-004.md
[AWS S3 Bucket has Global DELETE Permissions enabled via bucket policy]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-002.md
[AWS S3 Bucket has Global GET Permissions enabled via bucket policy]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-003.md
[AWS S3 Bucket has Global LIST Permissions enabled via bucket policy]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-004.md
[AWS S3 Bucket has Global PUT Permissions enabled via bucket policy]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-005.md
[AWS S3 CloudTrail buckets for which access logging is disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-006.md
[AWS S3 Object Versioning is disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-007.md
[AWS S3 bucket has global view ACL permissions enabled.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-008.md
[AWS S3 bucket not configured with secure data transport policy]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-009.md
[AWS S3 buckets are accessible to any authenticated user.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-010.md
[AWS S3 buckets are accessible to public]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-011.md
[AWS S3 buckets do not have server side encryption.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-012.md
[AWS SNS subscription is not configured with HTTPS]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SNS-001.md
[AWS SNS topic encrypted using default KMS key instead of CMK]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SNS-002.md
[AWS SNS topic with server-side encryption disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SNS-003.md
[AWS SQS does not have a dead letter queue configured]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SQS-001.md
[AWS SQS queue encryption using default KMS key instead of CMK]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SQS-002.md
[AWS SQS server side encryption not enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SQS-003.md
[AWS SageMaker notebook instance configured with direct internet access feature]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SGM-003.md
[AWS SageMaker notebook instance is not placed in VPC]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SGM-004.md
[AWS SageMaker notebook instance not configured with data encryption at rest using KMS key]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SGM-001.md
[AWS SageMaker notebook instance with root access enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SGM-002.md
[AWS Security Groups allow internet traffic from internet to CIFS port (445)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-014.md
[AWS Security Groups allow internet traffic from internet to DNS port (53)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-015.md
[AWS Security Groups allow internet traffic from internet to ElasticSearch Protocol Port (9300)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-024.md
[AWS Security Groups allow internet traffic from internet to FTP port (21)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-007.md
[AWS Security Groups allow internet traffic from internet to FTP-Data port (20)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-006.md
[AWS Security Groups allow internet traffic from internet to Kibana Protocol Port (5601)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-025.md
[AWS Security Groups allow internet traffic from internet to MSQL port (4333)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-013.md
[AWS Security Groups allow internet traffic from internet to MYSQL port (3306)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-011.md
[AWS Security Groups allow internet traffic from internet to Microsoft Operations Manager Protocol Port (1270)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-029.md
[AWS Security Groups allow internet traffic from internet to NetBIOS port (137)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-002.md
[AWS Security Groups allow internet traffic from internet to NetBIOS port (138)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-003.md
[AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-016.md
[AWS Security Groups allow internet traffic from internet to RDP port (3389)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-012.md
[AWS Security Groups allow internet traffic from internet to SMTP port (25)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-010.md
[AWS Security Groups allow internet traffic from internet to SQLServer port (1433)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-004.md
[AWS Security Groups allow internet traffic from internet to SQLServer port (1434)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-005.md
[AWS Security Groups allow internet traffic from internet to Telnet port (23)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-009.md
[AWS Security Groups allow internet traffic from internet to Trivial File Transfer Protocol Port (69)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-021.md
[AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-017.md
[AWS Security Groups allow internet traffic from internet to VNC Server port (5900)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-018.md
[AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5985)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-028.md
[AWS Security Groups allow internet traffic from internet to WinRM 2.0 (Microsoft Windows Remote Management) Protocol Port (5986)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-027.md
[AWS Security Groups allow internet traffic from internet to Windows RPC port (135)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-001.md
[AWS Security Groups allow internet traffic from internet to etcd-client Protocol Port (2379)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-026.md
[AWS Security Groups allow internet traffic to SSH port (22)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-008.md
[AWS Security Groups with Inbound rule overly permissive to All Traffic]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-020.md
[AWS VPC subnets should not allow automatic public IP assignment]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-VPC-001.md
[CloudTrail trail is not integrated with CloudWatch Log]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CT-004.md
[Code Pipeline Encryption at rest with customer-managed key (CMK) should be enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CP-001.md
[Dynamo DB kinesis specification property should not be null]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-DD-003.md
[Elasticsearch Domain should not have Encrytion using AWS Managed Keys]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ES-009.md
[Enable AWS Inspector to detect Vulnerability]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-INS-001.md
[Enable Enhanced scan type for AWS ECR registry to detect vulnerability]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECR-005.md
[Enhanced monitoring for Amazon RDS instances is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-019.md
[Ensure 'default' value is not used on Security Group setting for Redis cache engines]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC-006.md
[Ensure API Gateway has tracing enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-AG-005.md
[Ensure API gateway methods are not publicly accessible]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-AG-006.md
[Ensure AWS API Gateway uses TLS 1.2 in transit]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-AG-009.md
[Ensure AWS CloudTrail is logging data events for S3 and Lambda.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CT-005.md
[Ensure AWS Config includes global resources types (IAM).]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CFG-004.md
[Ensure AWS DAX data is encrypted in transit]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-DAX-002.md
[Ensure AWS DocumentDB logging is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-DDB-002.md
[Ensure AWS EC2 EBS and Network components' deletion protection is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC2-006.md
[Ensure AWS ECR Repository is not publicly accessible]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECR-004.md
[Ensure AWS EKS cluster has secrets encryption enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EKS-003.md
[Ensure AWS EKS control plane logging is enabled.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EKS-009.md
[Ensure AWS EKS only uses latest versions of Kubernetes.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EKS-006.md
[Ensure AWS Glue encrypt data at rest]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-GLUE-003.md
[Ensure AWS Glue security configuration encryption is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-GLUE-002.md
[Ensure AWS IAM policy do not have permission which may cause privilege escalation.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-027.md
[Ensure AWS IAM policy does not allows decryption actions on all KMS keys.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-041.md
[Ensure AWS IAM policy is not overly permissive to STS services.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-044.md
[Ensure AWS Lambda function is configured for a DLQ]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-LMD-005.md
[Ensure AWS Lambda function is configured for function-level concurrent execution limit]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-LMD-004.md
[Ensure AWS RDS Cluster has setup backup retention period of at least 30 days.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-028.md
[Ensure AWS RDS DB authentication is only enabled via IAM.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-027.md
[Ensure AWS RDS DB instance has deletion protection enabled.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-029.md
[Ensure AWS Redshift - Enhanced VPC routing must be enabled.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RSH-008.md
[Ensure AWS S3 bucket do not have policy that is overly permissive to VPC endpoints.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-025.md
[Ensure AWS S3 bucket policy is not overly permissive to any principal.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-023.md
[Ensure AWS SNS Topic is not publicly accessible through IAM policies.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-045.md
[Ensure AWS SNS topic do not have cross-account access.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SNS-008.md
[Ensure AWS SNS topic is not exposed to unauthorized access.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SNS-005.md
[Ensure AWS SNS topic policy is not overly permissive for publishing.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SNS-006.md
[Ensure AWS SNS topic policy is not overly permissive for subscription.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SNS-007.md
[Ensure AWS SQS queue access policy is not overly permissive.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SQS-006.md
[Ensure AWS SageMaker notebook instance IAM policy is not overly permissive to all traffic.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-046.md
[Ensure AWS Secrets Manager automatic rotation is enabled.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SM-003.md
[Ensure AWS VPC endpoint policy is not overly permissive.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-VPC-006.md
[Ensure AWS WorkSpaces do not use directory type Simple AD.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-WS-003.md
[Ensure AWS config is enabled in all regions]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CFG-002.md
[Ensure AWS resources that support tags have Tags]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-022.md
[Ensure AWS secret rotation period is per the GS standard (Ex: 30 days).]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SM-004.md
[Ensure ActiveMQ engine version is approved by GS.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-MQ-003.md
[Ensure Amazon MQ Broker logging is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-MQ-002.md
[Ensure Amazon MSK cluster has logging enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-MSK-005.md
[Ensure Amazon Machine Image (AMI) is not infected with mining malware.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC2-007.md
[Ensure AppSync is configured with AWS Web Application Firewall v2.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-APS-001.md
[Ensure Athena logging is enabled for athena workgroup.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ATH-002.md
[Ensure CloudFormation template is configured with stack policy.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CFR-002.md
[Ensure CloudWatch log groups are encrypted with KMS CMKs]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-LG-001.md
[Ensure CloudWatch log groups has retention days defined]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-LG-002.md
[Ensure Cloudformation rollback is disabled.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CFR-003.md
[Ensure Cluster level logging is enabled for EMR.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EMR-008.md
[Ensure CodeBuild project Artifact encryption is not disabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CB-001.md
[Ensure DAX is securely encrypted at rest]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-DAX-001.md
[Ensure DMS endpoints are supporting SSL configuration]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-DMS-001.md
[Ensure DMS replication instance is not publicly accessible]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-DMS-002.md
[Ensure DocDB ParameterGroup has TLS enable]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-DDB-003.md
[Ensure DocDB has audit logs enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-DDB-004.md
[Ensure DocumentDB cluster is encrypted at rest]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-DDB-001.md
[Ensure DynamoDB PITR is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-DD-002.md
[Ensure EBS volumes are encrypted using Customer Managed Key (CMK)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC2-010.md
[Ensure EBS volumes have encrypted launch configurations]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-AS-001.md
[Ensure EC2 Auto Scaling Group does not launch IMDSv1]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-AS-003.md
[Ensure EC2 instance that is not internet reachable with unrestricted access (0.0.0.0/0) other than HTTP/HTTPS port monitoring is enabled for EC2 instances]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-034.md
[Ensure ECR image scan on push is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECR-003.md
[Ensure ECR image tags are immutable]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECR-001.md
[Ensure ECR repositories are encrypted]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECR-002.md
[Ensure ECR resources are accessible only via private endpoint.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECR-006.md
[Ensure ECS Services and Task Set enable_execute_command property set to False]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-009.md
[Ensure EFS volumes in ECS task definitions have encryption in transit enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-007.md
[Ensure EKS cluster is configured with control plane security group attached to it.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EKS-007.md
[Ensure EMR cluster is not visible to all IAM users.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EMR-009.md
[Ensure Elastic Load Balancer v2 (ELBv2) SSL negotiation policy is not configured with weak ciphers.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-025.md
[Ensure ElasticSearch has a custom endpoint configured.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ES-010.md
[Ensure General and Audit logs are published to CloudWatch.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-MQ-005.md
[Ensure Glacier Backup policy is not publicly accessible]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-BKP-001.md
[Ensure Glue Data Catalog encryption is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-GLUE-001.md
[Ensure IAM groups contains at least one IAM user]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-008.md
[Ensure IAM policy is attached to group rather than user.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-042.md
[Ensure IAM policy is not overly permissive to Lambda service]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-012.md
[Ensure IAM policy is not overly permissive to all traffic for ecs.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-029.md
[Ensure IAM policy is not overly permissive to all traffic for elasticsearch.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-030.md
[Ensure IAM policy is not overly permissive to all traffic via condition clause.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-043.md
[Ensure Internet facing Classic ELB is not in use.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-022.md
[Ensure Internet facing ELBV2 is not in use.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-023.md
[Ensure Kubernetes secrets are encrypted using CMKs managed in AWS KMS]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EKS-004.md
[Ensure Lambda IAM policy is not overly permissive to all traffic]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-011.md
[Ensure LoadBalancer TargetGroup protocol values are limited to HTTPS]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-019.md
[Ensure LoadBalancer scheme is set to internal and not internet-facing]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-017.md
[Ensure MSK cluster is setup in GS VPC]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-MSK-004.md
[Ensure Neptune logging is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-NPT-001.md
[Ensure PGAudit is enabled on RDS Postgres instances]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-014.md
[Ensure QLDB ledger permissions mode is set to STANDARD]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-QLDB-001.md
[Ensure RDS DB instance has setup backup retention period of at least 30 days.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-030.md
[Ensure RDS cluster do not use a deprecated version of Aurora-PostgreSQL.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-022.md
[Ensure RDS cluster has IAM authentication enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-016.md
[Ensure RDS clusters and instances have deletion protection enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-013.md
[Ensure RDS dbcluster do not use a deprecated version of PostgreSQL.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-024.md
[Ensure RDS instace has IAM authentication enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-017.md
[Ensure RDS instances do not use a deprecated version of Aurora-PostgreSQL.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-021.md
[Ensure RDS instances do not use a deprecated version of PostgreSQL.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-023.md
[Ensure RabbitMQ engine version is approved by GS.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-MQ-004.md
[Ensure Redshift cluster allow version upgrade by default]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RSH-005.md
[Ensure Redshift database clusters are not using default master username.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RSH-011.md
[Ensure Redshift database clusters are not using default port(5439) for database connection.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RSH-012.md
[Ensure Redshift is not deployed outside of a VPC]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RSH-006.md
[Ensure Route53 DNS evaluateTargetHealth is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-R53-001.md
[Ensure S3 Bucket block_public_policy is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-021.md
[Ensure S3 Bucket has public access blocks]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-018.md
[Ensure S3 bucket RestrictPublicBucket is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-019.md
[Ensure S3 bucket cross-region replication is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-017.md
[Ensure S3 bucket has enabled lock configuration]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-016.md
[Ensure S3 bucket ignore_public_acls is enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-020.md
[Ensure S3 bucket is encrypted using KMS]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-015.md
[Ensure S3 hosted sites supported hardened CORS]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-014.md
[Ensure SNS Topic policy is not publicly accessible]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SNS-004.md
[Ensure SNS is only accessible via specific VPCe service.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SNS-009.md
[Ensure SNS topic is configured with secure data transport policy.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SNS-010.md
[Ensure SQS data is encrypted in Transit using SSL/TLS.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SQS-008.md
[Ensure SQS is only accessible via specific VPCe service.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SQS-007.md
[Ensure SQS policy documents do not allow all actions]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SQS-005.md
[Ensure SQS queue policy is not publicly accessible]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SQS-004.md
[Ensure Slow Logs feature is enabled for ElasticSearch cluster.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ES-011.md
[Ensure Termination protection is enabled for instances in the cluster for EMR.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EMR-010.md
[Ensure Timestream database is encrypted using KMS]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-TS-001.md
[Ensure Transfer Server is not use FTP protocol.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-TRF-002.md
[Ensure VPC endpoint service is configured for manual acceptance]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-VPC-003.md
[Ensure all EIP addresses allocated to a VPC are attached related EC2 instances]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-VPC-002.md
[Ensure all load balancers created are application load balancers]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-018.md
[Ensure an IAM policy is defined with the stack.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CFR-004.md
[Ensure auto scaling groups associated with a load balancer use elastic load balancing health checks]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-AS-002.md
[Ensure automated backups are enabled for Redshift cluster.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RSH-013.md
[Ensure capabilities in stacks do not have * in it.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CFR-005.md
[Ensure client authentication is enabled with TLS (mutual TLS authentication)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-MSK-003.md
[Ensure container insights are enabled on ECS cluster]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-008.md
[Ensure content encoding is enabled for API Gateway.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-AG-010.md
[Ensure data is Encrypted in transit (TLS)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-MSK-002.md
[Ensure detailed monitoring is enabled for EC2 instances]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC2-005.md
[Ensure enhanaced monitoring for AWS MSK is not set to default.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-MSK-006.md
[Ensure every Security Group rule contains a description]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-023.md
[Ensure fine-grained access control is enabled during domain creation in ElasticSearch.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ES-013.md
[Ensure in AWS ElastiCache, automatic backups is enabled for Redis cluster.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC-007.md
[Ensure lifecycle policy is enabled for ECR image repositories.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECR-007.md
[Ensure no IAM policy has a resource specified in the following format:'arn:aws:*:*']: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-004.md
[Ensure no KMS key policy contain wildcard (*) principal]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-KMS-003.md
[Ensure no hardcoded password set in the template]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-0031-RGX.md
[Ensure no wildcards are specified in IAM policy with 'Action' section]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-002.md
[Ensure no wildcards are specified in IAM policy with 'Resource' section]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-001.md
[Ensure no wildcards are specified in IAM trust-relationship policy with 'Principal' section]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-003.md
[Ensure node-to-node encryption is enabled on each ElasticSearch Domain]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ES-007.md
[Ensure one of subnets or subnet_mapping is defined for loadbalancer]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-016.md
[Ensure only private access for Amazon EKS cluster's Kubernetes API is enabled.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EKS-008.md
[Ensure public access is disabled for AWS MSK.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-MSK-007.md
[Ensure respective logs of Amazon RDS instance are enabled]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-RDS-018.md
[Ensure that API Gateway has enabled access logging]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-AG-004.md
[Ensure that AWS Elastic Load Balancer v2 (ELBv2) has deletion protection feature enabled.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-020.md
[Ensure that AWS ensure Gateway Load Balancer (GWLB) is not being used.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-021.md
[Ensure that Application Load Balancer drops HTTP headers]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-013.md
[Ensure that CodeBuild projects are encrypted using CMK]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-CB-002.md
[Ensure that EC2 instace is EBS Optimized]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC2-004.md
[Ensure that ECS Service and Task Set network configuration disallows the assignment of public IPs]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-010.md
[Ensure that ECS Task Definition have their network mode property set to awsvpc]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-014.md
[Ensure that ECS services and Task Sets are launched as Fargate type]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-011.md
[Ensure that ElastiCache replication Group (Redis) are encrypted at rest with customer managed CMK key]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-EC-005.md
[Ensure that Secrets Manager secret is encrypted using KMS]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SM-001.md
[Ensure that Workspace root volumes is encrypted.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-WS-002.md
[Ensure that Workspace user volumes is encrypted]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-WS-001.md
[Ensure that a log driver has been configured for each ECS task definition.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-017.md
[Ensure that public facing ELB has WAF attached]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-024.md
[Ensure that the AWS EC2 instances don't have a risky set of permissions management access to minimize security risks.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-013.md
[Ensure that the AWS EC2 instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-016.md
[Ensure that the AWS ECR Repository resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-022.md
[Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of org write permissions to minimize security risks.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-017.md
[Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of permissions management access permissions to minimize security risks.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-015.md
[Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-014.md
[Ensure that the AWS Lambda Function resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-023.md
[Ensure that the AWS S3 bucket resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-024.md
[Ensure that the AWS SQS Queue resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-025.md
[Ensure that the AWS Secret Manager Secret resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-026.md
[Ensure that the AWS policies don't have '*' in the resource section of the policy statement of ec2.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-019.md
[Ensure that the AWS policies don't have '*' in the resource section of the policy statement of ecs task definition.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-021.md
[Ensure that the AWS policies don't have '*' in the resource section of the policy statement of elastic bean stalk.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-018.md
[Ensure that the AWS policies don't have '*' in the resource section of the policy statement of lambda function.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-IAM-020.md
[Ensure that the CertificateManager certificates reference only Private ACMPCA certificate authorities]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ACM-003.md
[Ensure the ELBv2 ListenerCertificate listener_arn value is defined]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-014.md
[Ensure the Load Balancer Listener SSLPolicy is set to at least one value from approved policies]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ELB-015.md
[Ensure there are no undefined ECS task definition empty roles for ECS.]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-016.md
[Ensure to enable enforce_workgroup_configuration for athena workgroup]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ATH-001.md
[Instance is communicating with ports known to mine Bitcoin]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-031.md
[Instance is communicating with ports known to mine Ethereum]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-032.md
[JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has write access to the Log4j configuration]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-WAF-001.md
[Publicly exposed DB Ports]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-SG-030.md
[S3 buckets with configurations set to host websites]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-S3-013.md
[There is a possibility that AWS account ID has leaked]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-0029-RGX.md
[There is a possibility that AWS secret access key has leaked]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-0028-RGX.md
[There is a possibility that Aws access key id is exposed]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-0030-RGX.md
[There is a possibility that a value might contains a secret string or password]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-0032-RGX.md
[Unrestricted Inbound Traffic on Remote Server Administration Ports]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-NACL-007.md
[Use KMS Customer Master Keys for AWS MSK Clusters]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-MSK-001.md
[VPC configurations on ECS Services must use either vended security groups]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-013.md
[Value(s) of subnets attached to aws ecs service subnets are vended]: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/policies/aws/terraform/all/PR-AWS-TRF-ECS-012.md
