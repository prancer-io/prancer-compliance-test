



# Title: AWS MQ is publicly accessible


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-MQ-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-MQ-001|
|eval|data.rule.mq_publicly_accessible|
|message|data.rule.mq_publicly_accessible_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/mq_broker' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_MQ_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies the AWS MQ brokers which are publicly accessible. It is advisable to use MQ brokers privately only from within your AWS Virtual Private Cloud (VPC). Ensure that the AWS MQ brokers provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SC.3.183', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-SI.2.216', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.c', 'HITRUST v.9.4.2-Control Reference:09.m', 'LGPD', 'MAS TRM', 'MAS TRM 2021-11.1.5', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.22', 'NIST SP 800-172-3.14.3e', 'PCI DSS v3.2.1-1.3', 'PCI DSS v3.2.1-7.1', 'PCI-DSS', 'RMiT', 'Risk Management in Technology (RMiT)-10.55']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_mq_broker']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
