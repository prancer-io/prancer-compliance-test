



# Title: AWS ECS task definition elevated privileges enabled


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-ECS-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([ecs.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-ECS-001|
|eval|data.rule.ecs_task_evelated|
|message|data.rule.ecs_task_evelated_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_task_definition' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_ECS_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure your ECS containers are not given elevated privileges on the host container instance. When the privileged parameter is true, the container is given elevated privileges on the host container instance (similar to the root user). This policy checks the security configuration of your task definition and alerts if elevated privileges are enabled. Note: This parameter is not supported for Windows containers or tasks using the Fargate launch type.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'AWS Foundational Security Best Practices standard', 'AWS Foundational Security Best Practices standard-Secure access management', 'Brazilian Data Protection Law (LGPD)-Article 46', 'Brazilian Data Protection Law (LGPD)-Article 6', 'CCPA', 'CCPA 2018-1798.150(a)(1)', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-DSP-17', 'CSA CCM v.4.0.1-IAM-04', 'CSA CCM v.4.0.1-IAM-05', 'CSA CCM v.4.0.1-IAM-09', 'CSA CCM v.4.0.1-IAM-16', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 43", "CyberSecurity Law of the People's Republic of China-Article 44", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AC.2.007', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.c', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-18.1.4', 'ISO/IEC 27002:2013-6.1.2', 'ISO/IEC 27002:2013-9.1.1', 'ISO/IEC 27002:2013-9.1.2', 'ISO/IEC 27002:2013-9.2.3', 'ISO/IEC 27002:2013-9.2.5', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-9.2.3', 'ISO/IEC 27017:2015-9.2.5', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-9.2.3', 'ISO/IEC 27018:2019-9.2.5', 'LGPD', 'MAS TRM', 'MAS TRM 2021-9.1.1', 'MLPS', 'MLPS 2.0-8.1.10.6', 'NIST 800', 'NIST 800-53 Rev 5-Least Privilege', 'NIST 800-53 Rev4-AC-6', 'NIST CSF', 'NIST CSF-PR.AC-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.5', 'NIST SP 800-172-3.1.2e', 'PCI DSS v3.2.1-7.1', 'PCI DSS v3.2.1-7.1.2', 'PCI-DSS', 'PIPEDA', 'PIPEDA-4.7.3', 'RMiT', 'Risk Management in Technology (RMiT)-10.55']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_ecs_task_definition']


[ecs.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/ecs.rego
