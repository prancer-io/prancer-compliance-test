



# Master Test ID: PR-AWS-CLD-IAM-016


***<font color="white">Master Snapshot Id:</font>*** ['TEST_IAM_02']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-IAM-016|
|eval|data.rule.ec2_instance_with_iam_write_access|
|message|data.rule.ec2_instance_with_iam_write_access_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_IAM_016.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Ensure that the AWS EC2 instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.

***<font color="white">Description:</font>*** This policy identifies IAM write permissions that are defined as risky permissions. Ensure that the AWS EC2 instances provisioned in your AWS account don't have a risky set of write permissions to minimize security risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'AWS Well-Architected Framework-Identity and Access Management', 'LGPD', 'CSA CCM', "CyberSecurity Law of the People's Republic of China", 'CMMC', 'GDPR', 'HITRUST', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST CSF', 'RMiT', 'SOC 2']|
|service|['iam']|



[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
