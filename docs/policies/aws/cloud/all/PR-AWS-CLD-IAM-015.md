



# Master Test ID: PR-AWS-CLD-IAM-015


Master Snapshot Id: ['TEST_IAM_02']

type: rego

rule: [file(iam.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-IAM-015|
|eval: |data.rule.lambda_function_with_iam_permissions_management_access|
|message: |data.rule.lambda_function_with_iam_permissions_management_access_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_IAM_015.py|


severity: High

title: Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of permissions management access permissions to minimize security risks.

description: This policy identifies IAM permissions management access permissions that are defined as risky permissions. Ensure that the AWS Lambda Function instances provisioned in your AWS account don't have a risky set of permissions management access permissions to minimize security risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'AWS Well-Architected Framework-Identity and Access Management', 'LGPD', 'CSA CCM', "CyberSecurity Law of the People's Republic of China", 'CMMC', 'GDPR', 'HITRUST', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST CSF', 'RMiT', 'SOC 2']|
|service: |['iam']|



[file(iam.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
