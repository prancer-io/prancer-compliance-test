



# Master Test ID: PR-AWS-CLD-IAM-022


Master Snapshot Id: ['TEST_IAM_02']

type: rego

rule: [file(iam.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-IAM-022|
|eval: |data.rule.ecr_repository_is_publicly_accessible_through_iam_policies|
|message: |data.rule.ecr_repository_is_publicly_accessible_through_iam_policies_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_IAM_022.py|


severity: High

title: Ensure that the AWS ECR Repository resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.

description: It identifies the AWS ECR Repository resources which are publicly accessible through IAM policies. Ensure that the AWS ECR Repository resources provisioned in your AWS account are not publicly accessible from the Internet to avoid sensitive data exposure and minimize security risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'AWS Well-Architected Framework-Identity and Access Management', 'LGPD', 'CSA CCM', "CyberSecurity Law of the People's Republic of China", 'CMMC', 'GDPR', 'HITRUST', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST CSF', 'RMiT', 'SOC 2']|
|service: |['iam']|



[file(iam.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
