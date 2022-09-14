



# Master Test ID: PR-AWS-CLD-IAM-012


Master Snapshot Id: ['TEST_IAM_01']

type: rego

rule: [file(iam.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-IAM-012|
|eval: |data.rule.iam_policy_not_overly_permissive_to_lambda_service|
|message: |data.rule.iam_policy_not_overly_permissive_to_lambda_service_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_policy_versions' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_IAM_012.py|


severity: Low

title: Ensure IAM policy is not overly permissive to Lambda service

description: Ensure the principle of least privileges by ensuring that only restricted Lambda services for restricted resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'AWS Well-Architected Framework-Identity and Access Management', 'LGPD', 'CSA CCM', "CyberSecurity Law of the People's Republic of China", 'CMMC', 'GDPR', 'HITRUST', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST CSF', 'RMiT', 'SOC 2']|
|service: |['iam']|



[file(iam.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
