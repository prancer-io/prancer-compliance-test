



# Master Test ID: PR-AWS-CLD-IAM-027


Master Snapshot Id: ['TEST_IAM_02']

type: rego

rule: [file(iam.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-IAM-027|
|eval: |data.rule.iam_policy_permission_may_cause_privilege_escalation|
|message: |data.rule.iam_policy_permission_may_cause_privilege_escalation_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_role' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_IAM_027.py|


severity: Low

title: Ensure AWS IAM policy do not have permission which may cause privilege escalation.

description: It identifies AWS IAM Policy which have permission that may cause privilege escalation. AWS IAM policy having weak permissions could be exploited by an attacker to elevate privileges. It is recommended to follow the principle of least privileges ensuring that AWS IAM policy does not have these sensitive permissions.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'AWS Well-Architected Framework-Identity and Access Management', 'LGPD', 'CSA CCM', "CyberSecurity Law of the People's Republic of China", 'CMMC', 'GDPR', 'HITRUST', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST CSF', 'RMiT', 'SOC 2']|
|service: |['iam']|



[file(iam.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
