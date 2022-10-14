



# Title: Ensure AWS IAM policy do not have permission which may cause privilege escalation.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-IAM-027

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-IAM-027|
|eval|data.rule.iam_policy_permission_may_cause_privilege_escalation|
|message|data.rule.iam_policy_permission_may_cause_privilege_escalation_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_IAM_027.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It identifies AWS IAM Policy which have permission that may cause privilege escalation. AWS IAM policy having weak permissions could be exploited by an attacker to elevate privileges. It is recommended to follow the principle of least privileges ensuring that AWS IAM policy does not have these sensitive permissions.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'AWS Well-Architected Framework-Identity and Access Management', 'LGPD', 'CSA CCM', "CyberSecurity Law of the People's Republic of China", 'CMMC', 'GDPR', 'HITRUST', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST CSF', 'RMiT', 'SOC 2']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::iam::policy']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/iam.rego
