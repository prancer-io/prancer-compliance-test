



# Title: Ensure IAM policy is not overly permissive to Lambda service


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-IAM-012

***<font color="white">Master Snapshot Id:</font>*** ['TEST_IAM_01']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-IAM-012|
|eval|data.rule.iam_policy_not_overly_permissive_to_lambda_service|
|message|data.rule.iam_policy_not_overly_permissive_to_lambda_service_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_policy_versions' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_IAM_012.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Ensure the principle of least privileges by ensuring that only restricted Lambda services for restricted resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'AWS Well-Architected Framework-Identity and Access Management', 'LGPD', 'CSA CCM', "CyberSecurity Law of the People's Republic of China", 'CMMC', 'GDPR', 'HITRUST', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST CSF', 'RMiT', 'SOC 2']|
|service|['iam']|



[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/iam.rego
