



# Title: Ensure IAM policy is not overly permissive to Lambda service


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-IAM-012

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-IAM-012|
|eval|data.rule.iam_policy_not_overly_permissive_to_lambda_service|
|message|data.rule.iam_policy_not_overly_permissive_to_lambda_service_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_IAM_012.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Ensure the principle of least privileges by ensuring that only restricted Lambda services for restricted resources.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'AWS Well-Architected Framework-Identity and Access Management', 'LGPD', 'CSA CCM', "CyberSecurity Law of the People's Republic of China", 'CMMC', 'GDPR', 'HITRUST', 'MAS TRM', 'MITRE ATT&CK', 'MLPS', 'NIST 800', 'NIST CSF', 'RMiT', 'SOC 2']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_iam_policy']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego
