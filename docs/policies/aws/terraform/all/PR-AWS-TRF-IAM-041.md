



# Title: Ensure AWS IAM policy does not allows decryption actions on all KMS keys.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-IAM-041

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([iam.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-IAM-041|
|eval|data.rule.not_allow_decryption_actions_on_all_kms_keys|
|message|data.rule.not_allow_decryption_actions_on_all_kms_keys_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_IAM_041.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It identifies IAM policies that allow decryption actions on all KMS keys. Instead of granting permissions for all keys, determine the minimum set of keys that users need to access encrypted data. You should grant to identities only the kms:Decrypt or kms:ReEncryptFrom permissions and only for the keys that are required to perform a task. By adopting the principle of least privilege, you can reduce the risk of unintended disclosure of your data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['AWS Well-Architected Framework', 'AWS Well-Architected Framework-Identity and Access Management']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_iam_policy']


[iam.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/iam.rego
