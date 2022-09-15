



# Master Test ID: PR-AWS-CLD-EMR-009


***<font color="white">Master Snapshot Id:</font>*** ['TEST_EMR']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([emr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EMR-009|
|eval|data.rule.emr_cluster_not_visible_to_all_iam_users|
|message|data.rule.emr_cluster_not_visible_to_all_iam_users_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/emr.html#EMR.Client.describe_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EMR_009.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure EMR cluster is not visible to all IAM users.

***<font color="white">Description:</font>*** It checks if the EMR cluster created has a wide visibility to all IAM users. When true, IAM principals in the AWS account can perform EMR cluster actions that their IAM policies allow.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'CCPA', 'HITRUST', 'LGPD', 'MAS TRM', 'PCI-DSS', 'NIST 800', 'NIST SP', 'NIST CSF']|
|service|['emr']|



[emr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/emr.rego
