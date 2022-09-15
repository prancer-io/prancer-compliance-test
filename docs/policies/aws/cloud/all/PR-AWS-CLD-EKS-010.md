



# Master Test ID: PR-AWS-CLD-EKS-010


***<font color="white">Master Snapshot Id:</font>*** ['TEST_EKS', 'TEST_KMS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([eks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-EKS-010|
|eval|data.rule.eks_gs_managed_key|
|message|data.rule.eks_gs_managed_key_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks.html#EKS.Client.describe_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_EKS_010.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure GS-managed encryption key is used for AWS EKS.

***<font color="white">Description:</font>*** It checks if encryption is enabled with a GS managed KMS CMK during the EKS cluster setup.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'CCPA', 'CMMC', 'CSA CCM', 'HITRUST', 'ISO/IEC 27002', 'ISO/IEC 27017', 'ISO/IEC 27018', 'LGPD', 'MAS TRM', 'MLPS', 'NIST 800', 'NIST CSF', 'NIST SP', 'PCI-DSS', 'PIPEDA', 'RMiT']|
|service|['eks', 'kms']|



[eks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/eks.rego
