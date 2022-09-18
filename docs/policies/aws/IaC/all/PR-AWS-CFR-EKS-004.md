



# Title: Ensure Kubernetes secrets are encrypted using CMKs managed in AWS KMS


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-EKS-004

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([eks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-EKS-004|
|eval|data.rule.eks_encryption_kms|
|message|data.rule.eks_encryption_kms_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-encryptionconfig.html#cfn-eks-cluster-encryptionconfig-provider' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_EKS_004.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Application-layer Secrets Encryption provides an additional layer of security for sensitive data, such as user defined Secrets and Secrets required for the operation of the cluster, such as service account keys, which are all stored in etcd. Using this functionality, you can use a key, that you manage in AWS KMS, to encrypt data at the application layer  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::eks::cluster']


[eks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/eks.rego
