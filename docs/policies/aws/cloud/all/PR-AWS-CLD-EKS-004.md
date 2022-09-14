



# Master Test ID: PR-AWS-CLD-EKS-004


Master Snapshot Id: ['TEST_EKS']

type: rego

rule: [file(eks.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-EKS-004|
|eval: |data.rule.eks_encryption_kms|
|message: |data.rule.eks_encryption_kms_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-encryptionconfig.html#cfn-eks-cluster-encryptionconfig-provider' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_EKS_004.py|


severity: Low

title: Ensure Kubernetes secrets are encrypted using CMKs managed in AWS KMS

description: Application-layer Secrets Encryption provides an additional layer of security for sensitive data, such as user defined Secrets and Secrets required for the operation of the cluster, such as service account keys, which are all stored in etcd. Using this functionality, you can use a key, that you manage in AWS KMS, to encrypt data at the application layer  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['eks']|



[file(eks.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/eks.rego
