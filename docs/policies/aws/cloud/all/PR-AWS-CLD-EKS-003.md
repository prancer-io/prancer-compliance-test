



# Master Test ID: PR-AWS-CLD-EKS-003


Master Snapshot Id: ['TEST_EKS']

type: rego

rule: [file(eks.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-EKS-003|
|eval: |data.rule.eks_encryption_resources|
|message: |data.rule.eks_encryption_resources_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-encryptionconfig.html#cfn-eks-cluster-encryptionconfig-resources' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_EKS_003.py|


severity: High

title: Ensure AWS EKS cluster has secrets encryption enabled

description: Secrets in Kubernetes enables managing sensitive information such as passwords and API keys using Kubernetes-native APIs. When creating a secret resource the Kubernetes API server stores it in etcd in a base64 encoded form.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['HIPAA', 'Best Practice']|
|service: |['eks']|



[file(eks.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/eks.rego
