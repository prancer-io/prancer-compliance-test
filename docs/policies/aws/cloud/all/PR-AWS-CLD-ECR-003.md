



# Master Test ID: PR-AWS-CLD-ECR-003


Master Snapshot Id: ['TEST_ECR']

type: rego

rule: [file(ecr.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-ECR-003|
|eval: |data.rule.ecr_scan|
|message: |data.rule.ecr_scan_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-imagescanningconfiguration.html#cfn-ecr-repository-imagescanningconfiguration-scanonpush' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_ECR_003.py|


severity: Medium

title: Ensure ECR image scan on push is enabled

description: Amazon ECR is a fully managed container registry used to store, manage and deploy container images. ECR Image Scanning assesses and identifies operating system vulnerabilities. Using automated image scans you can ensure container image vulnerabilities are found before getting pushed to production. ECR APIs notify if vulnerabilities were found when a scan completes  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |[]|
|service: |['ecr']|



[file(ecr.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/ecr.rego
