



# Master Test ID: PR-AWS-CLD-S3-004


Master Snapshot Id: ['TEST_S3']

type: rego

rule: [file(storage.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-S3-004|
|eval: |data.rule.s3_acl_list|
|message: |data.rule.s3_acl_list_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_S3_004.py|


severity: Medium

title: AWS S3 Bucket has Global list Permissions enabled via bucket policy

description: This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to LIST objects from a bucket. These permissions permit anyone, malicious or not, to LIST objects from your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk loss or compromise of critical data by leaving this open.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['CSA CCM', 'GDPR', 'HITRUST', 'NIST 800', 'PCI DSS', 'SOC 2']|
|service: |['cloud']|



[file(storage.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
