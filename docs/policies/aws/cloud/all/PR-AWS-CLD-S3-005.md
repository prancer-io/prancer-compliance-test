



# Master Test ID: PR-AWS-CLD-S3-005


Master Snapshot Id: ['TEST_CT_01']

type: rego

rule: [file(storage.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-S3-005|
|eval: |data.rule.s3_acl_put|
|message: |data.rule.s3_acl_put_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_S3_005.py|


severity: Low

title: AWS S3 Bucket has Global put Permissions enabled via bucket policy

description: This policy identifies the S3 Bucket(s) which will allow any unauthenticated user to PUT objects into a bucket. These permissions permit anyone, malicious or not, to PUT objects into your S3 bucket if they can guess the namespace. Since the S3 service does not protect the namespace other than with ACLs and Bucket Policy, you risk compromise of critical data by leaving this open.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['CSA-CCM', 'PCI DSS', 'NIST 800', 'GDPR']|
|service: |['cloud']|



[file(storage.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
