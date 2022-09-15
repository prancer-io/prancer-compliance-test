



# Master Test ID: PR-AWS-CLD-S3-025


***<font color="white">Master Snapshot Id:</font>*** ['TEST_S3']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-S3-025|
|eval|data.rule.policy_is_not_overly_permissive_to_vpc_endpoints|
|message|data.rule.policy_is_not_overly_permissive_to_vpc_endpoints_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.get_bucket_policy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_S3_025.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure AWS S3 bucket do not have policy that is overly permissive to VPC endpoints.

***<font color="white">Description:</font>*** It identifies S3 buckets that have the bucket policy overly permissive to VPC endpoints. It is recommended to follow the principle of least privileges ensuring that the VPC endpoints have only necessary permissions instead of full permission on S3 operations. NOTE: When applying the Amazon S3 bucket policies for VPC endpoints described in this section, you might block your access to the bucket without intending to do so. Bucket permissions that are intended to specifically limit bucket access to connections originating from your VPC endpoint can block all connections to the bucket. The policy might disable console access to the specified bucket because console requests don't originate from the specified VPC endpoint. So remediation should be done very carefully. For details refer https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies-vpc-endpoint.html  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['CSA CCM', 'CSA CCM v.4.0.1-DSP-17', 'CSA CCM v.4.0.1-IAM-04', 'CSA CCM v.4.0.1-IAM-05', 'CSA CCM v.4.0.1-IAM-09', 'CSA CCM v.4.0.1-IAM-16', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:01.c', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-18.1.3', 'ISO/IEC 27002:2013-18.1.4', 'ISO/IEC 27002:2013-6.1.2', 'ISO/IEC 27002:2013-9.1.1', 'ISO/IEC 27002:2013-9.1.2', 'ISO/IEC 27002:2013-9.2.3', 'ISO/IEC 27002:2013-9.2.5', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-9.2.3', 'ISO/IEC 27017:2015-9.2.5', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-9.2.3', 'ISO/IEC 27018:2019-9.2.5', 'MAS TRM', 'MAS TRM 2021-9.1.1', 'MITRE ATT&CK', 'MITRE ATT&CK v10.0-T1530 - Data from Cloud Storage Object', 'MITRE ATT&CK v8.2-T1530', 'NIST CSF', 'NIST CSF-PR.AC-4', 'NIST SP', 'NIST SP 800-171 Revision 2-3.1.5', 'NIST SP 800-172-3.13.4e', 'PCI DSS v3.2.1-7.1', 'PCI DSS v3.2.1-7.1.2', 'PCI-DSS', 'RMiT', 'Risk Management in Technology (RMiT)-10.55']|
|service|['cloud']|



[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
