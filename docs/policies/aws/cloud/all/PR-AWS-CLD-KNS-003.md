



# Master Test ID: PR-AWS-CLD-KNS-003


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_11', 'TEST_KMS']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-KNS-003|
|eval|data.rule.kinesis_gs_kms_key|
|message|data.rule.kinesis_gs_kms_key_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kinesis.html#Kinesis.Client.describe_stream' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_KNS_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Title:</font>*** Ensure Kinesis streams are encrypted using dedicated GS managed KMS key.

***<font color="white">Description:</font>*** It is to check only GS managed CMKs are used to encrypt Kinesis Data Streams.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'CCPA', 'CMMC', 'CSA CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'LGPD', 'MAS TRM', 'NIST 800', 'NIST CSF', 'NIST SP', 'PCI-DSS', 'PIPEDA', 'RMiT', 'SOC 2']|
|service|['kinesis', 'kms']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
