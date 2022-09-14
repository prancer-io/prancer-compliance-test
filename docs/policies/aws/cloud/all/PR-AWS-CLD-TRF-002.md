



# Master Test ID: PR-AWS-CLD-TRF-002


Master Snapshot Id: ['TEST_TRF']

type: rego

rule: [file(storage.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-TRF-002|
|eval: |data.rule.transfer_server_protocol|
|message: |data.rule.transfer_server_protocol_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/transfer.html#Transfer.Client.describe_server' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_TRF_002.py|


severity: Medium

title: Ensure Transfer Server is not use FTP protocol.

description: It checks if FTP protocol is not used for AWS Transfer Family server.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['Best Practice']|
|service: |['transfer']|



[file(storage.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/storage.rego
