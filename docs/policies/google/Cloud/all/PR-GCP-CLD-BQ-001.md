



# Title: Ensure Big Query Datasets are not publically accessible


***<font color="white">Master Test Id:</font>*** PR-GCP-CLD-BQ-001

***<font color="white">Master Snapshot Id:</font>*** ['GOOGLE_BIGQUERY']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-CLD-BQ-001|
|eval|data.rule.bigquery_public_access|
|message|data.rule.bigquery_public_access_err|
|remediationDescription|make sure you are following the deployment template format presented <a href='https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets' target='_blank'>here</a>|
|remediationFunction|PR_GCP_CLD_BQ_001.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure there are no anonymously and/or publicly accessible BigQuery datasets available within your Google Cloud Platform (GCP) account. Google Cloud BigQuery datasets have Identity and Access Management (IAM) policies configured to determine who can have access to these resources  
  
  

|Title|Description|
| :---: | :---: |
|cloud|GCP|
|compliance|['CIS', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['cloud']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/cloud/database.rego
