



# Title: Ensure Big Query Datasets are not publically accessible


***<font color="white">Master Test Id:</font>*** PR-GCP-TRF-BQ-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-GCP-TRF-BQ-001|
|eval|data.rule.bq_public_access|
|message|data.rule.bq_public_access_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure there are no anonymously and/or publicly accessible BigQuery datasets available within your Google Cloud Platform (GCP) account. Google Cloud BigQuery datasets have Identity and Access Management (IAM) policies configured to determine who can have access to these resources  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['CIS', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['google_bigquery_dataset']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/google/terraform/database.rego
