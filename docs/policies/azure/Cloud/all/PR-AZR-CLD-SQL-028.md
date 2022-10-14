



# Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-028

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_412']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([postgreSQL.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-028|
|eval|data.rule.geoRedundantBackup|
|message|data.rule.geoRedundantBackup_err|
|remediationDescription|Configuring locally redundant or geo-redundant storage for backup is only allowed during server create. Once the server is provisioned, you cannot change the backup storage redundancy option.<br><br>To create an Azure Database for PostgreSQL server, take the following steps:<br>1. Select the Create a resource button (+) in the upper-left corner of the portal<br>2. Select Databases > Azure Database for PostgreSQL<br>3. Select the Single server deployment option<br>4. Fill out the Basics form required information<br>5. Ensure Backup Redundancy option is Geo_redundant<br><br>For More Information:<a href='https://docs.microsoft.com/en-us/azure/postgresql/concepts-backup' target='_blank'>https://docs.microsoft.com/en-us/azure/postgresql/concepts-backup</a>|
|remediationFunction|PR_AZR_CLD_SQL_028.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS']|
|service|['Databases']|



[postgreSQL.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/postgreSQL.rego
