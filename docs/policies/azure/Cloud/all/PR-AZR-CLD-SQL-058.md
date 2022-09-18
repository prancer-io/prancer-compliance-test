



# Title: Ensure Geo-redundant backup is enabled on MariaDB server.


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-SQL-058

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_409']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([dbforMariaDB.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-SQL-058|
|eval|data.rule.mariadb_geo_redundant_backup_enabled|
|message|data.rule.mariadb_geo_redundant_backup_enabled_err|
|remediationDescription|1. Sign in to Azure Management Console.<br>2. Navigate to All resources blade at https://portal.azure.com/#blade/HubsExtension/BrowseAll to access all your Microsoft Azure resources.<br>3. From the Type filter box, select Azure Database for MariaDB server to list the MariaDB servers provisioned within your Azure account.<br>4. Click on the name of the MariaDB database server that you want to examine.<br>5. In the navigation panel, under Settings, select Pricing tier to access the pricing tier settings available for the selected MariaDB server.<br>6. On the Pricing tier page, in the Backup Redundancy Options section, check the backup redundancy tier configured for the database server. If the selected tier is Locally Redundant, the data can be recovered from within the current region only, therefore the Geo-Redundant backup feature is not enabled for the selected Microsoft Azure MariaDB database server.<br>7. Repeat steps no. 4 – 6 for each MariaDB database server available in the current Azure subscription.<br>8. Repeat steps no. 3 – 7 for each subscription created in your Microsoft Azure cloud account.|
|remediationFunction|PR_AZR_CLD_SQL_058.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Azure Database for MariaDB provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['Best Practice']|
|service|['Databases']|



[dbforMariaDB.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/dbforMariaDB.rego
