from mdutils.mdutils import MdUtils
import json

def main(data):
    for i in range(len(data['cases'])):  

        file_name = str(data['cases'][i]["evals"][0]["id"])
        mdFile = MdUtils(file_name)
        mdFile.new_header(level=1,title="Master Test ID: "+str(data['cases'][i]['masterTestId']))
        mdFile.new_paragraph("Master Snapshot Id: "+ str(data['cases'][i]['masterSnapshotId']))
        mdFile.new_paragraph("type: "+ str(data['cases'][i]['type']))
        mdFile.new_paragraph("rule: "+ str(data['cases'][i]['rule']))

        evals = "evals: [\n    {\n       'ID': "+"'"+str(data['cases'][i]["evals"][0]["id"])+"'"+"\n       'eval': "+"'"+str(data['cases'][i]["evals"][0]["eval"])+"'"+"\n       'message': "+"'"+str(data['cases'][i]["evals"][0]["message"])+"'"+"\n       'remediationDescription': "+"'"+str(data['cases'][i]["evals"][0]["remediationDescription"])+"'"+"\n       'remediationFunction': "+"'"+str(data['cases'][i]["evals"][0]["remediationFunction"])+"'"+"\n    }\n]"
        mdFile.new_paragraph(evals)

        mdFile.new_paragraph("severity: "+ str(data['cases'][i]['severity']))
        mdFile.new_paragraph("title: "+ str(data['cases'][i]['title']))
        mdFile.new_paragraph("description: "+ str(data['cases'][i]['description']))

        tags= "tags: [\n    {\n       'cloud': "+"'"+str(data['cases'][i]["tags"][0]["cloud"])+"'"+"\n       'compliance': "+"'"+str(data['cases'][i]["tags"][0]["compliance"])+"'"+"\n       'service': "+"'"+str(data['cases'][i]["tags"][0]["service"])+"'"+"\n    }\n]"
        mdFile.new_paragraph(tags)

        # mdFile.new_paragraph("resourceTypes: "+ str(data['cases'][i]['resourceTypes']))
        
        mdFile.create_md_file()



file_name="masterTest.json"
with open(file_name, 'r', encoding='utf-8') as f:
    jsonData = json.load(f)
main(jsonData)