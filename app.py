from flask import Flask, render_template, request,redirect,url_for
import requests
import yaml
import os
import base64
from collections import OrderedDict
from dotenv import load_dotenv
import json


load_dotenv()

app = Flask(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

REPO_OWNER = os.getenv("REPO_OWNER")
REPO_NAME = os.getenv("REPO_NAME")

def get_company_names(repo_owner, repo_name, github_token):
    company_names = []
    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/contents/details.json'
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        # Decode and parse the existing JSON content
        existing_content = json.loads(base64.b64decode(response.json()['content']).decode())
        company_names = list(existing_content.keys())
    else:
        print(f"Failed to fetch company names. Status code: {response.status_code}")
        print("Response content:", response.content.decode())  # Print response content for debugging
    
    return company_names


def get_company_details(company_name, REPO_OWNER, REPO_NAME, GITHUB_TOKEN):
    company_details = {}

    # Construct the URL for the JSON file in the GitHub repository
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/details.json'


    # Set up headers with authorization token
    headers = {
        'Authorization': f'token {GITHUB_TOKEN}',
        'Accept': 'application/vnd.github.v3+json'
    }

    # Make GET request to GitHub API to fetch the details.json content
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        # Decode and load JSON content from response
        json_content = json.loads(base64.b64decode(response.json()['content']).decode())

        if company_name in json_content:
            # Extract repo_name and username from the JSON content based on the company_name
            company_info = json_content[company_name]
            repo_name = company_info.get('repo_url')
            username = company_info.get('username')

            # Construct the URL for the YAML file based on the extracted repo_name and username
            if repo_name and username:
                file_path = f'Pipeline/SoftwareMathematics/{company_name}/{repo_name}/{username}.yaml'
                yaml_url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file_path}'

                # Make GET request to GitHub API to fetch the YAML content
                yaml_response = requests.get(yaml_url, headers=headers)

                if yaml_response.status_code == 200:
                    # Decode and load YAML content from response
                    yaml_content = yaml.safe_load(base64.b64decode(yaml_response.json()['content']).decode())

                    # Check if yaml_content is not None
                    if yaml_content is not None:
                        # Correct the YAML syntax for each key-value pair
                        for key, value in yaml_content.items():
                            if value is None:  # Check if the value is None
                                yaml_content[key] = ""  # Assign an empty string if value is None
                            elif isinstance(value, str):  # Assuming IP addresses are given as strings
                                # Split the string into a list of IP addresses
                                formatted_string = value.replace('-', '').split()
                                # Prefix each IP address with a hyphen
                                formatted_string_space = ' '.join(formatted_string)
                                # Join the IP addresses back into a single string
                                yaml_content[key] = formatted_string_space

                        company_details = yaml_content
                    else:
                        company_details = {}
                else:
                    print(f"Failed to fetch YAML content. Status code: {yaml_response.status_code}")

    else:
        print(f"Failed to fetch details.json. Status code: {response.status_code}")
        print("Response content:", response.content.decode())  # Print response content for debugging

    return company_details

@app.route('/add',methods=['GET','POST'])
def add_form():
    if request.method=='POST':
        username = request.form.get('username')
        companyname = request.form.get('companyname')
        repo_url = request.form.get('repourl')
        enabled = request.form.get('enabled')
        job_type = request.form.get('job_type')
        run_command = request.form.get('runcmnd')
        src_path = request.form.get('srcpath')
        application_port = request.form.get('applicationport')
        deploy_port = request.form.get('deployport')
        ssh_port_prod = request.form.get('sshportprod')
        ssh_port_dev = request.form.get('sshportdev')
        build_command = request.form.get('buildcommand')
        pvt_deploy_servers_dev = request.form.get('pvtdeployserversdev')
        deploy_servers_dev = request.form.get('deployserversdev')
        pvt_deploy_servers_prod = request.form.get('pvtdeployserversprod')
        deploy_servers_prod = request.form.get('deployserversprod')
        deploy_env_prod = request.form.get('deployenvprod')
        deploy_env_dev = request.form.get('deployenvdev')
        deploy_env = request.form.get('deployenv')


        # Assuming pvt_deploy_servers_dev is a string containing IP addresses separated by spaces
        pvt_deploy_servers_dev_list = ' '.join(['-' + ip for ip in filter(None, pvt_deploy_servers_dev.split())]) if pvt_deploy_servers_dev else ''
        deploy_servers_prod_list = ' '.join(['-' + ip for ip in filter(None, deploy_servers_prod.split())]) if deploy_servers_prod else ''
        pvt_deploy_servers_prod_list = ' '.join(['-' + ip for ip in filter(None, pvt_deploy_servers_prod.split())]) if pvt_deploy_servers_prod else ''
        deploy_servers_dev_list = ' '.join(['-' + ip for ip in filter(None, deploy_servers_dev.split())]) if deploy_servers_dev else ''
        deploy_env_list = ' '.join(['-' + ip for ip in filter(None, deploy_env.split())]) if deploy_env else ''



        # Define the order of fields
        field_order = [
             "name",
            "company name",
            "repository url",
            "enabled",
            "job_type",
            "run_command",
            "src_path",
            "application_port",
            "deploy_port",
            "ssh_port_prod",
            "ssh_port_dev",
            "build_command",
            "pvt_deploy_servers_dev",
            "deploy_servers_dev",
            "pvt_deploy_servers_prod",
            "deploy_servers_prod",
            "deploy_env_prod",
            "deploy_env_dev",
            "deploy_env"
        ]
        data={
             "name": username,
            "company name": companyname,
            "repository url": repo_url,
            "enabled": enabled,
            "job_type": job_type,
            "run_command": run_command,
            "src_path": src_path,
            "application_port": application_port,
            "deploy_port": deploy_port,
            "ssh_port_prod": ssh_port_prod,
            "ssh_port_dev": ssh_port_dev,
            "build_command": build_command,
            "pvt_deploy_servers_dev": pvt_deploy_servers_dev_list,
            "deploy_servers_dev": deploy_servers_dev_list,
            "pvt_deploy_servers_prod": pvt_deploy_servers_prod_list,
            "deploy_servers_prod": deploy_servers_prod_list,
            "deploy_env_prod": deploy_env_prod,
            "deploy_env_dev": deploy_env_dev,
            "deploy_env": deploy_env_list
        }  

        data = OrderedDict((key, data[key]) for key in field_order if key in data)

        formatted_yaml = ''
        for field in field_order:
            if field in data:
                value = data[field]
                if isinstance(value, list):
                    value = yaml.dump(value, default_flow_style=False).strip()
                formatted_yaml += f"{field}: {value}\n"
            else:
                formatted_yaml += f"{field}: null\n"

        file_content_base64 = base64.b64encode(formatted_yaml.encode()).decode()

        repo_parts = data["repository url"].split('/')
        repo_name = repo_parts[-1]
        
        add_data_to_json(username,companyname,repo_name, GITHUB_TOKEN, REPO_OWNER, REPO_NAME)

        file_name = f'{data["name"]}.yaml'
        file_path = f'Pipeline/SoftwareMathematics/{data["company name"]}/{repo_name}/{file_name}'

        url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file_path}'

        headers = {
            'Authorization': f'token {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v3+json'
        }
 
           
        # response = requests.get(url, headers=headers)
        response = requests.get(url, headers=headers)


        if response.status_code == 200:
            # File already exists, update its content
            existing_file = response.json()
            payload = {
                'message': 'Update file',
                'content': file_content_base64,
                'sha': existing_file['sha']  # SHA of the existing file for update
            }
            response = requests.put(url, headers=headers, json=payload)

            # response = requests.put(url, headers=headers, json=payload,params={'ref': 'pipeline-1'})
        elif response.status_code == 404:
            # File does not exist, create a new file
            payload = {
                'message': 'Create file',
                'content': file_content_base64
            }
            response = requests.put(url, headers=headers, json=payload)
        
        if response.status_code == 201 or response.status_code == 200:
            return 'File saved successfully to GitHub.'
        else:
            return f'Failed to save file to GitHub. Status code: {response.status_code}'

    return "Data saved successfully!!"

import requests
import json
import base64

def add_data_to_json(username, companyname, repo_url, github_token, repo_owner, repo_name):
    # Get the existing content of the JSON file from GitHub

    new_data = {
        companyname: {
            'username': username,
            'repo_url': repo_url
        }
    }

    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/contents/details.json'
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    # response = requests.get(url, headers=headers)
    response = requests.get(url, headers=headers)

    
    if response.status_code == 200:
        # Decode and parse the existing JSON content
        existing_content = json.loads(base64.b64decode(response.json()['content']).decode())
    else:
        print(f"Failed to retrieve existing content. Status code: {response.status_code}")
        return

    # Add the new data to the existing content
    for key, value in new_data.items():
        existing_content[key] = value

    # Convert the updated content back to JSON string
    updated_content = json.dumps(existing_content, indent=4)

    # Encode the JSON string to base64
    encoded_content = base64.b64encode(updated_content.encode()).decode()

    # Prepare the payload for updating the file
    payload = {
        'message': 'Add data to details.json',
        'content': encoded_content,
        'sha': response.json()['sha']  # SHA of the existing file for update
    }

    # Use the GitHub API to update the content of details.json in the repository
    response = requests.put(url, headers=headers, json=payload)

    if response.status_code == 200 or response.status_code == 201:
        print("Data added successfully to details.json.")
    else:
        print(f"Failed to add data to details.json. Status code: {response.status_code}")
        

@app.route('/update', methods=['GET', 'POST'])
def update():
    if request.method == "GET":
        company_name = request.args.get('company')
        company_details = get_company_details(company_name, REPO_OWNER, REPO_NAME, GITHUB_TOKEN)
        return render_template("update.html", company_details=company_details)
    elif request.method == "POST":
        # Extract data from the form
        new_data = {
            'name': request.form.get('username'),
            'company_name': request.form.get('companyname'),
            'enabled': request.form.get('enabled') == 'yes',  # Convert to boolean
            'job_type': request.form.get('job_type'),
            'repository_url': request.form.get('repourl'),
            'run_command': request.form.get('runcmnd'),
            'src_path': request.form.get('srcpath'),
            'application_port': request.form.get('applicationport'),
            'deploy_port': request.form.get('deployport'),
            'ssh_port_prod': request.form.get('sshportprod'),
            'ssh_port_dev': request.form.get('sshportdev'),
            'build_command': request.form.get('buildcommand'),
            'pvt_deploy_servers_dev': request.form.get('pvtdeployserversdev'),
            'deploy_servers_dev': request.form.get('deployserversdev'),
            'pvt_deploy_servers_prod': request.form.get('pvtdeployserversprod'),
            'deploy_servers_prod': request.form.get('deployserversprod'),
            'deploy_env_prod': request.form.get('deployenvprod'),
            'deploy_env_dev': request.form.get('deployenvdev'),
            'deploy_env': request.form.get('deployenv')
        }
        
        # Redirect to a success page or back to the update page
        return redirect(url_for('update'))  # Redirect to the update page
    return "Updated"


@app.route('/create')
def create_user():
    return render_template("index.html")

@app.route('/')
def index():
    company_names=get_company_names(REPO_OWNER,REPO_NAME,GITHUB_TOKEN)
    return render_template("base.html",company_names=company_names)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
