import time
from flask import Flask, jsonify, render_template, request, redirect, session, url_for
import requests
import yaml
import os
import base64
from collections import OrderedDict
from dotenv import load_dotenv
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import logging

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session

# MongoDB connection
mongo_client = MongoClient('mongodb://localhost:27017/')
db = mongo_client['UserAuth']
users_collection = db['Users']

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = os.getenv("REPO_OWNER")
REPO_NAME = os.getenv("REPO_NAME")

ip_request_counts = {}


def update_ip_request_count(ip_address):
    current_time = time.time()
    if ip_address in ip_request_counts:
        count, timestamp = ip_request_counts[ip_address]
        if current_time - timestamp > 3600:  # Reset count if more than 1 hour has passed
            ip_request_counts[ip_address] = (1, current_time)
        else:
            ip_request_counts[ip_address] = (count + 1, timestamp)
    else:
        ip_request_counts[ip_address] = (1, current_time)

    # Check if the IP has exceeded the limit (e.g., 100 requests per hour)
    if ip_request_counts[ip_address][0] > 10:
        return False
    else:
        return True


def check_rate_limit(response):
    if 'headers' in response:
        remaining = int(response['headers'].get('X-RateLimit-Remaining', 0))
        reset_time = int(response['headers'].get('X-RateLimit-Reset', 0))
        return remaining, reset_time
    else:
        # If response does not contain headers, return default values
        return 0, 0


def fetch_file_names(company_name, repo_name, access_token):
    file_names = []

    target_url = (f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/Pipeline/SoftwareMathematics/'
                  f'{company_name}/{repo_name}')
    headers = {"Authorization": f"token {access_token}"} if access_token else {}

    response = requests.get(target_url, headers=headers)

    if response.status_code != 200:
        print(f"Failed to fetch Files. Status code: {response.status_code}")
        return file_names

    for item in response.json():
        if item["type"] == "file":
            file_names.append(item["name"])

    return file_names


def fetch_repo_names(company_name, access_token):
    repo_names = []

    target_url = (f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/Pipeline/SoftwareMathematics/'
                  f'{company_name}')

    headers = {"Authorization": f"token {access_token}"} if access_token else {}

    response = requests.get(target_url, headers=headers)

    if response.status_code != 200:
        print(f"Failed to fetch repositories. Status code: {response.status_code}")
        return repo_names

    for item in response.json():
        if item["type"] == "dir":
            repo_names.append(item["name"])

    return repo_names


def get_company_names(repo_owner, repo_name, github_token):
    company_names = []

    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/contents/Pipeline/SoftwareMathematics'
    headers = {
        'Authorization': f'token {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        # Parse the response JSON
        content = response.json()
        # Filter out directories
        directories = [item['name'] for item in content if item['type'] == 'dir']
        # Append directory names to company_names list
        company_names.extend(directories)
    else:
        print(f"Failed too fetch company names. Status code: {response.status_code}")
        print("Response content:", response.content.decode())  # Print response content for debugging

    return company_names


def get_company_details(company_name, repo_name, file_name, REPO_OWNER, REPO_NAME,
                        GITHUB_TOKEN):
    company_details = {}

    file_path = f'Pipeline/SoftwareMathematics/{company_name}/{repo_name}/{file_name}'
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file_path}'

    headers = {
        'Authorization': f'token {GITHUB_TOKEN}',
        'Accept': 'application/vnd.github.v3+json'
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:

        yaml_content = yaml.safe_load(base64.b64decode(response.json()['content']).decode())

        if yaml_content is not None:
            for key, value in yaml_content.items():

                if value is None:
                    yaml_content[key] = ""

                elif isinstance(value, str):
                    formatted_string = value.replace('-', '').split()
                    formatted_string_space = ' '.join(formatted_string)
                    yaml_content[key] = formatted_string_space

            company_details = yaml_content

        else:
            company_details = {}
    else:
        print(f"Failed to fetch YAML content. Status code: {response.status_code}")
    return company_details


@app.route('/add', methods=['GET', 'POST'])
def add_form():
    if request.method == 'POST':
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
        pvt_deploy_servers_dev_list = ' '.join(
            ['-' + ip for ip in filter(None, pvt_deploy_servers_dev.split())]) if pvt_deploy_servers_dev else ''
        deploy_servers_prod_list = ' '.join(
            ['-' + ip for ip in filter(None, deploy_servers_prod.split())]) if deploy_servers_prod else ''
        pvt_deploy_servers_prod_list = ' '.join(
            ['-' + ip for ip in filter(None, pvt_deploy_servers_prod.split())]) if pvt_deploy_servers_prod else ''
        deploy_servers_dev_list = ' '.join(
            ['-' + ip for ip in filter(None, deploy_servers_dev.split())]) if deploy_servers_dev else ''
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
        data = {
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

        file_name = f'{data["name"]}.yaml'
        file_path = f'Pipeline/SoftwareMathematics/{data["company name"]}/{repo_name}/{file_name}'

        url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file_path}'

        headers = {
            'Authorization': f'token {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
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
@app.route('/update', methods=['GET', 'POST'])
def update():
    if request.method == "GET":
        company_names = request.args.get('company_name')
        repo_names = request.args.get('repo_name')
        file_names = request.args.get('file_name')
        company_details = get_company_details(company_names, repo_names, file_names, REPO_OWNER, REPO_NAME,
                                              GITHUB_TOKEN)
        return render_template("update.html", company_details=company_details)
    elif request.method == "POST":
        try:
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

            # Handle the form data as required

            # Redirect to a success page or back to the update page
            return redirect(url_for('update'))  # Redirect to the update page or a success page
        except Exception as e:
            # Handle any exceptions that may occur during form processing
            print(f"An error occurred: {str(e)}")
            return render_template("error.html", error_message="An error occurred while processing the form.")

    return "Updated"


@app.route('/create')
def create_user():
    return render_template("index.html")


@app.route('/', methods=['GET', 'POST'])
def new_index():
    if 'username' not in session:
        # If user is not logged in, redirect to login page
        return redirect(url_for('login'))
    if request.method == 'POST':
        data = request.get_json()
        company_names = data.get('company_name')
        repo_names = data.get('repo_name')
        file_names = data.get('file_name')
        if company_names and not repo_names:
            repo_names = fetch_repo_names(company_names, GITHUB_TOKEN)
            return jsonify(repo_names)

        if company_names and repo_names:
            file_names = fetch_file_names(company_names, repo_names, GITHUB_TOKEN)
            return jsonify(file_names)
        else:
            return jsonify({})
    else:
        try:
            # Handle the GET request here
            company_names = get_company_names(REPO_OWNER, REPO_NAME, GITHUB_TOKEN)

            # Log company names
            logging.info(f"Company names: {company_names}")

            return render_template("base.html", company_names=company_names)
        except Exception as e:
            # Log any exceptions
            logging.error(f"An error occurred: {str(e)}")
            return "An error occurred"
    # company_names = get_company_names(REPO_OWNER, REPO_NAME, GITHUB_TOKEN)
    # return render_template('base.html',company_names=company_names)



# Login authentication function
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username exists in the database
        user = users_collection.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            # If username and password match, log in the user
            session['username'] = username
            return redirect('/')
        else:
            # If username or password is incorrect, render the login page with an error
            return render_template('login.html', error='Invalid username or password')

    else:
        # If it's a GET request, render the login form
        return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the username already exists
        if users_collection.find_one({'username': username}):
            error_message = 'Username already exists. Please choose a different username.'
            return render_template('sign_up.html', error=error_message)

        # Hash the password before storing it
        hashed_password = generate_password_hash(password)

        # Insert new user data into MongoDB
        user_data = {'username': username, 'password': hashed_password}
        users_collection.insert_one(user_data)

        return redirect(url_for('login'))  # Redirect to login page after successful signup

    return render_template('sign_up.html')


@app.route('/logout')
def logout():
    # Clear the session
    session.pop('username', None)
    # Redirect to the logout page
    return redirect(url_for('logout_page'))


@app.route('/logout_page')
def logout_page():
    return render_template('logout.html')


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
