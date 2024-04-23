import os
import time
from flask import Flask, request, redirect, render_template, session, url_for
from github import Github
import subprocess
import urllib.parse
import oyaml as yaml
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session

# MongoDB connection
mongo_client = MongoClient('mongodb://localhost:27017/')
db = mongo_client['UserAuth']
users_collection = db['Users']

github_token = os.environ.get("GITHUB_TOKEN")
github_username = os.environ.get("GITHUB_USERNAME")

repo_name = "Simple"  # Repository name (without username)
repo_path = r"D:\workspace\Simple"  # Specify the path in the repository where you want to save the YAML files

try:
    g = Github(login_or_token=github_token)
    gituser = g.get_user()
    repo = gituser.get_repo(repo_name)

except Exception as e:
    print("An error occurred:", e)

# Dictionary to store request counts for each IP address
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


@app.route('/add', methods=['POST'])
def get_user_input():
    if request.method == "POST":
        ip_address = request.remote_addr
        # Check if the IP has exceeded the request limit
        if not update_ip_request_count(ip_address):
            return "Error: IP address has exceeded request limit"

        company_name = request.form.get('company_name')
        repo_name = request.form.get('repo_name')  # Get the repository name from the form
        name = request.form.get('name')
        repo_url = request.form.get('repo_url')
        enabled = request.form.get('enabled')
        job_type = request.form.get('job_type')
        run_command = request.form.get('run_command')
        src_path = request.form.get('src_path')
        application_port = request.form.get('application_port')
        deploy_port = request.form.get('deploy_port')
        ssh_port_prod = request.form.get('ssh_port_prod')
        ssh_port_dev = request.form.get('ssh_port_dev')
        build_command = request.form.get('build_command')
        pvt_deploy_servers_dev = request.form.get('pvt_deploy_servers_dev')
        deploy_servers_dev = request.form.get('deploy_servers_dev')
        pvt_deploy_servers_prod = request.form.get('pvt_deploy_servers_prod')
        deploy_servers_prod = request.form.get('deploy_servers_prod')
        deploy_env_prod = request.form.get('deploy_env_prod')
        deploy_env_dev = request.form.get('deploy_env_dev')
        deploy_env = request.form.get('deploy_env')

        data = {
            'name': name,
            'repo_url': repo_url,
            'enabled': enabled,
            'job_type': job_type,
            'run_command': run_command,
            'src_path': src_path,
            'application_port': application_port,
            'deploy_port': deploy_port,
            'ssh_port_prod': ssh_port_prod,
            'ssh_port_dev': ssh_port_dev,
            'build_command': build_command,
            'pvt_deploy_servers_dev': pvt_deploy_servers_dev,
            'deploy_servers_dev': deploy_servers_dev,
            'pvt_deploy_servers_prod': pvt_deploy_servers_prod,
            'deploy_servers_prod': deploy_servers_prod,
            'deploy_env_prod': deploy_env_prod,
            'deploy_env_dev': deploy_env_dev,
            'deploy_env': deploy_env
        }

        file_name = f"{name}.yaml"
        escaped_company_name = urllib.parse.quote(company_name, safe='')
        escaped_repo_name = urllib.parse.quote(repo_name, safe='')  # Escape repository name
        escaped_name = urllib.parse.quote(name, safe='')

        # Extract repository name from the URL
        repo_url_parts = urllib.parse.urlparse(repo_url)
        repo_path_parts = repo_url_parts.path.split("/")
        repo_name_from_url = repo_path_parts[-1].split('.')[0] if repo_path_parts[-1] else repo_path_parts[-2].split('.')[0]

        # Construct the directory path
        directory_path = os.path.join(repo_path, 'pipelines', 'SoftwareMathematics', escaped_company_name, repo_name_from_url)

        # Ensure the directory exists, creating if necessary
        os.makedirs(directory_path, exist_ok=True)

        # Construct the file path
        file_path = os.path.join(directory_path, file_name)

        # Save YAML file locally
        with open(file_path, 'w') as file:
            yaml.dump(data, file, default_flow_style=False)

        # Upload YAML file to GitHub
        try:
            # Read the contents of the file
            with open(file_path, 'r') as file:
                content = file.read()

            # Construct the dynamic_repo_path
            dynamic_repo_path = f"pipelines/SoftwareMathematics/{escaped_company_name}/{repo_name_from_url}/{file_name}"

            response = repo.create_file(dynamic_repo_path, f"Create {file_name}", content, branch="yaml_file_create")

            git_cmd_add = ["git", "add", file_path]
            subprocess.run(git_cmd_add)

            git_cmd_commit = ["git", "commit", "-m", f"Add {file_name}"]
            subprocess.run(git_cmd_commit)

            git_cmd_push = ["git", "push", "origin", "yaml_file_create"]
            subprocess.run(git_cmd_push)

            # Check rate limit after each request
            remaining, reset_time = check_rate_limit(response)
            if remaining == 0:
                # Rate limit exceeded, wait until reset_time
                sleep_time = max(reset_time - time.time() + 10, 0)  # Ensure sleep_time is non-negative
                time.sleep(sleep_time)

            return redirect('/')
        except Exception as e:
            error_message = str(e)
            print("An error occurred while uploading file to GitHub:", str(e))
            return "Error occurred while uploading file to GitHub. Please check logs for details."


@app.route('/')
def hello_world():
    if 'username' not in session:
        # If user is not logged in, redirect to login page
        return redirect(url_for('login'))
    return render_template("newindex.html", github_username=github_username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the username exists in the database
        user = users_collection.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            session['username'] = username  # Set session variable to indicate authentication
            return redirect('/')  # Redirect to the homepage after successful login
        else:
            error_message = 'Invalid username or password. Please try again.'
            return render_template('login.html', error=error_message)

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
            return render_template('signup.html', error=error_message)

        # Hash the password before storing it
        hashed_password = generate_password_hash(password)

        # Insert new user data into MongoDB
        user_data = {'username': username, 'password': hashed_password}
        users_collection.insert_one(user_data)

        return redirect(url_for('login'))  # Redirect to login page after successful signup

    return render_template('signup.html')


if __name__ == "__main__":
    app.run(debug=True)
