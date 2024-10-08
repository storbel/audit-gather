import subprocess
import json
import click
from prettytable import PrettyTable
from termcolor import colored
from datetime import datetime, timedelta

def run_oc_command(command):
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    if result.returncode != 0:
        click.echo(f"Error running command: {command}")
        click.echo(f"Error message: {result.stderr}")
        return None
    return result.stdout

def check_apiserver_encryption():
    command = "oc get apiserver cluster -o json"
    output = run_oc_command(command)
    if output:
        apiserver_config = json.loads(output)
        encryption_config = apiserver_config.get('spec', {}).get('encryption', {}).get('type')
        if encryption_config:
            return ("API Server Encryption", "Enabled", "LOW", "green", "API Server encryption is properly configured.")
        else:
            return ("API Server Encryption", "Disabled", "CRITICAL", "red", "API Server encryption is not enabled. This poses a security risk.")
    return ("API Server Encryption", "Check Failed", "UNKNOWN", "yellow", "Unable to determine API Server encryption status.")

def check_audit_configuration():
    command = "oc get configmap config -n openshift-kube-apiserver -o json"
    output = run_oc_command(command)
    if output:
        config_map = json.loads(output)
        audit_policy = json.loads(config_map['data']['config.yaml'])
        audit_config = audit_policy.get('auditConfig', {})
        policy_configuration = audit_config.get('policyConfiguration', {})
        rules = policy_configuration.get('rules', [])
        
        for rule in rules:
            if rule.get('level') in ['RequestResponse', 'Metadata']:
                return ("Audit Configuration", "Properly Configured", "LOW", "green", "Audit is correctly configured to WriteRequestBodies or AllRequestBodies.")
        
        return ("Audit Configuration", "Improperly Configured", "WARNING", "yellow", "Audit is not configured to WriteRequestBodies or AllRequestBodies. This may limit the effectiveness of auditing.")
    return ("Audit Configuration", "Check Failed", "UNKNOWN", "yellow", "Unable to determine audit configuration status.")

def check_cluster_certificate():
    command = "oc get secret/router-ca -n openshift-ingress-operator -o json"
    output = run_oc_command(command)
    if output:
        secret_data = json.loads(output)
        tls_crt = secret_data['data'].get('tls.crt')
        if tls_crt:
            cert_check_command = f"echo '{tls_crt}' | base64 -d | openssl x509 -noout -dates"
            cert_info = run_oc_command(cert_check_command)
            if cert_info:
                for line in cert_info.split('\n'):
                    if line.startswith('notAfter='):
                        expiry_date = datetime.strptime(line.split('=')[1], '%b %d %H:%M:%S %Y %Z')
                        current_date = datetime.now()
                        days_until_expiry = (expiry_date - current_date).days
                        
                        if days_until_expiry > 30:
                            return ("Cluster Certificate", "Valid", "LOW", "green", f"Certificate is valid. Expires in {days_until_expiry} days.")
                        elif days_until_expiry > 0:
                            return ("Cluster Certificate", "Expiring Soon", "WARNING", "yellow", f"Certificate is valid but expires in {days_until_expiry} days. Consider renewing soon.")
                        else:
                            return ("Cluster Certificate", "Expired", "CRITICAL", "red", f"Certificate has expired {abs(days_until_expiry)} days ago.")
                
                return ("Cluster Certificate", "Unknown", "UNKNOWN", "yellow", "Unable to determine certificate expiry date.")
        else:
            return ("Cluster Certificate", "Not Found", "CRITICAL", "red", "TLS certificate not found in router-ca secret.")
    return ("Cluster Certificate", "Check Failed", "UNKNOWN", "yellow", "Unable to retrieve cluster certificate information.")
def check_hot_pods():
    # Get all role bindings across all namespaces
    command = "oc get rolebindings,clusterrolebindings --all-namespaces -o json"
    output = run_oc_command(command)
    if not output:
        return ("Hot Pods", "Check Failed", "UNKNOWN", "yellow", "Unable to retrieve role binding information.")

    bindings = json.loads(output)
    privileged_sas = set()

    # Check for service accounts with privileged roles
    privileged_roles = ["cluster-admin", "admin", "edit"]
    for item in bindings.get('items', []):
        role_ref = item.get('roleRef', {})
        if role_ref.get('name') in privileged_roles:
            for subject in item.get('subjects', []):
                if subject.get('kind') == 'ServiceAccount':
                    privileged_sas.add(f"{subject.get('namespace', 'unknown')}/{subject.get('name', 'unknown')}")

    # Get all pods
    command = "oc get pods --all-namespaces -o json"
    output = run_oc_command(command)
    if not output:
        return ("Hot Pods", "Check Failed", "UNKNOWN", "yellow", "Unable to retrieve pod information.")

    pods = json.loads(output)
    hot_pods = []

    for pod in pods['items']:
        namespace = pod['metadata']['namespace']
        pod_name = pod['metadata']['name']
        service_account = pod['spec'].get('serviceAccountName', 'default')
        
        if f"{namespace}/{service_account}" in privileged_sas:
            hot_pods.append(f"{namespace}/{pod_name}")

    if hot_pods:
        hot_pods_list = ", ".join(hot_pods[:20])  # List up to 5 hot pods
        if len(hot_pods) > 5:
            hot_pods_list += f" and {len(hot_pods) - 5} more"
        return ("Hot Pods", "Detected", "CRITICAL", "red", f"Found {len(hot_pods)} hot pod(s): {hot_pods_list}")
    else:
        return ("Hot Pods", "None Detected", "LOW", "green", "No hot pods found with elevated privileges.")
def check_kubeadmin_usage():
    # Fetch all available audit logs
    command = "oc adm node-logs --role=master --path=openshift-apiserver/audit.log"
    output = run_oc_command(command)

    if not output:
        return ("Kubeadmin Usage", "Check Failed", "UNKNOWN", "yellow", "Unable to retrieve audit logs.")

    kubeadmin_events = []
    for line in output.splitlines():
        try:
            log_entry = json.loads(line)
            if log_entry.get('user', {}).get('username') == 'kubeadmin':
                timestamp = log_entry.get('requestReceivedTimestamp', 'unknown time')
                verb = log_entry.get('verb', 'unknown action')
                resource = log_entry.get('objectRef', {}).get('resource', 'unknown resource')
                kubeadmin_events.append((timestamp, verb, resource))
        except json.JSONDecodeError:
            continue  # Skip lines that are not valid JSON

    if kubeadmin_events:
        # Sort events by timestamp
        kubeadmin_events.sort(key=lambda x: x[0])
        
        # Get the first and last usage times
        first_usage = kubeadmin_events[0][0]
        last_usage = kubeadmin_events[-1][0]
        
        # Format a summary of the most recent events
        recent_events = kubeadmin_events[-5:]  # Get the last 5 events
        event_summary = "\n".join([f"{ts}: {verb} on {res}" for ts, verb, res in recent_events])
        
        summary = (f"Found {len(kubeadmin_events)} kubeadmin usage event(s).\n"
                   f"First usage: {first_usage}\n"
                   f"Last usage: {last_usage}\n"
                   f"Most recent events:\n{event_summary}")
        
        severity = "CRITICAL" if len(kubeadmin_events) > 10 else "WARNING"
        color = "red" if severity == "CRITICAL" else "yellow"
        
        return ("Kubeadmin Usage", "Detected", severity, color, summary)
    else:
        return ("Kubeadmin Usage", "None Detected", "LOW", "green", "No kubeadmin usage detected in the audit logs.")

def display_results(results):
    table = PrettyTable()
    table.field_names = ["Check", "Status", "Severity", "Description"]
    table.align["Description"] = "l"
    table.max_width["Description"] = 60
    
    for check, status, severity, color, description in results:
        table.add_row([
            check,
            colored(status, color),
            colored(severity, color),
            description
        ])
    
    click.echo(table)
def check_anonymous_auth():
    # Fetch the API server configuration
    command = "oc get configmap config -n openshift-kube-apiserver -o json"
    output = run_oc_command(command)

    if not output:
        return ("Anonymous Auth", "Check Failed", "UNKNOWN", "yellow", "Unable to retrieve API server configuration.")

    try:
        config = json.loads(output)
        api_server_args = json.loads(config['data']['config.yaml'])['apiServerArguments']
        
        # Check if anonymous-auth flag is set and its value
        anonymous_auth = api_server_args.get('anonymous-auth', ['true'])
        
        if 'false' in anonymous_auth:
            return ("Anonymous Auth", "Disabled", "LOW", "green", "Anonymous authentication is correctly disabled.")
        else:
            return ("Anonymous Auth", "Enabled", "CRITICAL", "red", "Anonymous authentication is enabled. This poses a security risk.")
    
    except (json.JSONDecodeError, KeyError) as e:
        return ("Anonymous Auth", "Check Failed", "UNKNOWN", "yellow", f"Error parsing API server configuration: {str(e)}")

# Update the cli function to include the new check
@click.command()
@click.option('--encryption', is_flag=True, help='Check if API Server encryption is enabled.')
@click.option('--audit', is_flag=True, help='Check if audit is configured correctly.')
@click.option('--certificate', is_flag=True, help='Check if the OpenShift cluster certificate is valid.')
@click.option('--hot-pods', is_flag=True, help='Check for hot pods with elevated privileges.')
@click.option('--kubeadmin', is_flag=True, help='Check for kubeadmin usage in the audit logs.')
@click.option('--anonymous-auth', is_flag=True, help='Check if anonymous authentication is disabled.')
@click.option('--all', 'check_all', is_flag=True, help='Run all checks.')
def cli(encryption, audit, certificate, hot_pods, kubeadmin, anonymous_auth, check_all):
    """Run OpenShift cluster checks."""
    results = []

    if check_all or encryption:
        results.append(check_apiserver_encryption())
    if check_all or audit:
        results.append(check_audit_configuration())
    if check_all or certificate:
        results.append(check_cluster_certificate())
    if check_all or hot_pods:
        results.append(check_hot_pods())
    if check_all or kubeadmin:
        results.append(check_kubeadmin_usage())
    if check_all or anonymous_auth:
        results.append(check_anonymous_auth())

    if not results:
        click.echo("No checks selected. Use --help to see available options.")
    else:
        display_results(results)

if __name__ == '__main__':
    cli()