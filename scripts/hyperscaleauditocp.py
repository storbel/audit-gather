import subprocess
import json
import datetime
import os
import yaml
from prettytable import PrettyTable
from termcolor import colored
from datetime import datetime
import base64


def generate_banner():
    banner = r"""
____ ____ ____    _  _ _   _ ___  ____ ____ ____ ____ ____ _    ____
[__  |    |       |__|  \_/  |__] |___ |__/ [__  |    |__| |    |___
___] |___ |___    |  |   |   |    |___ |  \ ___] |___ |  | |___ |___

"""
    print(banner)

    print("SCC Hyperscale OpenShift Cluster Health Check Script")
    print("Version 1.0")
    print()
    print("Description:")
    print("This script performs comprehensive health checks on an OpenShift cluster,")
    print(
        "including resource quotas, security policies, and deployment configurations."
    )
    print()
    print("Author: Issam KLAI ( iklai@fr.scc.com)")
    print("Company: SCC Hyperscale")
    print()
    print("License: Proprietary and Confidential")
    print("This script is the intellectual property of SCC. Unauthorized copying,")
    print("modification, distribution, or use is strictly prohibited.")
    print()

    # Get current year
    import datetime

    current_year = datetime.datetime.now().year

    print(f"Copyright © {current_year} SCx. All rights reserved.")
    print()
    print("----------------------------------------")
    print()


def run_command(command):
    """Execute a shell command and return the output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()


def print_header(title):
    """Print a formatted header."""
    print(f"\n{'=' * 80}\n{title.center(80)}\n{'=' * 80}")


def truncate(string, length):
    """Truncate a string to a specific length."""
    return string[: length - 3] + "..." if len(string) > length else string


def print_color(color, text):
    """Print colored text."""
    colors = {
        "red": "\033[1;31m",
        "green": "\033[1;32m",
        "yellow": "\033[1;33m",
        "blue": "\033[1;34m",
        "magenta": "\033[1;35m",
        "cyan": "\033[1;36m",
        "default": "\033[0m",
    }
    print(f"{colors.get(color, '')}{text}{colors['default']}")


def get_cluster_info():
    """Retrieve and display cluster information."""
    print_header("Cluster Information")
    version = run_command(
        "oc get clusterversion -o jsonpath='{.items[0].status.desired.version}'"
    )
    channel = run_command(
        "oc get clusterversion -o jsonpath='{.items[0].spec.channel}'"
    )
    print_color("blue", f"Version: {version}")
    print_color("blue", f"Channel: {channel}")
    print_color("blue", "Upgrade history:")
    history = run_command(
        "oc get clusterversion -o jsonpath='{.items[0].status.history[*].completionTime}'"
    )
    for date in history.split():
        print(date[:10])


def get_nodes_info():
    """Retrieve and display node information."""
    print_header("Node Information")

    nodes = json.loads(run_command("oc get nodes -o json"))

    table = PrettyTable()
    table.field_names = ["Name", "Status", "Roles", "CPU", "Memory", "Architecture"]
    table.align = "l"  # Left-align text in columns

    for node in nodes["items"]:
        name = truncate(node["metadata"]["name"], 30)
        status = node["status"]["conditions"][-1]["type"]
        roles = truncate(
            ", ".join(
                [
                    key.split("/")[1]
                    for key in node["metadata"]["labels"]
                    if key.startswith("node-role.kubernetes.io")
                ]
            ),
            40,
        )
        cpu = node["status"]["capacity"]["cpu"]
        memory = node["status"]["capacity"]["memory"]
        arch = node["status"]["nodeInfo"]["architecture"]

        # Determine color based on status
        if status == "Ready":
            color = "green"
        elif status == "NotReady":
            color = "red"
        else:
            color = "yellow"

        table.add_row(
            [
                colored(name, color),
                colored(status, color),
                colored(roles, color),
                colored(cpu, color),
                colored(memory, color),
                colored(arch, color),
            ]
        )

    if nodes["items"]:
        print(f"Found {len(nodes['items'])} nodes:")
        print(table)
    else:
        print(colored("No nodes found in the cluster.", "yellow"))

    print("\nNode information retrieval complete.")


def get_network_info():
    """Retrieve and display network information."""
    print_header("Network Information")
    network = json.loads(run_command("oc get network.operator cluster -o json"))
    print_color(
        "blue", f"Cluster Network CIDR: {network['spec']['clusterNetwork'][0]['cidr']}"
    )
    print_color(
        "blue",
        f"Cluster Network Host Prefix: {network['spec']['clusterNetwork'][0]['hostPrefix']}",
    )
    print_color("blue", f"Network Type: {network['spec']['defaultNetwork']['type']}")
    print_color("blue", f"Service Network: {network['spec']['serviceNetwork'][0]}")


def get_storage_classes():
    """Retrieve and display storage class information."""
    print_header("Storage Classes")

    sc = json.loads(run_command("oc get storageclass -o json"))

    table = PrettyTable()
    table.field_names = [
        "Name",
        "Provisioner",
        "Reclaim Policy",
        "Volume Binding Mode",
        "Allow Volume Expansion",
    ]
    table.align = "l"  # Left-align text in columns

    for item in sc["items"]:
        name = truncate(item["metadata"]["name"], 30)
        provisioner = truncate(item["provisioner"], 30)
        reclaim_policy = item["reclaimPolicy"]
        volume_binding_mode = item.get("volumeBindingMode", "N/A")
        allow_volume_expansion = str(item.get("allowVolumeExpansion", False))

        # Determine color based on reclaim policy and volume binding mode
        if reclaim_policy == "Delete":
            color = "yellow"  # Potential data loss risk
        elif volume_binding_mode == "WaitForFirstConsumer":
            color = "green"  # Generally preferred for dynamic provisioning
        else:
            color = "cyan"  # Default color

        table.add_row(
            [
                colored(name, color),
                colored(provisioner, color),
                colored(reclaim_policy, color),
                colored(volume_binding_mode, color),
                colored(allow_volume_expansion, color),
            ]
        )

    if sc["items"]:
        print(f"Found {len(sc['items'])} storage classes:")
        print(table)
    else:
        print(colored("No storage classes found in the cluster.", "yellow"))

    print("\nStorage class information retrieval complete.")


def get_users_info():
    """Retrieve and display user information."""
    print_header("User Information")

    users = json.loads(run_command("oc get users -o json"))

    table = PrettyTable()
    table.field_names = ["Username", "UID", "Identity Provider", "Groups"]
    table.align = "l"  # Left-align text in columns

    for user in users["items"]:
        username = truncate(user["metadata"]["name"], 30)
        uid = truncate(user["metadata"]["uid"], 20)
        identity = truncate(user["identities"][0] if user["identities"] else "N/A", 30)

        # Handle 'groups' more carefully
        groups = user.get("groups", [])
        if not isinstance(groups, list):
            groups = [
                str(groups)
            ]  # Convert to a list with a single item if it's not already a list
        groups_str = truncate(", ".join(groups) if groups else "N/A", 40)

        # Color code based on whether the user has groups
        color = "green" if groups else "yellow"

        table.add_row(
            [
                colored(username, color),
                colored(uid, color),
                colored(identity, color),
                colored(groups_str, color),
            ]
        )

    if users["items"]:
        print(f"Found {len(users['items'])} users:")
        print(table)
    else:
        print(colored("No users found in the cluster.", "yellow"))

    print("\nUser information retrieval complete.")


def get_cluster_admins():
    """Retrieve and display cluster admin information."""
    print_header("Cluster Admins")

    admins = json.loads(run_command("oc get clusterrolebinding -o json"))

    table = PrettyTable()
    table.field_names = ["Kind", "Name", "Namespace"]
    table.align = "l"  # Left-align text in columns

    admin_count = 0
    for binding in admins["items"]:
        if binding["roleRef"]["name"] == "cluster-admin":
            for subject in binding["subjects"]:
                admin_count += 1
                kind = subject["kind"]
                name = subject["name"]
                namespace = subject.get("namespace", "N/A")

                # Color code based on kind
                if kind == "User":
                    color = "yellow"
                elif kind == "Group":
                    color = "blue"
                elif kind == "ServiceAccount":
                    color = "green"
                else:
                    color = "white"

                table.add_row(
                    [
                        colored(kind, color),
                        colored(name, color),
                        colored(namespace, color),
                    ]
                )

    if admin_count > 0:
        print(f"Found {admin_count} subjects with cluster-admin role:")
        print(table)
    else:
        print(colored("No subjects found with cluster-admin role.", "yellow"))

    print("\nCluster admin retrieval complete.")


def check_namespace_quotas():
    """Check ResourceQuotas and LimitRanges for all namespaces."""
    print_header("Checking ResourceQuotas and LimitRanges")

    namespaces = json.loads(run_command("oc get namespaces -o json"))

    table = PrettyTable()
    table.field_names = ["Namespace", "Resource Quota", "Limit Range"]
    table.align = "l"  # Left-align text in columns

    count_without_quota_or_limit = 0
    total_namespaces = 0

    for ns in namespaces["items"]:
        namespace = truncate(ns["metadata"]["name"], 40)

        if namespace.startswith("openshift-"):
            continue

        total_namespaces += 1

        quota = run_command(f"oc get resourcequota -n {namespace} -o name")
        limit = run_command(f"oc get limitrange -n {namespace} -o name")

        quota_status = "Set" if quota else "Not Set"
        limit_status = "Set" if limit else "Not Set"

        if quota_status == "Not Set" and limit_status == "Not Set":
            color = "yellow"
            count_without_quota_or_limit += 1
        else:
            color = "green"

        table.add_row(
            [
                colored(namespace, color),
                colored(quota_status, color),
                colored(limit_status, color),
            ]
        )

    if total_namespaces > 0:
        print(f"Checked {total_namespaces} namespaces:")
        print(table)
        print(
            f"\nNamespaces without ResourceQuota or LimitRange: {count_without_quota_or_limit}"
        )
        percentage = (count_without_quota_or_limit / total_namespaces) * 100
        print(f"Percentage: {percentage:.2f}%")
    else:
        print(colored("No user namespaces found in the cluster.", "yellow"))

    print("\nNamespace quota and limit range check complete.")


def check_scc_configuration():
    """Check Security Context Constraints (SCC) configuration."""
    print_header("Security Context Constraints (SCC) Configuration")
    sccs = json.loads(run_command("oc get scc -o json"))
    for scc in sccs["items"]:
        name = scc["metadata"]["name"]
        print(f"Analyzing SCC: {name}")
        if scc.get("allowPrivilegedContainer"):
            print_color("yellow", "  WARNING: allowPrivilegedContainer is set to true.")
        for field in ["allowHostPID", "allowHostIPC", "allowHostNetwork"]:
            if scc.get(field):
                print_color("yellow", f"  WARNING: {field} is set to true.")
        if scc["runAsUser"]["type"] == "RunAsAny":
            print_color("yellow", "  WARNING: runAsUser strategy is set to RunAsAny.")
        if scc["seLinuxContext"]["type"] == "RunAsAny":
            print_color(
                "yellow", "  WARNING: seLinuxContext strategy is set to RunAsAny."
            )
        print()


def check_pod_security():
    """Check for PodSecurityPolicy and PodSecurityAdmission configurations."""
    print_header("PodSecurityPolicy and PodSecurityAdmission Configurations")

    # Check for PodSecurityPolicies
    psp = run_command("oc get psp 2>/dev/null")
    if psp:
        print_color(
            "yellow",
            "WARNING: PodSecurityPolicies found. These are deprecated and will be removed in future Kubernetes versions.",
        )
        psp_table = PrettyTable()
        psp_table.field_names = ["Name", "Privileged"]
        for line in psp.strip().split("\n")[1:]:  # Skip header
            name, privileged = line.split()[:2]
            psp_table.add_row([name, privileged])
        print(psp_table)
    else:
        print("No PodSecurityPolicies found.")

    print("\nPodSecurityAdmission configurations:")
    psa = json.loads(run_command("oc get ns -o json"))
    psa_table = PrettyTable()
    psa_table.field_names = ["Namespace", "Enforce", "Audit", "Warn"]
    psa_table.align = "l"  # Left-align text in columns

    for ns in psa["items"]:
        name = ns["metadata"]["name"]
        annotations = ns["metadata"].get("annotations", {})
        enforce = annotations.get("pod-security.kubernetes.io/enforce", "Not set")
        audit = annotations.get("pod-security.kubernetes.io/audit", "Not set")
        warn = annotations.get("pod-security.kubernetes.io/warn", "Not set")
        psa_table.add_row([name, enforce, audit, warn])

    print(psa_table)

    # Check for cluster-wide PodSecurityAdmission configuration
    cluster_psa = run_command(
        "oc get kubeapiservers.operator.openshift.io cluster -o jsonpath='{.spec.observedConfig.admissionPluginConfig.PodSecurity}'"
    )
    if cluster_psa:
        print("\nCluster-wide PodSecurityAdmission configuration:")
        print(json.dumps(json.loads(cluster_psa), indent=2))
    else:
        print("\nNo cluster-wide PodSecurityAdmission configuration found.")


def check_cluster_operators():
    """Check and display the status of cluster operators."""
    print_header("Cluster Operators Status")

    operators = json.loads(run_command("oc get clusteroperators -o json"))

    table = PrettyTable()
    table.field_names = [
        "Name",
        "Version",
        "Available",
        "Progressing",
        "Degraded",
        "Since",
        "Message",
    ]
    table.align = "l"  # Left-align text in columns
    table.max_width["Message"] = 40  # Limit the width of the Message column

    for operator in operators["items"]:
        name = operator["metadata"]["name"]
        version = operator["status"].get("versions", [{}])[0].get("version", "N/A")

        conditions = {cond["type"]: cond for cond in operator["status"]["conditions"]}
        available = conditions["Available"]["status"]
        progressing = conditions["Progressing"]["status"]
        degraded = conditions["Degraded"]["status"]

        # Get the most recent transition time
        since = max(
            cond["lastTransitionTime"] for cond in operator["status"]["conditions"]
        )

        # Get the message from the most relevant condition
        message = ""
        if degraded == "True":
            message = conditions["Degraded"].get("message", "No message available")
        elif progressing == "True":
            message = conditions["Progressing"].get("message", "No message available")
        elif available == "True":
            message = conditions["Available"].get("message", "No message available")
        else:
            message = "No relevant message found"

        # Determine row color
        if degraded == "True":
            color = "red"
        elif progressing == "True":
            color = "yellow"
        elif available != "True":
            color = "yellow"
        else:
            color = "green"

        # Add colored row to table
        table.add_row(
            [
                colored(name, color),
                colored(version, color),
                colored(available, color),
                colored(progressing, color),
                colored(degraded, color),
                colored(since, color),
                colored(message[:40] + ("..." if len(message) > 40 else ""), color),
            ]
        )

    print(table)
    print("\nCluster operator status check complete.")


def check_image_config():
    """Check Image Configuration for allowed and insecure registries."""
    print_header("Image Configuration")
    config = json.loads(run_command("oc get image.config.openshift.io/cluster -o json"))
    print_color("blue", "Allowed Registries for Import:")
    for reg in config["spec"].get("allowedRegistriesForImport", []):
        print(f"  - {reg['domainName']} (Insecure: {reg.get('insecure', False)})")

    print_color("blue", "\nAllowed Registries:")
    for reg in config["spec"].get("registrySources", {}).get("allowedRegistries", []):
        print(f"  - {reg}")

    print_color("blue", "\nInsecure Registries:")
    for reg in config["spec"].get("registrySources", {}).get("insecureRegistries", []):
        print(f"  - {reg}")


def check_monitoring_logging():
    """Check monitoring and logging configurations."""
    print_header("Monitoring and Logging Configuration")
    monitoring = run_command("oc get clusteroperator monitoring")
    if "True" in monitoring:
        print_color("green", "Cluster Monitoring: Enabled")
    else:
        print_color("red", "Cluster Monitoring: Not enabled")

    logging = run_command("oc get clusterlogging instance -n openshift-logging")
    if logging:
        print_color("green", "Cluster Logging: Installed")
        print("ClusterLogging configuration:")
        print(
            run_command("oc get clusterlogging instance -n openshift-logging -o yaml")
        )
    else:
        print_color("red", "Cluster Logging: Not installed")


def check_routes_info():
    """Retrieve and display routes information."""
    print_header("Routes Information")

    routes = json.loads(run_command("oc get route -A -o json"))

    table = PrettyTable()
    table.field_names = ["Namespace", "Name", "Host", "TLS", "Path", "Service"]
    table.align = "l"  # Left-align text in columns

    for route in routes["items"]:
        ns = truncate(route["metadata"]["namespace"], 20)
        name = truncate(route["metadata"]["name"], 30)
        host = truncate(route["spec"].get("host", "N/A"), 40)
        tls = "Secured" if "tls" in route["spec"] else "Not Secured"
        path = route["spec"].get("path", "/")
        service = truncate(route["spec"].get("to", {}).get("name", "N/A"), 30)

        color = "green" if tls == "Secured" else "yellow"

        table.add_row(
            [
                colored(ns, color),
                colored(name, color),
                colored(host, color),
                colored(tls, color),
                colored(path, color),
                colored(service, color),
            ]
        )

    if routes["items"]:
        print(f"Found {len(routes['items'])} routes:")
        print(table)

        # Summary
        secured_routes = sum(1 for route in routes["items"] if "tls" in route["spec"])
        print(f"\nSummary:")
        print(f"Total routes: {len(routes['items'])}")
        print(f"Secured routes: {secured_routes}")
        print(f"Unsecured routes: {len(routes['items']) - secured_routes}")
    else:
        print(colored("No routes found in the cluster.", "yellow"))

    print("\nRoutes information check complete.")


def check_deployment_resources():
    """Check resource definitions for all deployments."""
    print_header("Deployment Resource Definitions")

    deployments = json.loads(run_command("oc get deployments --all-namespaces -o json"))

    table = PrettyTable()
    table.field_names = [
        "Namespace",
        "Deployment",
        "CPU Request",
        "CPU Limit",
        "Memory Request",
        "Memory Limit",
    ]
    table.align = "l"  # Left-align text in columns

    total = 0
    configured = 0

    for dep in deployments["items"]:
        ns = dep["metadata"]["namespace"]
        if ns.startswith("openshift-"):
            continue

        name = truncate(dep["metadata"]["name"], 30)
        resources = dep["spec"]["template"]["spec"]["containers"][0].get(
            "resources", {}
        )
        cpu_req = resources.get("requests", {}).get("cpu", "Not Set")
        cpu_lim = resources.get("limits", {}).get("cpu", "Not Set")
        mem_req = resources.get("requests", {}).get("memory", "Not Set")
        mem_lim = resources.get("limits", {}).get("memory", "Not Set")

        total += 1
        if "Not Set" not in [cpu_req, cpu_lim, mem_req, mem_lim]:
            configured += 1
            color = "green"
        else:
            color = "yellow"

        table.add_row(
            [
                colored(truncate(ns, 20), color),
                colored(name, color),
                colored(cpu_req, color),
                colored(cpu_lim, color),
                colored(mem_req, color),
                colored(mem_lim, color),
            ]
        )

    if total > 0:
        print(f"Analyzed {total} deployments:")
        print(table)

        ratio = configured / total
        percentage = ratio * 100
        print(f"\nDeployments with all resources configured: {configured}/{total}")
        print(f"Ratio: {ratio:.2f} ({percentage:.2f}%)")
    else:
        print(colored("No user deployments found in the cluster.", "yellow"))

    print("\nDeployment resource check complete.")


def check_hpa_configurations():
    """Check HorizontalPodAutoscaler configurations for all deployments."""
    print_header("HorizontalPodAutoscaler Configurations")
    hpas = json.loads(run_command("oc get hpa --all-namespaces -o json"))
    print(
        f"{'NAME':<30} {'NAMESPACE':<20} {'DEPLOYMENT':<30} {'MIN':<5} {'MAX':<5} {'CURRENT':<8} {'TARGET CPU':<10}"
    )
    print("-" * 110)
    for hpa in hpas["items"]:
        name = hpa["metadata"]["name"]
        ns = hpa["metadata"]["namespace"]
        deployment = hpa["spec"]["scaleTargetRef"]["name"]
        min_replicas = hpa["spec"]["minReplicas"]
        max_replicas = hpa["spec"]["maxReplicas"]
        current_replicas = hpa["status"].get("currentReplicas", "N/A")
        target_cpu = next(
            (
                m["resource"]["target"]["averageUtilization"]
                for m in hpa["spec"]["metrics"]
                if m["type"] == "Resource" and m["resource"]["name"] == "cpu"
            ),
            "N/A",
        )
        print(
            f"{name:<30} {ns:<20} {deployment:<30} {min_replicas:<5} {max_replicas:<5} {current_replicas:<8} {target_cpu:<10}"
        )


def check_network_policies():
    """Check NetworkPolicies for all deployments."""
    print_header("NetworkPolicies for Deployments")
    namespaces = run_command("oc get namespaces -o name").split()
    print(
        f"{'NAMESPACE':<30} {'DEPLOYMENT':<30} {'POLICY':<30} {'INGRESS':<15} {'EGRESS':<15}"
    )
    print("-" * 120)
    total_deployments = 0
    deployments_with_policies = 0
    for ns in namespaces:
        ns = ns.split("/")[1]
        if ns.startswith("openshift-"):
            continue
        deployments = run_command(f"oc get deployments -n {ns} -o name").split()
        for dep in deployments:
            dep = dep.split("/")[1]
            total_deployments += 1
            policies = run_command(f"oc get networkpolicies -n {ns} -o name").split()
            if policies:
                deployments_with_policies += 1
                for policy in policies:
                    policy = policy.split("/")[1]
                    policy_yaml = yaml.safe_load(
                        run_command(f"oc get networkpolicy {policy} -n {ns} -o yaml")
                    )
                    ingress = "Yes" if "ingress" in policy_yaml["spec"] else "No"
                    egress = "Yes" if "egress" in policy_yaml["spec"] else "No"
                    print(f"{ns:<30} {dep:<30} {policy:<30} {ingress:<15} {egress:<15}")
            else:
                print_color(
                    "yellow",
                    f"{ns:<30} {dep:<30} {'No Policy':<30} {'N/A':<15} {'N/A':<15}",
                )
    print(f"\nTotal deployments: {total_deployments}")
    print(f"Deployments with NetworkPolicies: {deployments_with_policies}")
    print(
        f"Deployments without NetworkPolicies: {total_deployments - deployments_with_policies}"
    )


def check_service_mesh():
    """Check for Istio/Service Mesh installation and configuration."""
    print_header("Service Mesh Information")
    istio_ns = run_command("oc get namespace istio-system --no-headers")
    if istio_ns:
        print_color("green", "Istio/Service Mesh is installed")
        print_color("cyan", "Applications using Istio:")
        namespaces = run_command(
            "oc get namespace -l istio-injection=enabled -o name"
        ).split()
        for ns in namespaces:
            ns = ns.split("/")[1]
            print_color("yellow", f"  Namespace: {ns}")
            deployments = run_command(
                f"oc get deployment -n {ns} -l 'istio=sidecar-injector' -o name"
            ).split()
            for dep in deployments:
                dep = dep.split("/")[1]
                print_color("magenta", f"    Deployment: {dep}")
    else:
        print_color("red", "Istio/Service Mesh is not installed")


def check_image_streams():
    """Check and display information about ImageStreams."""
    print_header("ImageStream Information")

    try:
        image_streams = json.loads(
            run_command("oc get imagestreams --all-namespaces -o json")
        )
    except Exception as e:
        print(colored(f"Error fetching ImageStreams: {str(e)}", "red"))
        return

    print(f"{'NAMESPACE':<30} {'NAME':<30} {'DOCKER REPO':<50} {'TAGS':<20}")
    print("-" * 130)

    for is_item in image_streams["items"]:
        ns = is_item["metadata"]["namespace"]
        name = is_item["metadata"]["name"]
        repo = is_item.get("status", {}).get("dockerImageRepository", "N/A")
        tags = is_item.get("status", {}).get("tags", [])
        tag_names = ", ".join(tag["tag"] for tag in tags) if tags else "N/A"

        print(f"{ns:<30} {name:<30} {repo:<50} {tag_names:<20}")


def check_persistent_volumes():
    """Check and display information about PersistentVolumes."""
    print_header("PersistentVolume Information")

    pvs = json.loads(run_command("oc get pv -o json"))

    table = PrettyTable()
    table.field_names = [
        "Name",
        "Capacity",
        "Access Modes",
        "Reclaim Policy",
        "Status",
        "Claim",
        "Storage Class",
    ]
    table.align = "l"  # Left-align text in columns

    for pv in pvs["items"]:
        name = truncate(pv["metadata"]["name"], 40)
        capacity = pv["spec"]["capacity"]["storage"]
        access_modes = ",".join(pv["spec"]["accessModes"])
        reclaim_policy = pv["spec"]["persistentVolumeReclaimPolicy"]
        status = pv["status"]["phase"]
        claim = truncate(pv["spec"].get("claimRef", {}).get("name", "N/A"), 20)
        storage_class = pv["spec"].get("storageClassName", "N/A")

        # Determine color based on status and reclaim policy
        if status == "Bound":
            color = "green"
        elif status == "Available":
            color = "cyan"
        elif status == "Released":
            color = "yellow"
        else:
            color = "red"

        # Adjust color if reclaim policy is Delete (potential data loss risk)
        if reclaim_policy == "Delete":
            color = "yellow"

        table.add_row(
            [
                colored(name, color),
                colored(capacity, color),
                colored(access_modes, color),
                colored(reclaim_policy, color),
                colored(status, color),
                colored(claim, color),
                colored(storage_class, color),
            ]
        )

    if pvs["items"]:
        print(f"Found {len(pvs['items'])} PersistentVolumes:")
        print(table)

        # Summary
        bound_pvs = sum(1 for pv in pvs["items"] if pv["status"]["phase"] == "Bound")
        available_pvs = sum(
            1 for pv in pvs["items"] if pv["status"]["phase"] == "Available"
        )
        released_pvs = sum(
            1 for pv in pvs["items"] if pv["status"]["phase"] == "Released"
        )
        delete_policy_pvs = sum(
            1
            for pv in pvs["items"]
            if pv["spec"]["persistentVolumeReclaimPolicy"] == "Delete"
        )

        print("\nSummary:")
        print(f"Bound PVs: {bound_pvs}")
        print(f"Available PVs: {available_pvs}")
        print(f"Released PVs: {released_pvs}")
        print(f"PVs with Delete reclaim policy: {delete_policy_pvs}")
    else:
        print(colored("No PersistentVolumes found in the cluster.", "yellow"))

    print("\nPersistentVolume check complete.")


def check_etcd_backup():
    """Check for etcd backup configuration."""
    print_header("etcd Backup Configuration")
    etcd_backup = run_command("oc get cronjob -n openshift-etcd etcd-backup -o yaml")
    if etcd_backup:
        print_color("green", "etcd backup cronjob found")
        backup_config = yaml.safe_load(etcd_backup)
        schedule = backup_config["spec"]["schedule"]
        print(f"Backup schedule: {schedule}")
    else:
        print_color("red", "No etcd backup cronjob found")


def check_alerts_receivers():
    """Check and display Alertmanager receivers configuration."""
    print_header("Alertmanager Receivers Configuration")
    secret = run_command(
        "oc -n openshift-monitoring get secret alertmanager-main --template='{{ index .data \"alertmanager.yaml\" }}'"
    )
    if secret:
        config = yaml.safe_load(base64.b64decode(secret))
        receivers = config.get("receivers", [])
        for receiver in receivers:
            print_color("cyan", f"Receiver: {receiver['name']}")
            if "pagerduty_configs" in receiver:
                print_color("yellow", "  PagerDuty configured")
            if "email_configs" in receiver:
                print_color("yellow", "  Email configured")
                for email_config in receiver["email_configs"]:
                    print_color("blue", f"    To: {email_config.get('to', 'N/A')}")
            if "webhook_configs" in receiver:
                print_color("yellow", "  Webhook configured")
                for webhook_config in receiver["webhook_configs"]:
                    print_color("blue", f"    URL: {webhook_config.get('url', 'N/A')}")
            if "slack_configs" in receiver:
                print_color("yellow", "  Slack configured")
                for slack_config in receiver["slack_configs"]:
                    print_color(
                        "blue", f"    Channel: {slack_config.get('channel', 'N/A')}"
                    )
            print()
    else:
        print_color("red", "No Alertmanager configuration found")


def check_cluster_monitoring_config():
    """Analyze cluster monitoring configuration."""
    print_header("Cluster Monitoring Configuration Analysis")
    config = run_command(
        "oc get configmap cluster-monitoring-config -n openshift-monitoring -o jsonpath='{.data.config\.yaml}'"
    )
    if config:
        config = yaml.safe_load(config)
        components = [
            "prometheusK8s",
            "alertmanagerMain",
            "prometheusOperator",
            "kubeStateMetrics",
            "telemeterClient",
            "openshiftStateMetrics",
            "thanosQuerier",
        ]
        for component in components:
            print_color("cyan", f"Checking component: {component}")
            comp_config = config.get(component, {})
            if "volumeClaimTemplate" in comp_config:
                print_color("green", "  ✓ volumeClaimTemplate found")
            else:
                print_color("red", "  ✗ volumeClaimTemplate not found")
            if (
                comp_config.get("nodeSelector", {}).get("node-role.kubernetes.io/infra")
                == ""
            ):
                print_color("green", "  ✓ nodeSelector for infra nodes found")
            else:
                print_color("red", "  ✗ nodeSelector for infra nodes not found")
            if any(
                "node-role.kubernetes.io/infra" in t.get("key", "")
                for t in comp_config.get("tolerations", [])
            ):
                print_color("green", "  ✓ Tolerations for infra nodes found")
            else:
                print_color("red", "  ✗ Tolerations for infra nodes not found")
            print()
        retention = config.get("prometheusK8s", {}).get("retention", "N/A")
        print_color("cyan", f"Retention period: {retention}")
    else:
        print_color("red", "No cluster monitoring configuration found")


def check_log_forwarding():
    """Detect log forwarding configurations in OpenShift logging stack."""
    print_header("Log Forwarding Configuration")
    if run_command("oc get csv -n openshift-logging | grep loki"):
        print_color("green", "Loki Operator is installed")
    else:
        print_color(
            "red", "Loki Operator not found. Logging stack may not be Loki-based."
        )
        return

    cl_forwarding = run_command(
        "oc get clusterlogging instance -n openshift-logging -o jsonpath='{.spec.forwardingSpec}'"
    )
    if cl_forwarding:
        print("ForwardingSpec found in ClusterLogging:")
        print(json.dumps(json.loads(cl_forwarding), indent=2))
    else:
        print("No ForwardingSpec found in ClusterLogging")

    clf_outputs = run_command(
        "oc get clusterlogforwarder instance -n openshift-logging -o jsonpath='{.spec.outputs}'"
    )
    if clf_outputs:
        print("Outputs found in ClusterLogForwarder:")
        print(json.dumps(json.loads(clf_outputs), indent=2))
    else:
        print("No outputs found in ClusterLogForwarder")


def check_metallb_configuration():
    """Check MetalLB installation and configuration."""
    print_header("MetalLB Configuration")
    if not run_command("oc get csv -n openshift-operators | grep metallb"):
        print_color("red", "MetalLB operator is not installed")
        return

    metallb_cr = run_command("oc get metallb -n openshift-metallb -o json")
    if not metallb_cr:
        print_color("red", "MetalLB Custom Resource not found")
        return

    metallb = json.loads(metallb_cr)
    strict_arp = metallb["items"][0]["spec"].get("strictARP", False)
    print_color("green" if strict_arp else "red", f"strictARP is set to {strict_arp}")

    lb_class = metallb["items"][0]["spec"].get("loadBalancerClass", "not set")
    print(f"LoadBalancerClass: {lb_class}")

    address_pools = json.loads(
        run_command("oc get addresspool -n openshift-metallb -o json")
    )
    if address_pools["items"]:
        print(f"Found {len(address_pools['items'])} AddressPool(s):")
        for pool in address_pools["items"]:
            print(
                f"  - Name: {pool['metadata']['name']}, Protocol: {pool['spec']['protocol']}, Addresses: {pool['spec']['addresses']}"
            )
    else:
        print_color("red", "No AddressPool resources found")


def check_webhook_configurations():
    """List MutatingWebhookConfigurations and ValidatingWebhookConfigurations."""
    print_header("Webhook Configurations")
    for webhook_type in [
        "mutatingwebhookconfigurations",
        "validatingwebhookconfigurations",
    ]:
        print(f"\n{webhook_type.capitalize()}:")
        webhooks = json.loads(run_command(f"oc get {webhook_type} -o json"))
        for webhook in webhooks["items"]:
            print(f"Name: {webhook['metadata']['name']}")
            for wh in webhook["webhooks"]:
                print(f"  - Webhook: {wh['name']}")
                print(f"    ClientConfig:")
                if "url" in wh["clientConfig"]:
                    print(f"      URL: {wh['clientConfig']['url']}")
                elif "service" in wh["clientConfig"]:
                    svc = wh["clientConfig"]["service"]
                    print(f"      Service: {svc['name']}/{svc['namespace']}")
                    print(f"      Path: {svc.get('path', 'N/A')}")
                print(f"    Rules:")
                for rule in wh["rules"]:
                    print(f"      - API Groups: {rule.get('apiGroups', ['*'])}")
                    print(f"        API Versions: {rule.get('apiVersions', ['*'])}")
                    print(f"        Resources: {rule.get('resources', ['*'])}")
                    print(f"        Operations: {rule.get('operations', ['*'])}")


def check_pod_disruption_budgets():
    """List all PodDisruptionBudgets in the cluster."""
    print_header("PodDisruptionBudgets")

    pdbs = json.loads(
        run_command("oc get poddisruptionbudgets --all-namespaces -o json")
    )

    table = PrettyTable()
    table.field_names = [
        "Namespace",
        "Name",
        "Min Available",
        "Max Unavailable",
        "Allowed Disruptions",
        "Current Healthy",
        "Desired Healthy",
    ]
    table.align = "l"  # Left-align text in columns

    for pdb in pdbs["items"]:
        namespace = truncate(pdb["metadata"]["namespace"], 40)
        name = truncate(pdb["metadata"]["name"], 30)
        min_available = pdb["spec"].get("minAvailable", "N/A")
        max_unavailable = pdb["spec"].get("maxUnavailable", "N/A")
        allowed_disruptions = pdb["status"].get("disruptionsAllowed", "N/A")
        current_healthy = pdb["status"].get("currentHealthy", "N/A")
        desired_healthy = pdb["status"].get("desiredHealthy", "N/A")

        # Determine color based on PDB status
        if allowed_disruptions == 0:
            color = "red"  # No disruptions allowed, might indicate issues
        elif allowed_disruptions == "N/A":
            color = "yellow"  # Status unknown
        else:
            color = "green"  # Disruptions allowed, normal state

        table.add_row(
            [
                colored(namespace, color),
                colored(name, color),
                colored(str(min_available), color),
                colored(str(max_unavailable), color),
                colored(str(allowed_disruptions), color),
                colored(str(current_healthy), color),
                colored(str(desired_healthy), color),
            ]
        )

    if pdbs["items"]:
        print(f"Found {len(pdbs['items'])} PodDisruptionBudgets:")
        print(table)
    else:
        print(colored("No PodDisruptionBudgets found in the cluster.", "yellow"))

    print("\nPodDisruptionBudget check complete.")


def check_kyverno_policies():
    """List all Kyverno policies and exceptions in the cluster."""
    print_header("Kyverno Policies and Exceptions")
    if not run_command("oc get crd policies.kyverno.io"):
        print_color(
            "red", "Kyverno CRDs not found. Is Kyverno installed on this cluster?"
        )
        return

    for policy_type in ["clusterpolicies", "policies"]:
        policies = json.loads(
            run_command(f"oc get {policy_type} --all-namespaces -o json")
        )
        print(f"\n{policy_type.capitalize()}:")
        print(
            f"{'NAMESPACE':<20} {'NAME':<30} {'BACKGROUND':<15} {'VALIDATION FAILURE':<20} {'MESSAGE':<50}"
        )
        print("-" * 140)
        for policy in policies["items"]:
            ns = policy["metadata"].get("namespace", "cluster-wide")
            name = policy["metadata"]["name"]
            background = policy["spec"].get("background", "N/A")
            validation_failure = policy["spec"].get("validationFailureAction", "N/A")
            message = (
                policy["spec"]["rules"][0].get("validate", {}).get("message", "N/A")
            )
            print(
                f"{ns:<20} {name:<30} {background:<15} {validation_failure:<20} {message[:47] + '...' if len(message) > 50 else message:<50}"
            )

    exceptions = json.loads(
        run_command("oc get policyexceptions --all-namespaces -o json")
    )
    print("\nPolicyExceptions:")
    print(f"{'NAMESPACE':<20} {'NAME':<30} {'POLICIES':<50}")
    print("-" * 100)
    for exception in exceptions["items"]:
        ns = exception["metadata"]["namespace"]
        name = exception["metadata"]["name"]
        policies = ", ".join([e["policyName"] for e in exception["spec"]["exceptions"]])
        print(
            f"{ns:<20} {name:<30} {policies[:47] + '...' if len(policies) > 50 else policies:<50}"
        )


def check_tls_secrets():
    """Check TLS secrets across all namespaces for expiration."""
    print_header("TLS Secrets Expiration Check")

    secrets = json.loads(run_command("oc get secrets --all-namespaces -o json"))

    table = PrettyTable()
    table.field_names = ["Namespace", "Name", "Not Before", "Not After", "Status"]
    table.align = "l"  # Left-align text in columns

    current_time = datetime.now()

    for secret in secrets["items"]:
        if secret["type"] == "kubernetes.io/tls":
            ns = truncate(secret["metadata"]["namespace"], 20)
            name = truncate(secret["metadata"]["name"], 30)

            try:
                cert_data = base64.b64decode(secret["data"]["tls.crt"])
                cert_info = run_command(
                    f"openssl x509 -noout -dates -subject <<< '{cert_data.decode()}'"
                )

                not_before = next(
                    line.split("=")[1]
                    for line in cert_info.split("\n")
                    if line.startswith("notBefore")
                )
                not_after = next(
                    line.split("=")[1]
                    for line in cert_info.split("\n")
                    if line.startswith("notAfter")
                )

                not_before_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                not_after_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")

                if current_time > not_after_date:
                    status = "EXPIRED"
                    color = "red"
                elif current_time < not_before_date:
                    status = "NOT YET VALID"
                    color = "yellow"
                else:
                    status = "VALID"
                    color = "green"

                table.add_row(
                    [
                        colored(ns, color),
                        colored(name, color),
                        colored(not_before_date.strftime("%Y-%m-%d"), color),
                        colored(not_after_date.strftime("%Y-%m-%d"), color),
                        colored(status, color),
                    ]
                )
            except Exception as e:
                table.add_row(
                    [
                        colored(ns, "red"),
                        colored(name, "red"),
                        colored("ERROR", "red"),
                        colored("ERROR", "red"),
                        colored(f"INVALID CERT: {str(e)}", "red"),
                    ]
                )

    if table._rows:
        print(f"Found {len(table._rows)} TLS secrets:")
        print(table)

        # Summary
        valid_certs = sum(1 for row in table._rows if "VALID" in row[-1])
        expired_certs = sum(1 for row in table._rows if "EXPIRED" in row[-1])
        invalid_certs = sum(1 for row in table._rows if "INVALID" in row[-1])

        print(f"\nSummary:")
        print(f"Total TLS secrets: {len(table._rows)}")
        print(f"Valid certificates: {valid_certs}")
        print(f"Expired certificates: {expired_certs}")
        print(f"Invalid certificates: {invalid_certs}")
    else:
        print(colored("No TLS secrets found in the cluster.", "yellow"))

    print("\nTLS secret expiration check complete.")


def check_kasten_configuration():
    """Check Kasten K10 configuration and backups."""
    print_header("Kasten K10 Configuration and Backups")

    # Check if Kasten is installed
    if not run_command("oc get namespace kasten-io"):
        print_color(
            "red",
            "Error: Kasten K10 namespace not found. Is Kasten installed on this cluster?",
        )
        return

    # Get K10 version
    k10_version = run_command(
        "oc get deployment k10-deployment -n kasten-io -o jsonpath='{.spec.template.spec.containers[0].image}'"
    ).split(":")[-1]
    print(f"Kasten K10 Version: {k10_version}")

    # Check storage backend
    print("\nStorage Backend Configuration:")
    profiles = json.loads(
        run_command("oc get profiles.config.kio.kasten.io -n kasten-io -o json")
    )
    for profile in profiles["items"]:
        print(f"Name: {profile['metadata']['name']}")
        print(f"Type: {profile['spec']['type']}")
        print(f"Location: {profile['spec']['location']}")

    # List recent snapshots
    print("\nRecent Snapshots:")
    snapshots = json.loads(
        run_command("oc get snapshots.k10.kasten.io --all-namespaces -o json")
    )
    for snapshot in snapshots["items"][:5]:  # Show only the 5 most recent snapshots
        print(f"Namespace: {snapshot['metadata']['namespace']}")
        print(f"Name: {snapshot['metadata']['name']}")
        print(f"Creation Time: {snapshot['metadata']['creationTimestamp']}")

    # List recent VolumeSnapshots
    print("\nRecent VolumeSnapshots:")
    volume_snapshots = json.loads(
        run_command("oc get volumesnapshots --all-namespaces -o json")
    )
    for vs in volume_snapshots["items"][
        :5
    ]:  # Show only the 5 most recent volume snapshots
        print(f"Namespace: {vs['metadata']['namespace']}")
        print(f"Name: {vs['metadata']['name']}")
        print(f"Creation Time: {vs['metadata']['creationTimestamp']}")
        print(f"Source PVC: {vs['spec']['source']['persistentVolumeClaimName']}")

    # List backup schedules
    print("\nBackup Schedules:")
    policies = json.loads(
        run_command("oc get policies.config.kio.kasten.io --all-namespaces -o json")
    )
    for policy in policies["items"]:
        print(f"Name: {policy['metadata']['name']}")
        print(f"Namespace: {policy['metadata']['namespace']}")
        print(f"Schedule: {policy['spec']['schedule']['cron']}")
        retention = policy["spec"]["retention"]
        print(
            f"Retention: {retention['hourly']} hourly, {retention['daily']} daily, {retention['weekly']} weekly, {retention['monthly']} monthly, {retention['yearly']} yearly"
        )


def get_infrastructure_details():
    """Retrieve and display infrastructure details."""
    print_header("Infrastructure Details")
    infra = json.loads(run_command("oc get infrastructure cluster -o json"))

    print(f"Platform: {infra['status']['platform']}")
    print(f"Infrastructure Name: {infra['status']['infrastructureName']}")
    print(f"Control Plane Topology: {infra['status']['controlPlaneTopology']}")
    print(f"Infrastructure Topology: {infra['status']['infrastructureTopology']}")

    if "platformStatus" in infra["status"]:
        platform_status = infra["status"]["platformStatus"]
        if "aws" in platform_status:
            print("\nAWS Specific Details:")
            print(f"Region: {platform_status['aws']['region']}")
        elif "azure" in platform_status:
            print("\nAzure Specific Details:")
            print(f"Resource Group: {platform_status['azure']['resourceGroupName']}")
        # Add more platform-specific details as needed


def classify_images_by_registry():
    """Classify images by source registry."""
    print_header("Image Classification by Registry")

    images = json.loads(run_command("oc get images -o json"))
    registry_counts = {}

    for image in images["items"]:
        registry = image["dockerImageReference"].split("/")[0].split(":")[0]
        registry_counts[registry] = registry_counts.get(registry, 0) + 1

    print(f"{'REGISTRY':<50} {'COUNT':<10}")
    print("-" * 60)
    for registry, count in sorted(
        registry_counts.items(), key=lambda x: x[1], reverse=True
    ):
        print(f"{registry:<50} {count:<10}")

    # Check for ImageContentSourcePolicy
    print("\nChecking ImageContentSourcePolicy...")
    icsp = json.loads(run_command("oc get imagecontentsourcepolicy -o json"))
    if icsp["items"]:
        for policy in icsp["items"]:
            print(f"Name: {policy['metadata']['name']}")
            for mirror in policy["spec"]["repositoryDigestMirrors"]:
                print(f"  Source: {mirror['source']}")
                print(f"  Mirrors: {', '.join(mirror['mirrors'])}")
    else:
        print("No ImageContentSourcePolicy found.")


def get_proxy_details():
    """Retrieve and display proxy details."""
    print_header("Proxy Configuration")

    proxy = json.loads(run_command("oc get proxy cluster -o json"))
    if "spec" in proxy:
        print(f"HTTP Proxy: {proxy['spec'].get('httpProxy', 'Not set')}")
        print(f"HTTPS Proxy: {proxy['spec'].get('httpsProxy', 'Not set')}")
        print(f"No Proxy: {proxy['spec'].get('noProxy', 'Not set')}")
    else:
        print_color("yellow", "No proxy configuration found.")


def get_registry_config():
    """Retrieve and display image registry configuration."""
    print_header("Image Registry Configuration")

    config = json.loads(
        run_command(
            "oc get configs.imageregistry.operator.openshift.io/cluster -o json"
        )
    )
    print(f"Management State: {config['spec']['managementState']}")
    print(f"Default Route: {config['spec'].get('defaultRoute', False)}")
    print(f"Replicas: {config['spec'].get('replicas', 1)}")

    if "storage" in config["spec"]:
        storage = config["spec"]["storage"]
        print("\nStorage Configuration:")
        for key, value in storage.items():
            print(f"  {key}: {value}")


def get_certificate_status():
    """Retrieve and display cluster certificate status."""
    print_header("Cluster Certificate Status")

    certs = json.loads(run_command("oc get certificatesigningrequests -o json"))
    print(f"{'NAME':<40} {'STATUS':<15} {'SIGNER':<30}")
    print("-" * 85)
    for cert in certs["items"]:
        name = cert["metadata"]["name"]
        status = cert["status"].get("conditions", [{}])[-1].get("type", "Unknown")
        signer = cert["spec"].get("signerName", "Unknown")
        print(f"{name:<40} {status:<15} {signer:<30}")


def get_identityProvider_details():
    """Retrieve and display identity provider details."""
    print_header("Identity Provider Configuration")

    oauth = json.loads(run_command("oc get oauth cluster -o json"))
    idps = oauth["spec"].get("identityProviders", [])

    if not idps:
        print("No identity providers configured.")
        return

    for idp in idps:
        print(f"Name: {idp['name']}")
        print(f"Type: {idp['type']}")
        print(f"Mapping Method: {idp['mappingMethod']}")
        print("Provider Specific Config:")

        # Get the provider-specific configuration
        provider_config = idp.get(idp["type"].lower(), {})
        if not provider_config:
            print("  No provider-specific configuration found.")
        else:
            for key, value in provider_config.items():
                print(f"  {key}: {value}")

        print()  # Add a blank line between providers


def get_top_nodes():
    """Display top nodes by CPU and memory usage."""
    print_header("Top Nodes (CPU and Memory Usage)")

    nodes = run_command("oc adm top nodes").split("\n")[1:]  # Skip header
    print(
        f"{'NAME':<30} {'CPU(cores)':<12} {'CPU%':<8} {'MEMORY(bytes)':<15} {'MEMORY%':<8}"
    )
    print("-" * 80)
    for node in nodes:
        parts = node.split()
        name, cpu_cores, cpu_percent, memory_bytes, memory_percent = parts
        color = (
            "red"
            if float(cpu_percent[:-1]) > 80 or float(memory_percent[:-1]) > 80
            else "default"
        )
        print_color(
            color,
            f"{name:<30} {cpu_cores:<12} {cpu_percent:<8} {memory_bytes:<15} {memory_percent:<8}",
        )


def list_subscriptions():
    """List all subscriptions in the OpenShift cluster."""
    print_header("Cluster Subscriptions")

    subs = json.loads(run_command("oc get subscriptions --all-namespaces -o json"))
    print(
        f"{'NAMESPACE':<20} {'NAME':<30} {'PACKAGE':<30} {'CHANNEL':<20} {'SOURCE':<30}"
    )
    print("-" * 130)
    for sub in subs["items"]:
        ns = sub["metadata"]["namespace"]
        name = sub["metadata"]["name"]
        package = sub["spec"]["name"]
        channel = sub["spec"].get("channel", "N/A")
        source = sub["spec"]["source"]
        print(f"{ns:<20} {name:<30} {package:<30} {channel:<20} {source:<30}")


def get_ingress_info():
    """Retrieve and display ingress information."""
    print_header("Ingress Information")

    ingresses = json.loads(run_command("oc get ingress --all-namespaces -o json"))
    print(f"{'NAMESPACE':<20} {'NAME':<30} {'HOSTS':<50}")
    print("-" * 100)
    for ingress in ingresses["items"]:
        ns = ingress["metadata"]["namespace"]
        name = ingress["metadata"]["name"]
        hosts = ", ".join(
            [rule.get("host", "N/A") for rule in ingress["spec"].get("rules", [])]
        )
        print(f"{ns:<20} {name:<30} {hosts:<50}")


def analyze_deployments_security():
    """Analyze deployment configurations for security settings."""
    print_header("Deployment Security Analysis")

    deployments = json.loads(run_command("oc get deployments --all-namespaces -o json"))
    print(
        f"{'NAMESPACE':<20} {'DEPLOYMENT':<30} {'PRIVILEGED':<15} {'READ_ONLY_ROOT_FS':<20} {'RUN_AS_NON_ROOT':<20}"
    )
    print("-" * 105)
    for dep in deployments["items"]:
        ns = dep["metadata"]["namespace"]
        name = dep["metadata"]["name"]
        containers = dep["spec"]["template"]["spec"]["containers"]
        privileged = any(
            c.get("securityContext", {}).get("privileged", False) for c in containers
        )
        read_only_root_fs = all(
            c.get("securityContext", {}).get("readOnlyRootFilesystem", False)
            for c in containers
        )
        run_as_non_root = all(
            c.get("securityContext", {}).get("runAsNonRoot", False) for c in containers
        )

        color = (
            "red"
            if privileged or not read_only_root_fs or not run_as_non_root
            else "green"
        )
        print_color(
            color,
            f"{ns:<20} {name:<30} {str(privileged):<15} {str(read_only_root_fs):<20} {str(run_as_non_root):<20}",
        )


def check_readiness_liveness():
    """Check readiness and liveness probes for all deployments."""
    print_header("Readiness and Liveness Probe Check")

    deployments = json.loads(run_command("oc get deployments --all-namespaces -o json"))
    print(f"{'NAMESPACE':<30} {'DEPLOYMENT':<40} {'READINESS':<15} {'LIVENESS':<15}")
    print("-" * 100)

    for dep in deployments["items"]:
        ns = dep["metadata"]["namespace"]
        name = dep["metadata"]["name"]

        if ns.startswith("openshift-"):
            continue

        containers = dep["spec"]["template"]["spec"]["containers"]
        readiness = any("readinessProbe" in container for container in containers)
        liveness = any("livenessProbe" in container for container in containers)

        status = "✓" if readiness and liveness else "✗"
        color = "green" if readiness and liveness else "yellow"

        print_color(
            color,
            f"{ns:<30} {name:<40} {'Configured' if readiness else 'Not Configured':<15} {'Configured' if liveness else 'Not Configured':<15}",
        )

    print("\nReadiness and liveness probe check complete.")


def check_deployments_servicemonitor():
    """Check for deployments without ServiceMonitor."""
    print_header("Deployments without ServiceMonitor")

    deployments = json.loads(run_command("oc get deployments --all-namespaces -o json"))
    service_monitors = json.loads(
        run_command("oc get servicemonitor --all-namespaces -o json")
    )

    deployments_without_sm = []
    sm_selectors = {}

    for sm in service_monitors["items"]:
        ns = sm["metadata"]["namespace"]
        name = sm["metadata"]["name"]
        selector = sm["spec"].get("selector", {})

        # Handle different selector types
        if "matchLabels" in selector:
            sm_selectors[f"{ns}/{name}"] = selector["matchLabels"]
        elif "matchExpressions" in selector:
            # For simplicity, we'll just store the first matchExpression
            # You might want to expand this for more complex scenarios
            if selector["matchExpressions"]:
                expr = selector["matchExpressions"][0]
                sm_selectors[f"{ns}/{name}"] = {expr["key"]: expr["values"][0]}
        else:
            # If neither matchLabels nor matchExpressions, use the selector as is
            sm_selectors[f"{ns}/{name}"] = selector

    for dep in deployments["items"]:
        ns = dep["metadata"]["namespace"]
        name = dep["metadata"]["name"]

        if ns.startswith("openshift-"):
            continue

        labels = dep["metadata"].get("labels", {})
        monitored = False

        for sm_ns_name, selector in sm_selectors.items():
            if all(labels.get(k) == v for k, v in selector.items()):
                monitored = True
                break

        if not monitored:
            deployments_without_sm.append(f"{ns}/{name}")

    if deployments_without_sm:
        print("The following deployments do not have an associated ServiceMonitor:")
        for dep in deployments_without_sm:
            print_color("yellow", f"  ✗ {dep}")
    else:
        print_color("green", "All deployments have an associated ServiceMonitor.")

    print(f"\nTotal deployments without ServiceMonitor: {len(deployments_without_sm)}")


def main():
    """Main function to run the OpenShift cluster audit."""
    generate_banner()

    # Main script
    functions = [
        get_cluster_info,
        get_infrastructure_details,
        get_proxy_details,
        get_nodes_info,
        check_image_streams,
        get_top_nodes,
        check_namespace_quotas,
        get_ingress_info,
        check_metallb_configuration,
        get_network_info,
        get_identityProvider_details,
        get_users_info,
        get_cluster_admins,
        classify_images_by_registry,
        get_registry_config,
        check_image_config,
        get_storage_classes,
        check_persistent_volumes,
        check_log_forwarding,
        check_monitoring_logging,
        check_alerts_receivers,
        check_cluster_monitoring_config,
        get_certificate_status,
        check_scc_configuration,
        check_webhook_configurations,
        check_pod_disruption_budgets,
        check_pod_security,
        check_kasten_configuration,
        check_service_mesh,
        check_cluster_operators,
        list_subscriptions,
        check_kyverno_policies,
        check_etcd_backup,
        check_tls_secrets,
        analyze_deployments_security,
        check_readiness_liveness,
        check_routes_info,
        check_deployment_resources,
        check_hpa_configurations,
        check_deployments_servicemonitor,
        check_network_policies,
    ]

    for func in functions:
        try:
            result = func()
            # print(f"{func.__name__} result: {result}")
        except Exception as e:
            print(f"Exception caught in {func.__name__}: {e}")


if __name__ == "__main__":
    main()
