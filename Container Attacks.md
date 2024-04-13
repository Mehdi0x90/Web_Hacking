# Container Attacks
## Privileged Container
Running containers with elevated privileges, allowing potential attackers to gain control over the underlying host system. Example: Running a container with root-level access and unrestricted capabilities.

In the noncompliant code, the container is launched with the –privileged flag, enabling privileged mode. This grants the container unrestricted access to the host system, potentially compromising its security boundaries.
```bash
# Noncompliant: Privileged container

FROM ubuntu
...
# Running container in privileged mode
RUN docker run -it --privileged ubuntu /bin/bash
```

The compliant code addresses the vulnerability by running the container without privileged mode. This restricts the container’s access to system resources and reduces the risk of privilege escalation and unauthorized access to the host.
```bash
# Compliant: Non-privileged container

FROM ubuntu
...
# Running container without privileged mode
RUN docker run -it ubuntu /bin/bash
```

## Exposed Container APIs
Insecurely exposing container APIs without proper authentication or access controls, allowing attackers to manipulate or extract sensitive information from containers. Example: Exposing Docker API without any authentication or encryption.

In the noncompliant code, the container’s API is exposed on port 8080 without any authentication or authorization mechanisms in place. This allows unrestricted access to the container API, making it susceptible to unauthorized access and potential attacks.
```bash
# Noncompliant: Exposed container API without authentication/authorization

FROM nginx
...
# Expose container API on port 8080
EXPOSE 8080
```
The compliant code addresses the vulnerability by exposing the container’s API internally on port 8080 and leveraging a reverse proxy or API gateway for authentication and authorization. The reverse proxy or API gateway acts as a security layer, handling authentication/authorization requests before forwarding them to the container API.

To further enhance the security of exposed container APIs, consider the following best practices:
1. Implement strong authentication and authorization mechanisms: Use industry-standard authentication protocols (e.g., OAuth, JWT) and enforce access controls based on user roles and permissions.
2. Employ Transport Layer Security (TLS) encryption: Secure the communication between clients and the container API using TLS certificates to protect against eavesdropping and tampering.
3. Regularly monitor and log API activity: Implement logging and monitoring mechanisms to detect and respond to suspicious or malicious activity.
4. Apply rate limiting and throttling: Protect the API from abuse and denial-of-service attacks by enforcing rate limits and throttling requests.

```bash
# Compliant: Secured container API with authentication/authorization

FROM nginx
...
# Expose container API on port 8080 (internal)
EXPOSE 8080

# Use a reverse proxy or API gateway for authentication/authorization
```

## Container Escape
Exploiting vulnerabilities in the container runtime or misconfigurations to break out of the container’s isolation and gain unauthorized access to the host operating system. Example: Exploiting a vulnerability in the container runtime to access the host system and other containers.

The below code creates and starts a container without any security isolation measures. This leaves the container susceptible to container escape attacks, where an attacker can exploit vulnerabilities in the container runtime or misconfigured security settings to gain unauthorized access to the host system.
```bash
# Noncompliant: Running a container without proper security isolation

require 'docker'

# Create a container with default settings
container = Docker::Container.create('Image' => 'nginx')
container.start
```
we introduce security enhancements to mitigate the risk of container escape. The HostConfig parameter is used to configure the container’s security settings. Here, we:

Set ‘Privileged’ => false to disable privileged mode, which restricts access to host devices and capabilities. Use ‘CapDrop’ => [‘ALL’] to drop all capabilities from the container, minimizing the potential attack surface. Add ‘SecurityOpt’ => [‘no-new-privileges’] to prevent privilege escalation within the container.

```bash
# Compliant: Running a container with enhanced security isolation

require 'docker'

# Create a container with enhanced security settings
container = Docker::Container.create(
  'Image' => 'nginx',
  'HostConfig' => {
    'Privileged' => false,           # Disable privileged mode
    'CapDrop' => ['ALL'],            # Drop all capabilities
    'SecurityOpt' => ['no-new-privileges']  # Prevent privilege escalation
  }
)
container.start
```

## Container Image Tampering
Modifying or replacing container images with malicious versions that may contain malware, backdoors, or vulnerable components. Example: Tampering with a container image to inject malicious code that steals sensitive information.

The below code directly pulls and runs a container image without verifying its integrity. This leaves the application vulnerable to container image tampering, where an attacker can modify the container image to include malicious code or compromise the application’s security.
```bash
#Pulling and running a container image without verifying integrity

require 'docker'

# Pull the container image
image = Docker::Image.create('fromImage' => 'nginx')

# Run the container image
container = Docker::Container.create('Image' => image.id)
container.start
```

we address this issue by introducing integrity verification. The code calculates the expected digest of the pulled image using the SHA256 hash algorithm. It then compares this expected digest with the actual digest of the image obtained from the Docker API. If the digests do not match, an integrity verification failure is raised, indicating that the image may have been tampered with.

```bash
# Compliant: Pulling and running a container image with integrity verification

require 'docker'
require 'digest'

# Image name and tag
image_name = 'nginx'
image_tag = 'latest'

# Pull the container image
image = Docker::Image.create('fromImage' => "#{image_name}:#{image_tag}")

# Verify the integrity of the pulled image
expected_digest = Digest::SHA256.hexdigest(image.connection.get("/images/#{image.id}/json").body)
actual_digest = image.info['RepoDigests'].first.split('@').last
if expected_digest != actual_digest
  raise "Integrity verification failed for image: #{image_name}:#{image_tag}"
end

# Run the container image
container = Docker::Container.create('Image' => image.id)
container.start
```

## Insecure Container Configuration
Misconfigurations in container settings, such as weak access controls or excessive permissions, allowing attackers to compromise the container or its environment. Example: Running a container with unnecessary capabilities or insecure mount points.

The noncompliant code creates and starts a container with default settings, which may have insecure configurations. These misconfigurations can lead to vulnerabilities, such as privilege escalation, excessive container privileges, or exposure of sensitive resources.

```bash
# Noncompliant: Running a container with insecure configuration

require 'docker'

# Create a container with default settings
container = Docker::Container.create('Image' => 'nginx')
container.start
```

In the compliant code, we address these security concerns by applying secure container configurations. The HostConfig parameter is used to specify the container’s configuration. Here, we:

Set ‘ReadOnly’ => true to make the container’s filesystem read-only, preventing potential tampering and unauthorized modifications. Use ‘CapDrop’ => [‘ALL’] to drop all capabilities from the container, minimizing the attack surface and reducing the potential impact of privilege escalation. Add ‘SecurityOpt’ => [‘no-new-privileges’] to prevent the container from gaining additional privileges. Specify ‘NetworkMode’ => ‘bridge’ to isolate the container in a bridge network, ensuring separation from the host and other containers. Use ‘PortBindings’ to bind the container’s port to a specific host port (‘80/tcp’ => [{ ‘HostPort’ => ‘8080’ }]). This restricts network access to the container and avoids exposing unnecessary ports.

```bash
# Compliant: Running a container with secure configuration

require 'docker'

# Create a container with secure settings
container = Docker::Container.create(
  'Image' => 'nginx',
  'HostConfig' => {
    'ReadOnly' => true,               # Set container as read-only
    'CapDrop' => ['ALL'],             # Drop all capabilities
    'SecurityOpt' => ['no-new-privileges'],  # Prevent privilege escalation
    'NetworkMode' => 'bridge',        # Use a bridge network for isolation
    'PortBindings' => { '80/tcp' => [{ 'HostPort' => '8080' }] }  # Bind container port to a specific host port
  }
)
container.start
```

## Denial-of-Service (DoS)
Overloading container resources or exploiting vulnerabilities in the container runtime to disrupt the availability of containerized applications. Example: Launching a DoS attack against a container by overwhelming it with excessive requests.

The noncompliant code snippet shows a Dockerfile that is vulnerable to resource overloading and DoS attacks. It does not implement any resource limitations or restrictions, allowing the container to consume unlimited resources. This can lead to a DoS situation if an attacker overwhelms the container with excessive requests or exploits vulnerabilities in the container runtime.

```bash
# Noncompliant: Vulnerable Dockerfile with unlimited resource allocation

FROM nginx:latest

COPY app /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

The compliant code snippet addresses this vulnerability by not explicitly setting any resource limitations. However, it is essential to implement resource management and limit container resources based on your application’s requirements and the resources available in your environment. This can be achieved by configuring resource limits such as CPU, memory, and network bandwidth using container orchestration platforms or Docker-compose files.

```bash
version: '3'
services:
  nginx:
    image: nginx:latest
    ports:
      - 80:80
    volumes:
      - ./app:/usr/share/nginx/html
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: '256M'
```

## Kernel Vulnerabilities
Exploiting vulnerabilities in the kernel or host operating system to gain unauthorized access or control over containers. Example: Exploiting a kernel vulnerability to escalate privileges and compromise containers.

```bash
# Noncompliant: Ignoring kernel vulnerabilities

docker run -d ubuntu:latest /bin/bash
```

To mitigate kernel vulnerabilities, it is important to regularly check for updates and apply security patches to the host system. Additionally, you can use tools to scan and assess the vulnerability status of the kernel before creating a Docker container.

Here’s an example of compliant code that incorporates checking for kernel vulnerabilities using the kubehunter tool before creating the container:

```bash
# Compliant: Checking kernel vulnerabilities

# Perform vulnerability assessment using kubehunter
kubehunter scan

# Check the output for kernel vulnerabilities

# If vulnerabilities are found, take necessary steps to address them

# Create the Docker container
docker run -d ubuntu:latest /bin/bash
```
In the compliant code snippet, the kubehunter tool is used to perform a vulnerability assessment, including checking for kernel vulnerabilities. The output of the tool is examined, and if any vulnerabilities are found, appropriate steps are taken to address them before creating the Docker container.

## Shared Kernel Exploitation
Containers sharing the same kernel can be vulnerable to attacks that exploit kernel vulnerabilities, allowing attackers to affect multiple containers. Example: Exploiting a kernel vulnerability to gain unauthorized access to multiple containers on the same host.

In the noncompliant code, the Docker image installs a vulnerable package and runs a vulnerable application. If an attacker manages to exploit a kernel vulnerability within the container, they could potentially escape the container and compromise the host or other containers.

```bash
# Noncompliant: Vulnerable to container breakout

FROM ubuntu:latest

# Install vulnerable package
RUN apt-get update && apt-get install -y vulnerable-package

# Run vulnerable application
CMD ["vulnerable-app"]
```

The compliant code addresses the vulnerability by ensuring that the container image only includes necessary and secure packages. It performs regular updates and includes security patches to mitigate known vulnerabilities. By running a secure application within the container, the risk of a container breakout is reduced.

To further enhance security, additional measures can be taken such as utilizing container isolation techniques like running containers with restricted privileges, leveraging security-enhanced kernels (such as those provided by certain container platforms), and monitoring and logging container activity to detect potential exploitation attempts.

```bash
# Compliant: Mitigated container breakout vulnerability

FROM ubuntu:latest

# Install security updates and necessary packages
RUN apt-get update && apt-get upgrade -y && apt-get install -y secure-package

# Run secure application
CMD ["secure-app"]
```

## Insecure Container Orchestration
Misconfigurations or vulnerabilities in container orchestration platforms, such as Kubernetes, can lead to unauthorized access, privilege escalation, or exposure of sensitive information. Example: Exploiting a misconfigured Kubernetes cluster to gain unauthorized access to sensitive resources.

In the noncompliant code, the Pod definition enables privileged mode for the container, granting it elevated privileges within the container orchestration environment. If an attacker gains access to this container, they could exploit the elevated privileges to perform malicious actions on the host or compromise other containers.

```bash
# Noncompliant: Vulnerable to privilege escalation

apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
spec:
  containers:
    - name: vulnerable-container
      image: vulnerable-image
      securityContext:
        privileged: true  # Privileged mode enabled
```

The compliant code addresses the vulnerability by explicitly disabling privileged mode for the container. By running containers with reduced privileges, the impact of a potential compromise is limited, and the attack surface is minimized.

In addition to disabling privileged mode, other security measures should be implemented to enhance the security of container orchestration. This includes configuring appropriate RBAC (Role-Based Access Control) policies, enabling network segmentation and isolation, regularly applying security patches to the orchestration system, and monitoring the environment for suspicious activities.

```bash
# Compliant: Mitigated privilege escalation

apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
    - name: secure-container
      image: secure-image
      securityContext:
        privileged: false  # Privileged mode disabled
```

## Dump All Secrets
Dumping all secrets in a Kubernetes cluster refers to an unauthorized extraction of sensitive information stored as secrets within the cluster. This attack allows an attacker with the right permissions to access and exfiltrate all secrets, potentially leading to further compromise.

Noncompliant Code: The following noncompliant code demonstrates an attempt to dump all secrets from a Kubernetes cluster without proper authorization:

```bash
# Retrieve all secrets using kubectl command
kubectl get secrets --all-namespaces -o json > secrets.json
```

The noncompliant code utilizes the kubectl get secrets command to retrieve all secrets in the cluster across all namespaces. This action assumes that the attacker has the necessary permissions to access and list secrets, potentially leading to unauthorized access to sensitive information.

Compliant Code: Dumping all secrets in a Kubernetes cluster is considered a malicious activity, and providing compliant code for it would be inappropriate. Instead, I can provide you with guidelines on how to ensure the security of secrets in a Kubernetes cluster:
* Implement Least Privilege: Follow the principle of least privilege when granting permissions to users and service accounts. Only assign the necessary privileges required for specific tasks, and regularly review and audit these permissions.
* Implement Role-Based Access Control (RBAC): Configure RBAC rules to restrict access to secrets based on the principle of least privilege. Assign appropriate roles to users and service accounts, ensuring they have the minimum necessary permissions.
* Use Namespaces: Leverage Kubernetes namespaces to logically segregate resources and isolate secrets. Limit access to secrets within specific namespaces based on the principle of least privilege.
* Implement Secrets Encryption: Encrypt secrets at rest and in transit. Kubernetes provides mechanisms such as the Secrets Encryption Configuration feature, which encrypts secrets stored in etcd, the Kubernetes cluster’s key-value store.
* Monitor Kubernetes API Server Audit Logs: Enable and monitor Kubernetes API server audit logs to detect and investigate suspicious activities, such as unauthorized access attempts or abnormal querying of secrets.
* Regularly Rotate Secrets: Implement a process to regularly rotate secrets to minimize the impact of potential compromise. This includes setting expiry times for secrets and automating the rotation process.
* Secure Cluster Access: Secure access to the Kubernetes cluster by implementing strong authentication mechanisms, such as using strong passwords, multi-factor authentication (MFA), or integration with an identity provider.


## Steal Pod Service Account Token
Stealing a pod’s service account token refers to the unauthorized extraction of the service account token from a running pod in a Kubernetes cluster. The service account token is a sensitive credential that grants access to the Kubernetes API and other resources within the cluster.

Noncompliant Code: The following noncompliant code demonstrates an attempt to steal the service account token from a running pod:

```bash
# Execute command to read the service account token from within the pod
kubectl exec <pod-name> -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

The noncompliant code uses the kubectl exec command to execute a command (cat /var/run/secrets/kubernetes.io/serviceaccount/token) inside the specified pod. This command reads and outputs the contents of the service account token file. An attacker with sufficient access to the cluster could use this method to steal the token and gain unauthorized access to Kubernetes resources.

Compliant Code: It is essential to adhere to security best practices and prevent the theft of service account tokens. Below are some recommendations for securing pod service account tokens:
* Limit Pod Permissions: Assign minimal permissions to pods by using the principle of least privilege. Only grant the necessary access required for the pod to function properly.
* Use Role-Based Access Control (RBAC): Implement RBAC rules to restrict pod permissions and limit the ability to execute privileged commands or access sensitive files.
* Avoid Mounting Service Account Tokens: When creating pods, avoid mounting the service account token as a volume or exposing it as an environment variable. Minimize the attack surface by not making the token easily accessible within the pod.
* Regularly Rotate Service Account Tokens: Implement a process to periodically rotate service account tokens. This helps mitigate the impact of a compromised token and reduces the window of opportunity for attackers.
* Monitor Pod Activity: Enable logging and monitoring for pod activities. Regularly review logs and detect any suspicious or unauthorized access attempts.
* Implement Pod Security Policies: Utilize Pod Security Policies (PSPs) to enforce security controls on pod creation, including restrictions on executing privileged commands or accessing sensitive files.


## Create Admin ClusterRole
Create Admin ClusterRole refers to the process of creating a Kubernetes ClusterRole with administrative permissions. It involves creating a Service Account bound to the ClusterRole and establishing a Cluster Role Binding to associate the Service Account with the desired privileges.

Noncompliant Code: The following noncompliant code demonstrates the creation of an Admin ClusterRole:

```bash
# Create an Admin ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin-clusterrole
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["*"]

# Create a Service Account in the kube-system namespace
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-serviceaccount
  namespace: kube-system

# Create a Cluster Role Binding to associate the Service Account with the ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-clusterrolebinding
subjects:
- kind: ServiceAccount
  name: admin-serviceaccount
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: admin-clusterrole
  apiGroup: rbac.authorization.k8s.io
```

The noncompliant code creates an Admin ClusterRole named “admin-clusterrole” with wide-ranging permissions (apiGroups: [””], resources: [””], verbs: [””]). It also creates a Service Account named “admin-serviceaccount” in the kube-system namespace and binds it to the Admin ClusterRole using a Cluster Role Binding named “admin-clusterrolebinding”. This configuration grants the Service Account administrative access to all resources in the cluster, which is not recommended for security reasons.

Compliant Code: When creating a ClusterRole with administrative permissions, it is important to follow the principle of least privilege and assign only the necessary privileges to the Service Account. Below is an example of compliant code:

```bash
# Create a ClusterRole with appropriate administrative permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin-clusterrole
rules:
- apiGroups: [""]
  resources: ["pods", "deployments"]
  verbs: ["get", "list", "create", "update", "delete"]

# Create a Service Account in the kube-system namespace
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-serviceaccount
  namespace: kube-system

# Create a Cluster Role Binding to associate the Service Account with the ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-clusterrolebinding
subjects:
- kind: ServiceAccount
  name: admin-serviceaccount
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: admin-clusterrole
  apiGroup: rbac.authorization.k8s.io
```

The compliant code creates an Admin ClusterRole named “admin-clusterrole” with specific permissions for managing pods and deployments. It limits the verbs to “get”, “list”, “create”, “update”, and “delete” for those resources. This approach follows the principle of least privilege, granting only the necessary permissions to the Service Account. By adopting this approach, the Service Account associated with the Admin ClusterRole has restricted administrative access, reducing the potential impact of any compromise or misuse of the account.


## Create Client Certificate Credential
Create Client Certificate Credential refers to the process of generating a client certificate for a privileged user in a Kubernetes cluster. The client certificate can be used to authenticate and access the cluster with the assigned privileges.

Noncompliant Code: The following noncompliant code demonstrates the creation of a client certificate:

```bash
# Generate a private key
openssl genrsa -out client.key 2048

# Create a certificate signing request (CSR)
openssl req -new -key client.key -out client.csr -subj "/CN=client"

# Print the CSR
cat client.csr
```

The noncompliant code manually generates a private key using OpenSSL and creates a certificate signing request (CSR) for a client with the Common Name (CN) “client”. However, this code snippet alone does not include the step to approve the CSR and issue the client certificate. It is important to note that this noncompliant code does not adhere to best practices and security requirements for managing client certificates within a Kubernetes cluster.

Compliant Code: To create a client certificate credential in a compliant manner, it is recommended to use the Kubernetes Certificate Signing Request (CSR) API and follow the proper procedures for certificate generation and approval. Below is an example of compliant code:

```bash
# Create a CertificateSigningRequest object
apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
  name: client-csr
spec:
  groups:
  - system:authenticated
  request: (base64-encoded CSR)
  usages:
  - client auth

# Approve the CertificateSigningRequest
kubectl certificate approve client-csr

# Retrieve the signed certificate
kubectl get csr client-csr -o jsonpath='{.status.certificate}' | base64 -d > client.crt

# Print the client certificate and private key
echo "Client Certificate:"
cat client.crt

echo "Client Private Key:"
openssl rsa -in client.key -text
```

The compliant code demonstrates the proper approach for creating a client certificate credential. It involves creating a CertificateSigningRequest (CSR) object with the appropriate metadata, including the base64-encoded CSR and specified usages. The CSR is then approved using the kubectl certificate approve command, and the signed certificate is retrieved using kubectl get csr. Finally, the client certificate and private key are printed.

## Create Long-Lived Token
Create Long-Lived Token refers to the process of generating a token with an extended expiration period for a service account in a Kubernetes cluster. This allows an attacker to establish persistence by creating a long-lived token that grants ongoing access to the compromised cluster.

Noncompliant Code: The following noncompliant code demonstrates the creation of a long-lived token:

```bash
# Create a service account token
kubectl create serviceaccount long-lived-token-sa

# Get the token
kubectl get secret $(kubectl get serviceaccount long-lived-token-sa -o jsonpath='{.secrets[0].name}') -o jsonpath='{.data.token}' | base64 -d
```

The noncompliant code generates a service account token for a newly created service account. It retrieves the token from the associated secret and decodes it using base64. However, this code snippet alone does not specify an extended expiration for the token, and the default token expiration policy of the cluster will be applied. It is important to note that this noncompliant code does not adhere to the concept of creating a long-lived token explicitly.

Compliant Code: To create a long-lived token, a compliant approach would involve defining a custom TokenRequest with a specific expiration time. Here’s an example of compliant code:

```bash
# Create a TokenRequest with extended expiration
apiVersion: authentication.k8s.io/v1
kind: TokenRequest
metadata:
  name: long-lived-token
spec:
  audience: api
  expirationSeconds: 2592000  # 30 days (adjust as needed)
  tokenRequest:
    metadata:
      name: serviceaccount-name
      namespace: namespace-name

# Create the TokenRequest
kubectl create -f token-request.yaml

# Get the token
kubectl get secret $(kubectl get tokenrequest long-lived-token -o jsonpath='{.status.secretName}') -o jsonpath='{.data.token}' | base64 -d
```

The compliant code defines a TokenRequest object specifying the desired expiration time for the token (e.g., 30 days). It also includes the name of the service account and the namespace. The TokenRequest is then created using kubectl create with the YAML file containing the object definition. Finally, the token is retrieved by accessing the associated secret and decoding the token value.


## Container breakout via hostPath volume mount
Container breakout via hostPath volume mount is a privilege escalation technique in Kubernetes where a malicious actor creates a pod that mounts the entire node’s root filesystem using the hostPath volume. This allows the attacker to escape the pod’s containerized environment and access sensitive files or execute privileged actions on the underlying host system.

Noncompliant Code: The following noncompliant code demonstrates the creation of a pod with a hostPath volume mount:

```bash
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-container-breakout
spec:
  containers:
  - name: attacker-container
    image: busybox
    command: ["/bin/sh", "-c"]
    args: ["cat /host/etc/passwd"]
    volumeMounts:
    - name: hostpath-volume
      mountPath: /host
  volumes:
  - name: hostpath-volume
    hostPath:
      path: /
```

The noncompliant code defines a pod named “hostpath-container-breakout” with a single container based on the “busybox” image. The container executes the command “cat /host/etc/passwd” to read the “/etc/passwd” file on the host system. The hostPath volume is mounted at “/host”, allowing access to the node’s root filesystem.

Compliant Code: To prevent container breakout via hostPath volume mount, it is essential to apply proper security controls and restrictions to limit access to the host system. Here’s an example of compliant code that mitigates this issue:

```bash
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
  - name: trusted-container
    image: busybox
    command: ["/bin/sh", "-c"]
    args: ["echo 'Access denied'"]
    securityContext:
      allowPrivilegeEscalation: false
```


The compliant code defines a pod named “secure-pod” with a single container based on the “busybox” image. The container executes a command that simply echoes “Access denied” to indicate restricted access. The securityContext section is added with the “allowPrivilegeEscalation” field set to false, which prevents privilege escalation attempts within the container.


## Privilege escalation through node/proxy permissions
Privilege escalation through node/proxy permissions is a technique in Kubernetes that leverages the node proxy API to escalate privileges. By using this technique, an attacker with the nodes/proxy permission can bypass admission control checks and API server logging to escalate their privileges to cluster administrator.

Noncompliant Code: The following noncompliant code demonstrates the creation of a cluster role with nodes/proxy permissions and binding it to a service account:

```bash
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nodes-proxy-role
rules:
- apiGroups: [""]
  resources: ["nodes/proxy"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: nodes-proxy-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: nodes-proxy-role
subjects:
- kind: ServiceAccount
  name: nodes-proxy-sa
  namespace: your-namespace
```

The noncompliant code creates a cluster role named “nodes-proxy-role” with rules granting full access to the nodes/proxy resource. It also creates a cluster role binding named “nodes-proxy-binding” that binds the role to a service account named “nodes-proxy-sa” in a specific namespace.

Compliant Code: To mitigate privilege escalation through node/proxy permissions, it’s crucial to implement the principle of least privilege and restrict access to sensitive resources. Here’s an example of compliant code:

```bash
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: restricted-nodes-proxy-role
rules:
- apiGroups: [""]
  resources: ["nodes/proxy"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: restricted-nodes-proxy-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: restricted-nodes-proxy-role
subjects:
- kind: ServiceAccount
  name: restricted-nodes-proxy-sa
  namespace: your-namespace
```

The compliant code creates a cluster role named “restricted-nodes-proxy-role” with a rule that allows only the “get” verb for the nodes/proxy resource. This significantly limits the permissions associated with the role, reducing the risk of privilege escalation.


## Run a Privileged Pod
Running a privileged pod in Kubernetes refers to launching a pod with elevated privileges, equivalent to running as root on the worker node. Privileged pods can be used as a vector for privilege escalation within the cluster.

Noncompliant Code: The following noncompliant code demonstrates the creation of a privileged pod:

```bash
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: your-namespace
spec:
  containers:
  - name: privileged-container
    image: busybox:latest
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
```

The noncompliant code creates a pod named “privileged-pod” within a specific namespace. It contains a single container named “privileged-container” running the “busybox:latest” image. The securityContext.privileged field is set to true, indicating that the pod should run with elevated privileges.

Compliant Code: To ensure the security and integrity of the cluster, it’s important to follow the principle of least privilege and avoid running privileged pods whenever possible. Here’s an example of compliant code:

```bash
apiVersion: v1
kind: Pod
metadata:
  name: non-privileged-pod
  namespace: your-namespace
spec:
  containers:
  - name: non-privileged-container
    image: busybox:latest
    command: ["sleep", "3600"]
```

The compliant code creates a pod named “non-privileged-pod” within a specific namespace. It contains a single container named “non-privileged-container” running the “busybox:latest” image.

By omitting the securityContext.privileged field or setting it to false (the default), the pod and its container will run with standard user privileges. This reduces the risk of privilege escalation and helps maintain the security boundaries within the cluster.































