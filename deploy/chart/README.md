# xalgorix

![Version: 1.0.0](https://img.shields.io/badge/Version-1.0.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 4.6.91](https://img.shields.io/badge/AppVersion-4.6.91-informational?style=flat-square)

Xalgorix autonomous AI penetration testing platform (dashboard on port 9137, persistent /data volume, optional Ingress or Gateway API exposure)

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| valerianomanassero |  |  |

## Requirements

Kubernetes: `>=1.19.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity rules for pod assignment. |
| auth | object | `{"existingSecret":"","password":"","username":""}` | Dashboard credentials, rendered as XALGORIX_USERNAME and XALGORIX_PASSWORD environment variables in the chart Secret. When empty, the container entrypoint generates a random admin password and prints it once to the container logs. |
| auth.existingSecret | string | `""` | Name of an existing Secret holding the dashboard credentials. It must contain `XALGORIX_USERNAME` and `XALGORIX_PASSWORD` keys. When set, `username` and `password` are ignored and no credentials are written to the chart-managed Secret. |
| auth.password | string | `""` | Dashboard login password. |
| auth.username | string | `""` | Dashboard login username. |
| autoscaling | object | `{"enabled":false,"maxReplicas":10,"minReplicas":1,"targetCPUUtilizationPercentage":80}` | Horizontal pod autoscaler for the deployment. |
| autoscaling.enabled | bool | `false` | Whether to create a HorizontalPodAutoscaler instead of a fixed replica count. WARNING: Xalgorix is stateful (scans, reports and the persisted settings file live under /data). Scaling beyond one replica is NOT supported with local persistence: the default ReadWriteOnce PVC cannot multi-attach, and even with ReadWriteMany storage each replica keeps independent scan state. Leave disabled unless you run each replica as a single shared-nothing unit. |
| autoscaling.maxReplicas | int | `10` | Maximum number of replicas. |
| autoscaling.minReplicas | int | `1` | Minimum number of replicas. |
| autoscaling.targetCPUUtilizationPercentage | int | `80` | Target average CPU utilization percentage. |
| env | object | `{"config":{},"raw":{},"secret":{}}` | Extra environment variables injected into the container. - `raw`: plain key/value pairs set directly on the container; use for any   `XALGORIX_*` variable without a dedicated value above. - `config`: rendered into a ConfigMap and injected via `envFrom`. - `secret`: rendered into a Secret and injected via `envFrom`. Settings changed in the dashboard's Settings UI persist to /data/.xalgorix.env and take precedence over these at startup. |
| env.config | object | `{}` | Key/value pairs rendered into a ConfigMap and injected via `envFrom`. |
| env.raw | object | `{}` | Plain key/value pairs set directly on the container. |
| env.secret | object | `{}` | Key/value pairs rendered into a Secret and injected via `envFrom`. |
| fullnameOverride | string | `""` | Overrides the fully qualified app name in resource names. |
| httproute | object | `{"annotations":{},"enabled":false,"gateway":{},"hostname":"","hostnames":[],"matches":[{"path":{"type":"PathPrefix","value":"/"}}]}` | Gateway API HTTPRoute, an alternative to the Ingress. Requires the `gateway.networking.k8s.io` CRDs and an existing Gateway. |
| httproute.annotations | object | `{}` | Annotations added to the HTTPRoute. |
| httproute.enabled | bool | `false` | Whether to create the HTTPRoute. |
| httproute.gateway | object | `{}` | Existing Gateway to attach the route to. `name` is required when enabled; `namespace` defaults to the release namespace. |
| httproute.hostname | string | Matches all traffic on the Gateway. | Hostname to match. A hostname prefixed with a dot (e.g. `.example.com`) matches all subdomains. |
| httproute.hostnames | list | `[]` | Additional hostnames to match. |
| httproute.matches | list | Matches the `/` path prefix. | Match rules for the route. An empty list matches all traffic. |
| image | object | `{"pullPolicy":"IfNotPresent","repository":"ghcr.io/xalgord/xalgorix","tag":""}` | Container image settings. |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy. |
| image.repository | string | `"ghcr.io/xalgord/xalgorix"` | Image repository. |
| image.tag | string | The chart `appVersion`. | Image tag. |
| imagePullSecrets | list | `[]` | Names of existing secrets with registry credentials for private images. |
| ingress | object | `{"annotations":{},"className":"traefik","enabled":false,"hosts":[{"host":"xalgorix.local","paths":[{"path":"/","pathType":"Prefix"}]}],"tls":[]}` | Ingress resource for exposing the dashboard. Requires an ingress controller installed in the cluster. Add dashboard auth before exposing the dashboard beyond loopback. |
| ingress.annotations | object | `{}` | Annotations added to the Ingress. |
| ingress.className | string | `"traefik"` | Ingress class name. |
| ingress.enabled | bool | `false` | Whether to create the Ingress. |
| ingress.hosts | list | `[{"host":"xalgorix.local","paths":[{"path":"/","pathType":"Prefix"}]}]` | Hosts and paths served by the application. |
| ingress.tls | list | `[]` | TLS configuration for the Ingress. |
| livenessProbe | object | `{}` | Liveness probe for the container. |
| nameOverride | string | `""` | Overrides the chart name in resource names. |
| nodeSelector | object | `{}` | Node labels for pod assignment. |
| persistence | object | `{"accessModes":["ReadWriteOnce"],"enabled":true,"existingClaim":"","size":"10Gi","storageClass":""}` | Persistent volume for /data (scans, reports and the persisted settings file the dashboard writes to). |
| persistence.accessModes | list | `["ReadWriteOnce"]` | Access modes for the claim. |
| persistence.enabled | bool | `true` | Create a PersistentVolumeClaim for the data volume. When disabled an emptyDir is used and data is lost on pod restart. |
| persistence.existingClaim | string | `""` | Use an existing PersistentVolumeClaim instead of creating one. |
| persistence.size | string | `"10Gi"` | Size of the claim. |
| persistence.storageClass | string | The cluster default storage class. | Storage class for the claim. |
| podAnnotations | object | `{}` | Annotations added to the pods. |
| podLabels | object | `{}` | Extra labels added to the pods. |
| podSecurityContext | object | `{}` | Security context applied at the pod level. The image runs as root by design (package auto-install and the Kali toolset need write access to system paths); the container is the isolation boundary. |
| readinessProbe | object | `{}` | Readiness probe for the container. |
| replicaCount | int | `1` | Number of pod replicas. Ignored when `autoscaling.enabled` is true. |
| resources | object | `{}` | Compute resources for the container. |
| securityContext | object | `{}` | Security context applied to the container. The bundled pentest toolset may need NET_ADMIN, NET_RAW and SYS_PTRACE, and seccomp=unconfined for low-level tools (iptables, ARP spoofing, debuggers). |
| service | object | `{"port":9137,"type":"ClusterIP"}` | Service exposing the dashboard. |
| service.port | int | `9137` | Dashboard port (the web UI listens on 9137). |
| service.type | string | `"ClusterIP"` | Service type. |
| serviceAccount | object | `{"annotations":{},"automount":false,"create":true,"name":""}` | Service account used by the pods. |
| serviceAccount.annotations | object | `{}` | Annotations added to the service account. |
| serviceAccount.automount | bool | `false` | Whether to automatically mount the service account API credentials. Xalgorix never talks to the Kubernetes API; leave disabled unless a sidecar in the pod needs it. |
| serviceAccount.create | bool | `true` | Whether a service account should be created. |
| serviceAccount.name | string | A name generated from the full name. | Name of the service account to use. |
| tolerations | list | `[]` | Tolerations for pod assignment. |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
