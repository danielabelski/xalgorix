{{/*
Expand the name of the chart.
*/}}
{{- define "xalgorix.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields only accept that
(e.g. DNS names as per RFC 1035).
*/}}
{{- define "xalgorix.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "xalgorix.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "xalgorix.labels" -}}
helm.sh/chart: {{ include "xalgorix.chart" . }}
{{ include "xalgorix.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "xalgorix.selectorLabels" -}}
app.kubernetes.io/name: {{ include "xalgorix.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "xalgorix.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "xalgorix.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
ConfigMap name.
*/}}
{{- define "xalgorix.configMapName" -}}
{{- printf "%s-config" (include "xalgorix.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Secret name.
*/}}
{{- define "xalgorix.secretName" -}}
{{- printf "%s-secret" (include "xalgorix.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
