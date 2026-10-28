{{/* Common naming and labels. */}}
{{- define "warden.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "warden.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "warden.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "warden.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "warden.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Per-component selector labels. Pass a dict {root, component}. */}}
{{- define "warden.selectorLabels" -}}
app.kubernetes.io/name: {{ include "warden.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* The admin-token Secret name. */}}
{{- define "warden.secretName" -}}
{{- printf "%s-admin" (include "warden.fullname" .) -}}
{{- end -}}

{{/* SQLAlchemy (psycopg) URL for the Python services. */}}
{{- define "warden.pyDatabaseUrl" -}}
postgresql+psycopg://{{ .Values.postgres.auth.username }}:{{ .Values.postgres.auth.password }}@postgres:5432/{{ .Values.postgres.auth.database }}
{{- end -}}

{{/* node-pg URL for the gateway. */}}
{{- define "warden.pgDatabaseUrl" -}}
postgresql://{{ .Values.postgres.auth.username }}:{{ .Values.postgres.auth.password }}@postgres:5432/{{ .Values.postgres.auth.database }}
{{- end -}}

{{/* Admin-token env var sourced from the Secret, emitted only when a token is configured. */}}
{{- define "warden.adminTokenEnv" -}}
{{- if .Values.adminToken }}
- name: WARDEN_ADMIN_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "warden.secretName" . }}
      key: admin-token
{{- end }}
{{- end -}}

{{/* An initContainer (python image) that blocks until the migration has created the schema. */}}
{{- define "warden.waitForSchema" -}}
- name: wait-for-schema
  image: "{{ .Values.images.python.repository }}:{{ .Values.images.python.tag }}"
  imagePullPolicy: {{ .Values.pullPolicy }}
  command: ["sh", "-c"]
  args:
    - |
      until python -c "import os; from sqlalchemy import create_engine, inspect; exit(0 if inspect(create_engine(os.environ['PY_DATABASE_URL'])).has_table('verdicts') else 1)" 2>/dev/null; do echo 'waiting for schema'; sleep 2; done
  env:
    - name: PY_DATABASE_URL
      value: {{ include "warden.pyDatabaseUrl" . | quote }}
{{- end -}}
