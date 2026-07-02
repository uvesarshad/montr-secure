{{/*
Montr Secure — chart helpers.
*/}}

{{- define "montr.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "montr.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "montr.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "montr.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "montr.labels" -}}
helm.sh/chart: {{ include "montr.chart" . }}
{{ include "montr.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: montr-secure
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "montr.selectorLabels" -}}
app.kubernetes.io/name: {{ include "montr.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Per-component ServiceAccount name.
Usage: {{ include "montr.serviceAccountName" (dict "ctx" $ "component" "api") }}
*/}}
{{- define "montr.serviceAccountName" -}}
{{- $ctx := .ctx -}}
{{- if $ctx.Values.serviceAccount.create -}}
{{- printf "%s-%s" (include "montr.fullname" $ctx) .component | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- default "default" $ctx.Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Name of the chart-managed (or existing) app Secret. */}}
{{- define "montr.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "montr.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Per-component image reference. Falls back registry/repository/tag to the global
`image.*`, and the tag to .Chart.AppVersion. Per-component override via
`<component>.image.{registry,repository,tag}`.
Usage: {{ include "montr.image" (dict "ctx" $ "component" "api") }}
*/}}
{{- define "montr.image" -}}
{{- $ctx := .ctx -}}
{{- $component := .component -}}
{{- $img := (index $ctx.Values $component).image | default dict -}}
{{- $registry := $img.registry | default $ctx.Values.image.registry -}}
{{- $repository := $img.repository | default (printf "%s-%s" $ctx.Values.image.repository $component) -}}
{{- $tag := $img.tag | default $ctx.Values.image.tag | default $ctx.Chart.AppVersion -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- end -}}

{{/* REDIS_URL — bundled service name, or the external URL. */}}
{{- define "montr.redisUrl" -}}
{{- if .Values.redis.enabled -}}
{{- printf "redis://%s-redis:%v" (include "montr.fullname" .) (.Values.redis.port | int) -}}
{{- else -}}
{{- required "redis.enabled=false requires redis.externalUrl" .Values.redis.externalUrl -}}
{{- end -}}
{{- end -}}

{{/*
Postgres password: explicit value, else reuse the one already stored in the app
Secret (stable across upgrades via lookup), else generate. Call ONCE per render
and store in a variable to keep POSTGRES_PASSWORD and DATABASE_URL consistent.
*/}}
{{- define "montr.postgresPassword" -}}
{{- if .Values.postgres.auth.password -}}
{{- .Values.postgres.auth.password -}}
{{- else -}}
{{- $secretName := printf "%s-secrets" (include "montr.fullname" .) -}}
{{- $existing := (lookup "v1" "Secret" .Release.Namespace $secretName) -}}
{{- if and $existing (hasKey ($existing.data | default dict) "POSTGRES_PASSWORD") -}}
{{- index $existing.data "POSTGRES_PASSWORD" | b64dec -}}
{{- else -}}
{{- randAlphaNum 24 -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Pod-level securityContext (hardened, values-driven). */}}
{{- define "montr.podSecurityContext" -}}
{{- toYaml .Values.podSecurityContext -}}
{{- end -}}

{{/* Container-level securityContext (hardened, values-driven). */}}
{{- define "montr.containerSecurityContext" -}}
{{- toYaml .Values.containerSecurityContext -}}
{{- end -}}

{{/* The full MontrConfig rendered as JSON for the app config file. */}}
{{- define "montr.configJson" -}}
{{- .Values.montrConfig | toPrettyJson -}}
{{- end -}}
