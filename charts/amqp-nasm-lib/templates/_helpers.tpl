{{/*
AMQP Environment Variables
*/}}
{{- define "amqp-nasm-lib.env" -}}
{{- $globalAmqp := .Values.global.amqp | default dict -}}
{{- $localAmqp := .Values.amqp | default dict -}}
{{- $amqpConfig := mergeOverwrite $globalAmqp $localAmqp -}}
- name: CONTAINER_ENV_USERNAME
  value: {{ $amqpConfig.username | default "guest" | quote }}
- name: CONTAINER_ENV_PASSWORD
  value: {{ $amqpConfig.password | default "guest" | quote }}
- name: CONTAINER_ENV_EXCHANGE
  value: {{ $amqpConfig.exchange | default "datetime_exchange" | quote }}
- name: CONTAINER_ENV_ROUTINGKEY
  value: {{ $amqpConfig.routingKey | default "datetime.last" | quote }}
- name: CONTAINER_ENV_QUEUENAME
  value: {{ $amqpConfig.queueName | default "datetime_queue" | quote }}
- name: CONTAINER_ENV_VHOST
  value: {{ $amqpConfig.vhost | default "/" | quote }}
- name: CONTAINER_ENV_HOST
  value: {{ $amqpConfig.host | default "rabbitmq" | quote }}
- name: CONTAINER_ENV_PORT
  value: {{ $amqpConfig.port | default 5672 | quote }}
{{- end }}

{{/*
AMQP Deployment template
*/}}
{{- define "amqp-nasm-lib.deployment" -}}
{{- $component := .Values.component | required "component is required" -}}
{{- $image := .Values.image | default dict -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-{{ $component }}
  namespace: {{ .Release.Namespace }}
  labels:
    app.kubernetes.io/name: {{ .Release.Name }}-{{ $component }}
    app.kubernetes.io/instance: {{ .Release.Name }}
    app.kubernetes.io/component: {{ $component }}
    helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
spec:
  replicas: {{ .Values.replicaCount | default 1 }}
  selector:
    matchLabels:
      app: {{ .Release.Name }}-{{ $component }}
      app.kubernetes.io/name: {{ .Release.Name }}-{{ $component }}
      app.kubernetes.io/instance: {{ .Release.Name }}
      app.kubernetes.io/component: {{ $component }}
  template:
    metadata:
      labels:
        app: {{ .Release.Name }}-{{ $component }}
        app.kubernetes.io/name: {{ .Release.Name }}-{{ $component }}
        app.kubernetes.io/instance: {{ .Release.Name }}
        app.kubernetes.io/component: {{ $component }}
    spec:
      containers:
      - name: {{ $component }}
        image: "{{ $image.repository | default "amqp-nasm" }}:{{ $image.tag | default "latest" }}"
        command: ["/app/start_amqp.sh"]
        args: [{{ $component | quote }}]
        env:
        {{- include "amqp-nasm-lib.env" . | nindent 8 }}
        resources:
          limits:
            memory: "256Mi"
            cpu: "500m"
          requests:
            memory: "128Mi"
            cpu: "250m"
        imagePullPolicy: {{ $image.pullPolicy | default "IfNotPresent" }}
      restartPolicy: Always
{{- end }}
