# Cuarta fuente (opcional): logs de Kubernetes

El enunciado pide mínimo 3 fuentes. Ya hay auth.log, syslog y nginx, así que Kubernetes es un extra si sobra tiempo.

Idea:

1. `minikube start` y desplegar cualquier app (por ejemplo, la misma nginx).
2. Correr Filebeat como DaemonSet en minikube con el input `container` sobre `/var/log/containers/*.log` y
   `fields: { origen: k8s }`, apuntando a Logstash en el PC (`host.minikube.internal:5044`).
   Para eso hay que publicar el puerto 5044 de Logstash en el compose.
3. Agregar `logstash/pipeline/50-k8s.conf` con `data_stream.dataset = siem.k8s` y los campos
   `kubernetes.*` que ya trae Filebeat.

_(pendiente: decidir si se hace)_
