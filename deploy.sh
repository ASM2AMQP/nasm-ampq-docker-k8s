#!/bin/bash
# deploy-k3s.sh - Build and deploy AMQP Assembly Stack for k3s

set -e

# Load environment variables
if [ -f ".env" ]; then
    source .env
elif [ -f "kubernetes.env" ]; then
    source kubernetes.env
else
    echo "Error: .env or kubernetes.env file not found"
    exit 1
fi

echo "Building Docker image..."

# docker build -f attic/Dockerfile.single -t amqp-nasm:latest \
docker build --target=final -t amqp-nasm:latest \
  --build-arg USERNAME="$CONTAINER_ENV_USERNAME" \
  --build-arg PASSWORD="$CONTAINER_ENV_PASSWORD" \
  --build-arg EXCHANGE="$CONTAINER_ENV_EXCHANGE" \
  --build-arg ROUTINGKEY="$CONTAINER_ENV_ROUTINGKEY" \
  --build-arg QUEUENAME="$CONTAINER_ENV_QUEUENAME" \
  --build-arg VHOST="$CONTAINER_ENV_VHOST" \
  --build-arg HOST="asm-amqp-stack-rabbitmq" \
  --build-arg PORT="$CONTAINER_ENV_PORT" \
  .

echo "Tagging Docker image amqp-nasm:latest as docker.io/library/amqp-nasm:latest..."
docker tag amqp-nasm:latest docker.io/library/amqp-nasm:latest

echo "Saving Docker image to tar file..."
docker save amqp-nasm:latest -o amqp-nasm-latest.tar

echo "Importing image into k3s containerd..."
sudo k3s ctr images import amqp-nasm-latest.tar

echo "Cleaning up tar file..."
rm amqp-nasm-latest.tar

echo "Verifying image import..."
sudo k3s ctr images ls | grep amqp-nasm

echo "Updating Helm dependencies..."
cd charts/amqp-nasm-stack
helm dependency update

echo "Deploying stack..."
helm upgrade --install asm-amqp-stack . \
  --create-namespace \
  --namespace amqp-system \
  --set global.amqp.username="$CONTAINER_ENV_USERNAME" \
  --set global.amqp.password="$CONTAINER_ENV_PASSWORD" \
  --set global.amqp.exchange="$CONTAINER_ENV_EXCHANGE" \
  --set global.amqp.routingKey="$CONTAINER_ENV_ROUTINGKEY" \
  --set global.amqp.queueName="$CONTAINER_ENV_QUEUENAME" \
  --set global.amqp.vhost="$CONTAINER_ENV_VHOST" \
  --set global.amqp.host="asm-amqp-stack-rabbitmq" \
  --set global.amqp.port="$CONTAINER_ENV_PORT" \
  --set rabbitmq.auth.username="$CONTAINER_ENV_USERNAME" \
  --set rabbitmq.auth.password="$CONTAINER_ENV_PASSWORD" \
  --set producer.image.repository="amqp-nasm" \
  --set producer.image.tag="latest" \
  --set producer.image.pullPolicy=Never \
  --set consumer.image.repository="amqp-nasm" \
  --set consumer.image.tag="latest" \
  --set consumer.image.pullPolicy=Never \
  --wait \
  --timeout 300s

echo "Deployment complete"
