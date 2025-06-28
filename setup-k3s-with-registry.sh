#!/bin/bash
# setup-k3s-with-registry.sh - Setup k3s with local registry support

set -e

echo "Creating registry container..."
docker run -d \
  --restart=always \
  --name registry \
  -p 5000:5000 \
  registry:2

echo "Creating k3s registries.yaml config..."
sudo mkdir -p /etc/rancher/k3s
sudo tee /etc/rancher/k3s/registries.yaml > /dev/null <<EOF
mirrors:
  localhost:5000:
    endpoint:
      - "http://localhost:5000"
configs:
  "localhost:5000":
    tls:
      insecure_skip_verify: true
EOF

echo "Restarting k3s to apply registry config..."
sudo systemctl restart k3s

echo "Waiting for k3s to be ready..."
sleep 10

echo "Verifying k3s status..."
kubectl get nodes

echo "Registry setup complete!"
echo "You can now use localhost:5000 as your registry"
echo "Test with: docker push localhost:5000/test-image:latest"
