#!/bin/bash
# cleanup.sh - Remove AMQP Assembly Stack

echo "Removing AMQP Assembly Stack..."
helm uninstall asm-amqp-stack -n amqp-system

echo "Removing namespace (optional)..."
read -p "Do you want to remove the amqp-system namespace? (y/N): " confirm
if [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]]; then
    kubectl delete namespace amqp-system
    echo "Namespace removed."
else
    echo "Namespace kept."
fi

echo "Cleanup completed!"
