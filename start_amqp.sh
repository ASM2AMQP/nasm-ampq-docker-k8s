#!/bin/sh

set -o errexit
set -o nounset


wait_for_the_slow_rabbit() {
  echo "Waiting for rabbitmq on $HOST:$PORT..."
  sleep 10  # Simple wait for RabbitMQ to start
}

if [ $# -ne 1 ]; then
  echo "Error: Exactly one argument required."
  exit 1
fi

case "$1" in
  consumer)
    echo "Running consumer ..."
    wait_for_the_slow_rabbit && /app/amqp -r
    # Add consumer-specific commands here
    ;;
  producer)
    echo "Running producer ..."
    wait_for_the_slow_rabbit && while date; do sleep 1; done | /app/amqp -s
    # Add producer-specific commands here
    ;;
  *)
    echo "Error: Argument must be 'consumer' or 'producer'."
    exit 1
    ;;
esac



