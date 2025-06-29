#!/bin/bash

echo "Starting RabbitMQ container..."
docker run -d --name test-rabbitmq --rm -p 5672:5672 rabbitmq:3 > /dev/null 2>&1

echo "Waiting for RabbitMQ to start..."
sleep 10

echo "Testing producer (sending date every second for 5 seconds)..."
(for i in {1..5}; do date; sleep 1; done) | timeout 10 ./amqp_glibc -s &
PRODUCER_PID=$!

echo "Testing consumer (receiving messages)..."
timeout 10 ./amqp_glibc -r &
CONSUMER_PID=$!

sleep 6

echo "Cleaning up..."
kill $PRODUCER_PID $CONSUMER_PID 2>/dev/null || true
docker stop test-rabbitmq > /dev/null 2>&1 || true

echo "Test completed!"
