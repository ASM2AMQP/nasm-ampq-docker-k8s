# Dockerfile

FROM alpine:latest AS base

RUN adduser -D appuser \
 && mkdir -p /app \
 && chown -R appuser:appuser /app

FROM base AS build

# Install build dependencies here
RUN apk add --no-cache nasm binutils musl-dev

ARG USERNAME
ARG PASSWORD
ARG EXCHANGE
ARG ROUTINGKEY
ARG QUEUENAME
ARG VHOST
ARG HOST
ARG PORT

WORKDIR /app

COPY amqp.asm .

# What a madness?!
ENV USERNAME=${USERNAME} \
    PASSWORD=${PASSWORD} \
    EXCHANGE=${EXCHANGE} \
    ROUTINGKEY=${ROUTINGKEY} \
    QUEUENAME=${QUEUENAME} \
    VHOST=${VHOST} \
    HOST=${HOST} \
    PORT=${PORT}
    
# Oh, do you also enjoy all the Docker YAML insanity? - up next: a Helm chart!
RUN nasm \
   -DUSERNAME='"'"${USERNAME}"'"' \
   -DPASSWORD='"'"${PASSWORD}"'"' \
   -DEXCHANGE='"'"${EXCHANGE}"'"' \
   -DROUTINGKEY='"'"${ROUTINGKEY}"'"' \
   -DQUEUENAME='"'"${QUEUENAME}"'"' \
   -DVHOST='"'"${VHOST}"'"' \
   -DHOST='"'"${HOST}"'"' \
   -DPORT="${PORT}" \
   -f elf64 -o amqp.o amqp.asm 

RUN ld -dynamic-linker /lib/ld-musl-x86_64.so.1 -lc amqp.o -o amqp
# RUN ld -dynamic-linker /lib/ld-linux-x86-64.so.2 -lc amqp.o -o amqp

FROM base AS final

# Install only runtime dependencies
#RUN apk add --no-cache musl netcat-openbsd

ARG HOST
ARG PORT
ENV HOST=${HOST} \
    PORT=${PORT}
    

WORKDIR /app

COPY start_amqp.sh .
RUN chmod +x start_amqp.sh

#USER appuser

COPY --from=build /app/amqp /app/amqp
