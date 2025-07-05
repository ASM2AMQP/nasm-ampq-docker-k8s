#!/bin/bash

USERNAME=guest
PASSWORD=guest
EXCHANGE=datetime_exchange
ROUTINGKEY=datetime.last
QUEUENAME=datetime_queue
VHOST=/
HOST=localhost
PORT=5672

nasm \
   -DUSERNAME='"${USERNAME}"' \
   -DPASSWORD='"${PASSWORD}"' \
   -DEXCHANGE='"${EXCHANGE}"' \
   -DROUTINGKEY='"${ROUTINGKEY}"' \
   -DQUEUENAME='"${QUEUENAME}"' \
   -DVHOST='"${VHOST}"' \
   -DHOST='"${HOST}"' \
   -DPORT='${PORT}' \
   -f elf64 -o amqp.o amqp.asm && \
ld -dynamic-linker /lib/ld-musl-x86_64.so.1 -lc amqp.o -o amqp
