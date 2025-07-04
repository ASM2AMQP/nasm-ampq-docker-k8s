#!/bin/bash
nasm -DUSERNAME='"guest"' -DPASSWORD='"guest"' -DEXCHANGE='"my_exchange"' -DROUTINGKEY='"my.topic"' -DQUEUENAME='"my_queue"' -DVHOST='"/"' -DHOST='"localhost"' -DPORT=5672 -f elf64 -o amqp.o amqp.asm
ld -dynamic-linker /lib64/ld-linux-x86-64.so.2 -lc amqp.o -o amqp