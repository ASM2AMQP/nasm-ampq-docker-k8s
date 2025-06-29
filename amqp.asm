%ifndef USERNAME
  %define USERNAME "guest"
%endif

%ifndef PASSWORD
  %define PASSWORD "guest"
%endif

%ifndef EXCHANGE
  %define EXCHANGE "my_exchange"
%endif

%ifndef ROUTINGKEY
  %define ROUTINGKEY "my.topic"
%endif

%ifndef QUEUENAME
  %define QUEUENAME "my_queue"
%endif

%ifndef VHOST
  %define VHOST "/"
%endif

%ifndef HOST
  %define HOST "localhost"
%endif

%ifndef PORT
  %define PORT 5672
%endif

; Runtime configuration buffer sizes
USERNAME_MAX    equ 64
PASSWORD_MAX    equ 128  
HOSTNAME_MAX    equ 256
QUEUENAME_MAX   equ 256
EXCHANGE_MAX    equ 256
VHOST_MAX       equ 128
ROUTINGKEY_MAX  equ 256

section .data
    ; String values
    username       db USERNAME
    password       db PASSWORD
    vhost          db VHOST
    exchange       db EXCHANGE
    routing_key    db ROUTINGKEY
    queue_name     db QUEUENAME
    host_str       db HOST, 0

    ; Precomputed lengths
    username_len       equ password - username
    password_len       equ vhost - password
    vhost_len          equ exchange - vhost
    exchange_len       equ routing_key - exchange
    routing_key_len    equ queue_name - routing_key
    queue_name_len     equ host_str - queue_name

    ; Network port (big endian)
    port_be        dw ((PORT & 0xFF) << 8) | ((PORT >> 8) & 0xFF)

    ; Messages
    usage_msg      db "Usage: ./amqp <mode> [user] [host] [port] [vhost] [queuename] [exchange] [routingkey]", 10
                   db "  mode: -s (sender) or -r (receiver)", 10
                   db "  Optional args use compile-time defaults if empty/missing", 10, 0
    password_prompt db "Password: ", 0
    password_prompt_len equ $ - password_prompt - 1
    newline        db 10, 0
    mode_err       db "Unknown mode. Use -s (sender) or -r (receiver)", 10, 0

    ; Error messages
    error_dns_fail       db "DNS resolution failed", 10, 0
    error_sock_fail      db "Socket creation failed", 10, 0
    error_conn_fail      db "Connection failed", 10, 0
    error_frame_overflow db "Frame Overflow", 10, 0
    error_receive_buffer_overflow db "Receive Buffer Overflow", 10, 0

    ; Trace messages
    trace_send       db "Message sent to exchange: ", EXCHANGE, 10, 0
    trace_receive    db "Received from queue: ", 0
    trace_listening  db "Listening on queue: ", QUEUENAME, 10, 0
    trace_read_stdin db "Reading messages from stdin (Ctrl+D to end):", 10, 0
    trace_conn        db "[TRACE] Connecting to broker...", 10, 0
    trace_handshake   db "[TRACE] Starting AMQP handshake...", 10, 0
    trace_channel     db "[TRACE] Opening channel...", 10, 0
    trace_exchange    db "[TRACE] Declaring exchange...", 10, 0
    trace_queue       db "[TRACE] Declaring queue...", 10, 0
    trace_bind        db "[TRACE] Binding queue to exchange...", 10, 0
    trace_publish     db "[TRACE] Publishing message...", 10, 0
    trace_consume     db "[TRACE] Starting consumer...", 10, 0
    trace_waiting     db "[TRACE] Waiting for messages...", 10, 0
    trace_connection_open     db "  [TRACE] Connection Open ...", 0
    trace_connection_open_ok     db " Ok", 10, 0
    trace_connection_start     db "  [TRACE] Connection Start ...", 0
    trace_connection_start_ok     db " Ok", 10, 0
    trace_connection_tune     db "  [TRACE] Connection Tune ...", 0
    trace_connection_tune_ok     db " Ok", 10, 0
    trace_receive_frame     db "  [TRACE] Receive Frame...", 10, 0
    trace_send_amqp_header     db "  [TRACE] Send AMQP Header...", 10, 0

    ; AMQP Protocol header
    amqp_header    db "AMQP", 0, 0, 9, 1

    ; Prebuilt AMQP frames with correct byte order

    ; Connection.StartOk Frame
    conn_start_ok_frame:
        db 1                        ; frame type (method)
        db 0, 0                     ; channel 0
        db 0, 0, 0, (conn_start_ok_payload_end - conn_start_ok_payload) ; payload size
    conn_start_ok_payload:
        db 0, 10, 0, 11            ; Connection.StartOk (class 10, method 11)
        db 0, 0, 0, 0              ; client properties (empty table)
        db 5, "PLAIN"              ; mechanism (length + string)
        db 0, 0, 0, (sasl_end - sasl_start)  ; response length
    sasl_start:
        db 0, USERNAME
        db 0, PASSWORD
    sasl_end:
        db 5, "en_US"              ; locale (length + string)
    conn_start_ok_payload_end:
        db 0xCE                    ; frame end

    ; Connection.TuneOk Frame
    conn_tune_ok_frame:
        db 1                       ; frame type
        db 0, 0                    ; channel 0
        db 0, 0, 0, (conn_tune_ok_payload_end - conn_tune_ok_payload) ; payload size
    conn_tune_ok_payload:
        db 0, 10, 0, 31            ; Connection.TuneOk (class 10, method 31)
        db 0, 1                    ; channel max (0 = no limit)
        db 0, 2, 0, 0              ; frame max 131072
        db 0, 0                    ; heartbeat 0 (disabled)
    conn_tune_ok_payload_end:
        db 0xCE                    ; frame end

    ; Connection.Open Frame
    conn_open_frame:
        db 1                       ; frame type
        db 0, 0                    ; channel 0
        db 0, 0, 0, (conn_open_payload_end - conn_open_payload) ; payload size
    conn_open_payload:
        db 0, 10, 0, 40            ; Connection.Open (class 10, method 40)
        db vhost_len               ; virtual host length
        db VHOST                   ; virtual host
        db 0, 0                    ; reserved fields
    conn_open_payload_end:
        db 0xCE                    ; frame end

    ; Channel.Open Frame
    channel_open_frame:
        db 1                       ; frame type
        db 0, 1                    ; channel 1
        db 0, 0, 0, (channel_open_payload_end - channel_open_payload) ; payload size
    channel_open_payload:
        db 0, 20, 0, 10            ; Channel.Open (class 20, method 10)
        db 0                       ; reserved
    channel_open_payload_end:
        db 0xCE                    ; frame end

    ; Exchange.Declare Frame
    exchange_declare_frame:
        db 1                       ; frame type
        db 0, 1                    ; channel 1
        db 0, 0, 0, (exchange_declare_payload_end - exchange_declare_payload) ; payload size
    exchange_declare_payload:
        db 0, 40, 0, 10            ; Exchange.Declare (class 40, method 10)
        db 0, 0                    ; reserved
        db exchange_len            ; exchange name length
        db EXCHANGE                ; exchange name
        db 5, "topic"              ; exchange type (length + string)
        db 0b00000010              ; flags: durable=1
        db 0, 0, 0, 0              ; arguments (empty table)
    exchange_declare_payload_end:
        db 0xCE                    ; frame end

    ; Queue.Declare Frame
    queue_declare_frame:
        db 1                       ; frame type
        db 0, 1                    ; channel 1
        db 0, 0, 0, (queue_declare_payload_end - queue_declare_payload) ; payload size
    queue_declare_payload:
        db 0, 50, 0, 10            ; Queue.Declare (class 50, method 10)
        db 0, 0                    ; reserved
        db queue_name_len          ; queue name length
        db QUEUENAME               ; queue name
        db 0                       ; flags: not durable, not exclusive, not auto-delete
        db 0, 0, 0, 0              ; arguments (empty table)
    queue_declare_payload_end:
        db 0xCE                    ; frame end

    ; Queue.Bind Frame
    queue_bind_frame:
        db 1                       ; frame type
        db 0, 1                    ; channel 1
        db 0, 0, 0, (queue_bind_payload_end - queue_bind_payload) ; payload size
    queue_bind_payload:
        db 0, 50, 0, 20            ; Queue.Bind (class 50, method 20)
        db 0, 0                    ; reserved
        db queue_name_len          ; queue name length
        db QUEUENAME               ; queue name
        db exchange_len            ; exchange name length
        db EXCHANGE                ; exchange name
        db routing_key_len         ; routing key length
        db ROUTINGKEY              ; routing key
        db 0                       ; nowait flag
        db 0, 0, 0, 0              ; arguments (empty table)
    queue_bind_payload_end:
        db 0xCE                    ; frame end

    ; Basic.Consume Frame
    basic_consume_frame:
        db 1                       ; frame type
        db 0, 1                    ; channel 1
        db 0, 0, 0, (basic_consume_payload_end - basic_consume_payload) ; payload size
    basic_consume_payload:
        db 0, 60, 0, 20            ; Basic.Consume (class 60, method 20)
        db 0, 0                    ; reserved
        db queue_name_len          ; queue name length
        db QUEUENAME               ; queue name
        db 0                       ; consumer tag length (auto-generated)
        db 0b00000010              ; flags: no_ack=1
        db 0, 0, 0, 0              ; arguments (empty table)
    basic_consume_payload_end:
        db 0xCE                    ; frame end

    ; Basic.Publish Frame
    basic_publish_frame:
        db 1                       ; frame type
        db 0, 1                    ; channel 1
        db 0, 0, 0, (basic_publish_payload_end - basic_publish_payload) ; payload size
    basic_publish_payload:
        db 0, 60, 0, 40            ; Basic.Publish (class 60, method 40)
        db 0, 0                    ; reserved
        db exchange_len            ; exchange name length
        db EXCHANGE                ; exchange name
        db routing_key_len         ; routing key length
        db ROUTINGKEY              ; routing key
        db 0                       ; flags: not mandatory, not immediate
    basic_publish_payload_end:
        db 0xCE                    ; frame end

    ; Content Header Frame template in data segment
    content_header_frame:
        db 2                       ; frame type header (2)
        db 0, 1                    ; channel = 1
        db 0, 0, 0, (content_header_payload_end - content_header_payload) ; payload size
    content_header_payload:
        db 0, 60                   ; class id = 60 (Basic) - BIG ENDIAN
        db 0, 0                    ; weight = 0 - BIG ENDIAN
    content_header_body_size_pos:
        dq 0                       ; placeholder for body size (uint64 BE)
        db 0, 0                    ; property flags = 0 (no properties) - BIG ENDIAN
    content_header_payload_end:
        db 0xCE                    ; frame end

    ; Offsets relative to frame start:
    body_size_offset      equ content_header_body_size_pos - content_header_frame

    ;; ; Content Body Frame template in data segment
    ;; content_body_frame:
    ;;     db 3                  ; frame type body (3)
    ;;     db 0, 1                  ; Channel ID: 1
    ;; content_body_message_size:
    ;;     dd 0                       ; placeholder for message size (uint32 BE)
    ;; content_body_payload:
    ;; content_body_payload_end:
    ;;     db 0xCE               ; Frame end

    ;; ; Offsets relative to frame start:
    ;; message_size_offset      equ content_body_message_size - content_body_frame
    ;; message_payload_offset      equ content_body_payload - content_body_frame


%define RECEIVE_BUFFER_SIZE 4096
%define FRAME_BUFFER_SIZE 512
%define INPUT_BUFFER_SIZE 512
	
section .bss
    sockfd         resd 1
    sockaddr       resb 16
    addrinfo_hints resb 48     ; sizeof(struct addrinfo)
    addrinfo_res   resq 1      ; pointer to result
    receive_buffer resb RECEIVE_BUFFER_SIZE
    frame_buffer   resb FRAME_BUFFER_SIZE
    input_buffer   resb INPUT_BUFFER_SIZE
    message_len    resd 1
    hex_out_buffer: resb 2049
    ;; hex_out_buffer: times 2048 db 0    ; Buffer for hex output (1024 bytes * 2 + null)
    ; Runtime configuration overrides
    runtime_username resb USERNAME_MAX
    runtime_password resb PASSWORD_MAX
    runtime_host     resb HOSTNAME_MAX
    runtime_port     resb 8           ; port as string
    runtime_vhost    resb VHOST_MAX
    runtime_queuename resb QUEUENAME_MAX
    runtime_exchange resb EXCHANGE_MAX
    runtime_routingkey resb ROUTINGKEY_MAX

section .text
    global _start
    extern getaddrinfo


_start:
    ; Check arguments - at least mode required
    mov rax, [rsp]
    cmp rax, 2
    jl show_usage
    
    ; Parse optional arguments: [user] [host] [port] [vhost] [queuename] [exchange] [routingkey]
    ; argc stored in rax, argv pointers start at [rsp + 16]
    
    ; Parse username (argv[2])
    cmp rax, 3
    jl .parse_host
    mov rsi, [rsp + 24]         ; argv[2]
    mov rdi, runtime_username
    mov rcx, USERNAME_MAX
    call copy_argument
    
.parse_host:
    ; Parse host (argv[3])  
    cmp rax, 4
    jl .parse_port
    mov rsi, [rsp + 32]         ; argv[3]
    mov rdi, runtime_host
    mov rcx, HOSTNAME_MAX
    call copy_argument
    
.parse_port:
    ; Parse port (argv[4])
    cmp rax, 5
    jl .parse_vhost
    mov rsi, [rsp + 40]         ; argv[4]
    mov rdi, runtime_port
    mov rcx, 8
    call copy_argument
    
.parse_vhost:
    ; Parse vhost (argv[5])
    cmp rax, 6
    jl .parse_queuename
    mov rsi, [rsp + 48]         ; argv[5]
    mov rdi, runtime_vhost
    mov rcx, VHOST_MAX
    call copy_argument
    
.parse_queuename:
    ; Parse queuename (argv[6])
    cmp rax, 7
    jl .parse_exchange
    mov rsi, [rsp + 56]         ; argv[6]
    mov rdi, runtime_queuename
    mov rcx, QUEUENAME_MAX
    call copy_argument
    
.parse_exchange:
    ; Parse exchange (argv[7])
    cmp rax, 8
    jl .parse_routingkey
    mov rsi, [rsp + 64]         ; argv[7]
    mov rdi, runtime_exchange
    mov rcx, EXCHANGE_MAX
    call copy_argument
    
.parse_routingkey:
    ; Parse routingkey (argv[8])
    cmp rax, 9
    jl .check_password
    mov rsi, [rsp + 72]         ; argv[8]
    mov rdi, runtime_routingkey
    mov rcx, ROUTINGKEY_MAX
    call copy_argument

.check_password:
    ; If username was provided, prompt for password
    cmp byte [runtime_username], 0
    je .parse_mode
    call prompt_password

.parse_mode:
    ; Parse mode
    mov rsi, [rsp + 16]
    cmp byte [rsi], '-'
    jne mode_error
    mov al, [rsi + 1]
    cmp al, 's'
    je mode_send
    cmp al, 'r'
    je mode_receive
    jmp mode_error

mode_send:
    call setup_connection
    call setup_channel_and_exchange

    mov rdi, trace_read_stdin
    call print_trace

send_loop:
    call read_stdin_message
    test rax, rax
    jz cleanup_exit

    mov rdi, trace_publish
    call print_trace

    call publish_message

    mov rdi, trace_send
    call print_trace

    jmp send_loop

mode_receive:
    call setup_connection
    call setup_channel_and_exchange
    call setup_queue_and_bind

    mov rdi, trace_consume
    call print_trace
    call start_consuming

    mov rdi, trace_listening
    call print_trace

    mov rdi, trace_waiting
    call print_trace

receive_loop:
    call wait_for_message
    jmp receive_loop

    jmp cleanup_exit

setup_connection:
    mov rdi, trace_conn
    call print_trace
    call resolve_and_connect

    mov rdi, trace_handshake
    call print_trace
    call amqp_handshake
    ret

setup_channel_and_exchange:
    mov rdi, trace_channel
    call print_trace
    call open_channel

    mov rdi, trace_exchange
    call print_trace
    call declare_exchange
    ret

setup_queue_and_bind:
    mov rdi, trace_queue
    call print_trace
    call declare_queue

    mov rdi, trace_bind
    call print_trace
    call bind_queue
    ret

resolve_and_connect:
    ; Setup addrinfo hints
    mov rdi, addrinfo_hints
    mov rcx, 48
    xor rax, rax
    rep stosb               ; zero out hints structure
    
    ; Set hints: ai_family = AF_UNSPEC (0), ai_socktype = SOCK_STREAM (1)
    mov dword [addrinfo_hints + 8], 1   ; ai_socktype = SOCK_STREAM (offset 8)
    
    ; Align stack for C call
    push rbp
    mov rbp, rsp
    and rsp, -16
    
    ; Use runtime_host if set, otherwise use default host_str
    mov rdi, runtime_host
    cmp byte [rdi], 0       ; check if runtime_host is empty
    jne .use_runtime_host
    mov rdi, host_str       ; use default if runtime_host is empty
.use_runtime_host:
    
    ; Call getaddrinfo(hostname, NULL, &hints, &result)
    xor rsi, rsi                ; service (NULL)
    lea rdx, [addrinfo_hints]   ; hints
    lea rcx, [addrinfo_res]     ; result pointer
    call getaddrinfo
    
    mov rsp, rbp
    pop rbp
    
    test rax, rax
    jnz dns_fail_handler        ; getaddrinfo returns 0 on success
    
    ; Get the first addrinfo result
    mov rsi, [addrinfo_res]
    test rsi, rsi
    jz dns_fail_handler
    
    ; Create socket using address family from result
    mov rax, 41                     ; sys_socket
    mov edi, [rsi + 4]              ; ai_family from addrinfo (offset 4)
    mov rsi, 1                      ; SOCK_STREAM
    mov rdx, 0                      ; protocol
    syscall
    
    test rax, rax
    js socket_fail_handler
    mov [sockfd], eax
    
    ; Connect using sockaddr from addrinfo result
    mov rax, 42                     ; sys_connect
    mov rdi, [sockfd]
    mov rsi, [addrinfo_res]
    mov rsi, [rsi + 24]             ; ai_addr from addrinfo (offset 24)
    mov rdx, [addrinfo_res]
    mov edx, [rdx + 16]             ; ai_addrlen from addrinfo (offset 16)
    syscall
    
    test rax, rax
    js connect_fail_handler
    ret

amqp_handshake:
    ; Send protocol header
    mov rdi, trace_send_amqp_header
    call print_trace
    call send_amqp_header

    mov rdi, trace_connection_start
    call print_trace
    call receive_frame              ; Connection.Start

    mov rdi, trace_connection_start_ok
    call print_trace
    call send_connection_start_ok

    mov rdi, trace_connection_tune
    call print_trace
    call receive_frame              ; Connection.Tune

    mov rdi, trace_connection_tune_ok
    call print_trace
    call send_connection_tune_ok ; Connection.TuneOk

    mov rdi, trace_connection_open
    call print_trace
    call send_connection_open       ; Connection.Open

    mov rdi, trace_connection_open_ok
    call print_trace
    call receive_frame              ; Connection.OpenOk
    ret

send_amqp_header:
    mov rax, 1
    mov rdi, [sockfd]
    mov rsi, amqp_header
    mov rdx, 8
    syscall
    ret


send_connection_start_ok:
    ; Check if runtime username is provided
    cmp byte [runtime_username], 0
    je .send_static
    
    ; Build dynamic frame with runtime credentials
    call build_connection_start_ok_frame
    mov rdi, frame_buffer
    mov edx, eax                ; frame size returned in eax
    call send_frame
    ret
    
.send_static:
    mov rdi, conn_start_ok_frame
    mov rdx, (conn_start_ok_payload_end - conn_start_ok_frame + 1)
    call send_frame
    ret

; Build Connection.StartOk frame with runtime credentials
build_connection_start_ok_frame:
    push rsi
    push rdi
    push rcx
    push rdx
    
    mov rdi, frame_buffer
    
    ; Frame header
    mov byte [rdi], 1           ; frame type
    inc rdi
    mov word [rdi], 0           ; channel 0
    add rdi, 2
    add rdi, 4                  ; skip payload size for now
    
    ; Method header
    mov word [rdi], 0x000A      ; class 10 (Connection)
    add rdi, 2
    mov word [rdi], 0x000B      ; method 11 (StartOk)
    add rdi, 2
    
    ; Client properties table (empty for simplicity)
    mov dword [rdi], 0
    add rdi, 4
    
    ; Mechanism (PLAIN)
    mov byte [rdi], 5           ; length
    inc rdi
    mov rax, 'PLAIN'
    mov [rdi], rax
    add rdi, 4
    mov byte [rdi], 0           ; null terminator for PLAIN
    inc rdi
    
    ; Response (SASL authentication)
    ; Calculate total auth string length: 1 + username_len + 1 + password_len
    mov rsi, runtime_username
    call str_len
    mov rdx, rcx                ; username length
    
    mov rsi, runtime_password
    call str_len                ; password length in rcx
    
    add rdx, rcx                ; username + password lengths
    add rdx, 2                  ; + 2 null separators
    
    mov [rdi], dl               ; auth string length
    inc rdi
    
    ; Auth string format: \0username\0password
    mov byte [rdi], 0           ; first null
    inc rdi
    
    ; Copy username
    mov rsi, runtime_username
    mov rcx, rdx                ; reuse calculated length
    sub rcx, 2                  ; subtract nulls, keep username+password
    mov rax, rsi
    call str_len                ; get actual username length in rcx
.copy_username:
    test rcx, rcx
    jz .username_done
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .copy_username
.username_done:
    
    mov byte [rdi], 0           ; separator null
    inc rdi
    
    ; Copy password  
    mov rsi, runtime_password
    call str_len
.copy_password:
    test rcx, rcx
    jz .password_done
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .copy_password
.password_done:
    
    ; Locale
    mov byte [rdi], 5           ; length
    inc rdi
    mov rax, 'en_US'
    mov [rdi], rax
    add rdi, 4
    mov byte [rdi], 0
    inc rdi
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate and set payload size
    mov rax, rdi
    sub rax, frame_buffer
    sub rax, 8                  ; subtract frame header
    mov rsi, frame_buffer
    add rsi, 3
    mov [rsi], eax
    
    ; Return total frame size
    mov rax, rdi
    sub rax, frame_buffer
    
    pop rdx
    pop rcx
    pop rdi
    pop rsi
    ret

send_connection_tune_ok:
    mov rdi, conn_tune_ok_frame
    mov rdx, (conn_tune_ok_payload_end - conn_tune_ok_frame + 1)
    call send_frame
    ret

send_connection_open:
    ; Build dynamic Connection.Open frame
    call build_connection_open_frame
    mov rdi, frame_buffer
    mov edx, eax                ; frame size returned in eax
    call send_frame
    ret

; Build Connection.Open frame with runtime vhost
build_connection_open_frame:
    push rsi
    push rdi
    push rcx
    
    mov rdi, frame_buffer
    
    ; Frame header
    mov byte [rdi], 1           ; frame type  
    inc rdi
    mov word [rdi], 0           ; channel 0
    add rdi, 2
    
    ; Skip payload size for now
    add rdi, 4
    
    ; Method header
    mov word [rdi], 0x000A      ; class 10 (Connection)
    add rdi, 2
    mov word [rdi], 0x0028      ; method 40 (Open)  
    add rdi, 2
    
    ; Virtual host - use runtime or default
    mov rsi, runtime_vhost
    cmp byte [rsi], 0
    jne .use_runtime_vhost
    mov rsi, vhost
    mov cl, vhost_len
    jmp .copy_vhost
    
.use_runtime_vhost:
    call str_len                ; get length in rcx
    
.copy_vhost:
    mov [rdi], cl               ; vhost length
    inc rdi
    rep movsb                   ; copy vhost string
    
    ; Reserved fields
    mov word [rdi], 0
    add rdi, 2
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate and set payload size
    mov rax, rdi
    sub rax, frame_buffer       ; total frame size
    sub rax, 8                  ; subtract frame header size  
    mov rsi, frame_buffer
    add rsi, 3
    mov [rsi], eax              ; set payload size (big endian handled by hardware)
    
    ; Return total frame size in eax
    mov rax, rdi
    sub rax, frame_buffer
    
    pop rcx
    pop rdi
    pop rsi
    ret

open_channel:
    mov rdi, channel_open_frame
    mov rdx, (channel_open_payload_end - channel_open_frame + 1)
    call send_frame
    call receive_frame
    ret

declare_exchange:
    ; Build dynamic Exchange.Declare frame
    call build_exchange_declare_frame
    mov rdi, frame_buffer
    mov edx, eax                ; frame size returned in eax
    call send_frame
    call receive_frame
    ret

build_exchange_declare_frame:
    push rsi
    push rdi
    push rcx
    
    mov rdi, frame_buffer
    
    ; Frame header
    mov byte [rdi], 1           ; frame type
    inc rdi
    mov word [rdi], 1           ; channel 1
    add rdi, 2
    add rdi, 4                  ; skip payload size
    
    ; Method header
    mov word [rdi], 0x0028      ; class 40 (Exchange)
    add rdi, 2
    mov word [rdi], 0x000A      ; method 10 (Declare)
    add rdi, 2
    
    ; Reserved short
    mov word [rdi], 0
    add rdi, 2
    
    ; Exchange name - use runtime or default
    mov rsi, runtime_exchange
    cmp byte [rsi], 0
    jne .use_runtime_exchange
    mov rsi, exchange
    mov rcx, exchange_len
    jmp .copy_exchange
    
.use_runtime_exchange:
    call str_len
    
.copy_exchange:
    mov [rdi], cl               ; exchange name length
    inc rdi
    rep movsb                   ; copy exchange name
    
    ; Type (topic)
    mov byte [rdi], 5           ; length
    inc rdi
    mov rax, 'topic'
    mov [rdi], rax
    add rdi, 5
    
    ; Flags (passive=0, durable=1, auto-delete=0, internal=0, nowait=0)
    mov byte [rdi], 0x02
    inc rdi
    
    ; Arguments table (empty)
    mov dword [rdi], 0
    add rdi, 4
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate and set payload size
    mov rax, rdi
    sub rax, frame_buffer
    sub rax, 8
    mov rsi, frame_buffer
    add rsi, 3
    mov [rsi], eax
    
    ; Return total frame size
    mov rax, rdi
    sub rax, frame_buffer
    
    pop rcx
    pop rdi
    pop rsi  
    ret

declare_queue:
    ; Build dynamic Queue.Declare frame
    call build_queue_declare_frame  
    mov rdi, frame_buffer
    mov edx, eax                ; frame size returned in eax
    call send_frame
    call receive_frame
    ret

; Build Queue.Declare frame with runtime queue name
build_queue_declare_frame:
    push rsi
    push rdi
    push rcx
    
    mov rdi, frame_buffer
    
    ; Frame header
    mov byte [rdi], 1           ; frame type
    inc rdi
    mov word [rdi], 1           ; channel 1
    add rdi, 2
    add rdi, 4                  ; skip payload size
    
    ; Method header  
    mov word [rdi], 0x0032      ; class 50 (Queue)
    add rdi, 2
    mov word [rdi], 0x000A      ; method 10 (Declare)
    add rdi, 2
    
    ; Reserved short
    mov word [rdi], 0
    add rdi, 2
    
    ; Queue name - use runtime or default
    mov rsi, runtime_queuename
    cmp byte [rsi], 0
    jne .use_runtime_queue
    mov rsi, queue_name
    mov rcx, queue_name_len
    jmp .copy_queue
    
.use_runtime_queue:
    call str_len
    
.copy_queue:
    mov [rdi], cl               ; queue name length
    inc rdi
    rep movsb                   ; copy queue name
    
    ; Flags (passive=0, durable=1, exclusive=0, auto-delete=0, nowait=0)
    mov byte [rdi], 0x02
    inc rdi
    
    ; Arguments table (empty)
    mov dword [rdi], 0
    add rdi, 4
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate and set payload size
    mov rax, rdi
    sub rax, frame_buffer
    sub rax, 8
    mov rsi, frame_buffer
    add rsi, 3
    mov [rsi], eax
    
    ; Return total frame size
    mov rax, rdi
    sub rax, frame_buffer
    
    pop rcx
    pop rdi
    pop rsi
    ret

bind_queue:
    ; Build dynamic Queue.Bind frame  
    call build_queue_bind_frame
    mov rdi, frame_buffer
    mov edx, eax                ; frame size returned in eax
    call send_frame
    call receive_frame
    ret

; Build Queue.Bind frame with runtime parameters
build_queue_bind_frame:
    push rsi
    push rdi
    push rcx
    push rdx
    
    mov rdi, frame_buffer
    
    ; Frame header
    mov byte [rdi], 1           ; frame type
    inc rdi
    mov word [rdi], 1           ; channel 1
    add rdi, 2
    add rdi, 4                  ; skip payload size
    
    ; Method header
    mov word [rdi], 0x0032      ; class 50 (Queue)
    add rdi, 2
    mov word [rdi], 0x0014      ; method 20 (Bind)
    add rdi, 2
    
    ; Reserved short
    mov word [rdi], 0
    add rdi, 2
    
    ; Queue name - use runtime or default
    mov rsi, runtime_queuename
    cmp byte [rsi], 0
    jne .use_runtime_queue
    mov rsi, queue_name
    mov rcx, queue_name_len
    jmp .copy_queue
    
.use_runtime_queue:
    call str_len
    
.copy_queue:
    mov [rdi], cl               ; queue name length
    inc rdi
    rep movsb                   ; copy queue name
    
    ; Exchange name - use runtime or default
    mov rsi, runtime_exchange
    cmp byte [rsi], 0
    jne .use_runtime_exchange
    mov rsi, exchange  
    mov rcx, exchange_len
    jmp .copy_exchange
    
.use_runtime_exchange:
    call str_len
    
.copy_exchange:
    mov [rdi], cl               ; exchange name length
    inc rdi
    rep movsb                   ; copy exchange name
    
    ; Routing key - use runtime or default
    mov rsi, runtime_routingkey
    cmp byte [rsi], 0
    jne .use_runtime_routing
    mov rsi, routing_key
    mov rcx, routing_key_len
    jmp .copy_routing
    
.use_runtime_routing:
    call str_len
    
.copy_routing:
    mov [rdi], cl               ; routing key length
    inc rdi
    rep movsb                   ; copy routing key
    
    ; Nowait flag
    mov byte [rdi], 0
    inc rdi
    
    ; Arguments table (empty)
    mov dword [rdi], 0
    add rdi, 4
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate and set payload size
    mov rax, rdi
    sub rax, frame_buffer
    sub rax, 8
    mov rsi, frame_buffer
    add rsi, 3
    mov [rsi], eax
    
    ; Return total frame size
    mov rax, rdi
    sub rax, frame_buffer
    
    pop rdx
    pop rcx
    pop rdi
    pop rsi
    ret

start_consuming:
    ; Build dynamic Basic.Consume frame
    call build_basic_consume_frame
    mov rdi, frame_buffer
    mov edx, eax                ; frame size returned in eax
    call send_frame
    call receive_frame
    ret

; Build Basic.Consume frame with runtime queue name
build_basic_consume_frame:
    push rsi
    push rdi
    push rcx
    
    mov rdi, frame_buffer
    
    ; Frame header
    mov byte [rdi], 1           ; frame type
    inc rdi
    mov word [rdi], 1           ; channel 1
    add rdi, 2
    add rdi, 4                  ; skip payload size
    
    ; Method header
    mov word [rdi], 0x003C      ; class 60 (Basic)
    add rdi, 2
    mov word [rdi], 0x0014      ; method 20 (Consume)
    add rdi, 2
    
    ; Reserved short
    mov word [rdi], 0
    add rdi, 2
    
    ; Queue name - use runtime or default
    mov rsi, runtime_queuename
    cmp byte [rsi], 0
    jne .use_runtime_queue
    mov rsi, queue_name
    mov rcx, queue_name_len
    jmp .copy_queue
    
.use_runtime_queue:
    call str_len
    
.copy_queue:
    mov [rdi], cl               ; queue name length
    inc rdi
    rep movsb                   ; copy queue name
    
    ; Consumer tag (empty)
    mov byte [rdi], 0
    inc rdi
    
    ; Flags (no-local=0, no-ack=1, exclusive=0, nowait=0)
    mov byte [rdi], 0x02
    inc rdi
    
    ; Arguments table (empty)
    mov dword [rdi], 0
    add rdi, 4
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate and set payload size
    mov rax, rdi
    sub rax, frame_buffer
    sub rax, 8
    mov rsi, frame_buffer
    add rsi, 3
    mov [rsi], eax
    
    ; Return total frame size
    mov rax, rdi
    sub rax, frame_buffer
    
    pop rcx
    pop rdi
    pop rsi
    ret

publish_message:
    ; Build and send dynamic Basic.Publish method frame
    call build_basic_publish_frame
    mov rdi, frame_buffer
    mov edx, eax                ; frame size returned in eax
    call send_frame

    ; Send content header
    call send_content_header

    ; Send content body
    call send_content_body
    ret

; Build Basic.Publish frame with runtime exchange and routing key
build_basic_publish_frame:
    push rsi
    push rdi
    push rcx
    
    mov rdi, frame_buffer
    
    ; Frame header
    mov byte [rdi], 1           ; frame type
    inc rdi
    mov word [rdi], 1           ; channel 1
    add rdi, 2
    add rdi, 4                  ; skip payload size
    
    ; Method header
    mov word [rdi], 0x003C      ; class 60 (Basic)
    add rdi, 2
    mov word [rdi], 0x0028      ; method 40 (Publish)
    add rdi, 2
    
    ; Reserved short
    mov word [rdi], 0
    add rdi, 2
    
    ; Exchange name - use runtime or default
    mov rsi, runtime_exchange
    cmp byte [rsi], 0
    jne .use_runtime_exchange
    mov rsi, exchange
    mov rcx, exchange_len
    jmp .copy_exchange
    
.use_runtime_exchange:
    call str_len
    
.copy_exchange:
    mov [rdi], cl               ; exchange name length
    inc rdi
    rep movsb                   ; copy exchange name
    
    ; Routing key - use runtime or default
    mov rsi, runtime_routingkey
    cmp byte [rsi], 0
    jne .use_runtime_routing
    mov rsi, routing_key
    mov rcx, routing_key_len
    jmp .copy_routing
    
.use_runtime_routing:
    call str_len
    
.copy_routing:
    mov [rdi], cl               ; routing key length
    inc rdi
    rep movsb                   ; copy routing key
    
    ; Flags (mandatory=0, immediate=0)
    mov byte [rdi], 0
    inc rdi
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate and set payload size
    mov rax, rdi
    sub rax, frame_buffer
    sub rax, 8
    mov rsi, frame_buffer
    add rsi, 3
    mov [rsi], eax
    
    ; Return total frame size
    mov rax, rdi
    sub rax, frame_buffer
    
    pop rcx
    pop rdi
    pop rsi
    ret

send_content_header:
    ; Build AMQP header frame
    ; Copy template to frame buffer
    lea rdi, [frame_buffer]
    mov rsi, content_header_frame
    mov rcx, (content_header_payload_end - content_header_frame + 1)
    cmp rcx, FRAME_BUFFER_SIZE
    ja frame_buffer_overflow
    rep movsb

    ; Set body size (big endian conversion)
    mov eax, [message_len]       ; load 32-bit length
    bswap eax                   ; convert to big-endian
    mov dword [frame_buffer + body_size_offset], 0      ; upper 4 bytes = 0
    mov dword [frame_buffer + body_size_offset + 4], eax ; lower 4 bytes = be

    ; Output frame as hex to stderr
    lea rdi, [frame_buffer]         ; frame start
    mov rdx, (content_header_payload_end - content_header_frame + 1)
    call dump_frame_hex_spaced      ; use spaced version for readability
    mov rdi, hex_out_buffer         ; print hex output
    call print_trace
    mov rdi, newline                ; add newline
    call print_trace

    ; Send frame
    lea rdi, [frame_buffer]
    mov rdx, (content_header_payload_end - content_header_frame + 1)
    call send_frame
    ret

send_content_body:
    ; Build AMQP body frame
    lea rdi, [frame_buffer]
    mov byte [rdi], 3               ; body frame type
    mov word [rdi + 1], 0x0100      ; channel 1 (big endian)
    ; Frame size (big endian)
    mov eax, [message_len]
    cmp eax, FRAME_BUFFER_SIZE - 8
    ja frame_buffer_overflow
    bswap eax
    mov dword [rdi + 3], eax
    ; Copy message
    lea rsi, [input_buffer]
    add rdi, 7
    mov ecx, [message_len]
    rep movsb
    ; Frame end
    mov byte [rdi], 0xCE

    ; Output frame as hex to stderr
    lea rdi, [frame_buffer]         ; frame start
    mov edx, [message_len]          ; message length
    add rdx, 8                      ; + 8 for frame header (7) + frame end (1)
    call dump_frame_hex_spaced      ; use spaced version for readability
    mov rdi, hex_out_buffer         ; print hex output
    call print_trace
    mov rdi, newline                ; add newline
    call print_trace

    ; Send frame
    lea rdi, [frame_buffer]
    mov edx, [message_len]
    add rdx, 8
    call send_frame
    ret

send_frame:
    mov rax, 1
    mov rsi, rdi
    mov rdi, [sockfd]
    syscall
    ret

wait_for_message:
wait_loop:
    call receive_frame

    ; Check for Basic.Deliver (method frame, class 60, method 60)
    cmp byte [receive_buffer], 1
    jne wait_loop

    mov ax, [receive_buffer + 7]
    cmp ax, 0x3C00                  ; Basic class (big endian)
    jne wait_loop

    mov ax, [receive_buffer + 9]
    cmp ax, 0x3C00                  ; Deliver method (big endian)
    jne wait_loop

    ; Receive content header and body
    call receive_frame
    call receive_frame

%ifdef TRACING
    ; Print message	
    mov rdi, trace_receive
    call print_string_to_stdout
%endif
    lea rdi, [receive_buffer + 7]
    call print_string_to_stdout

    mov rdi, newline
    call print_string_to_stdout
    ret

receive_frame:
    ; Read frame header (7 bytes)
    mov rax, 0
    mov rdi, [sockfd]
    lea rsi, [receive_buffer]
    mov rdx, 7
    syscall

    test rax, rax
    jle cleanup_exit

    ; Extract payload size (convert from big endian)
    mov eax, [receive_buffer + 3]
    bswap eax

    ; Check payload size fits in buffer
    mov ecx, RECEIVE_BUFFER_SIZE
    sub ecx, 7
    cmp eax, ecx
    ja receive_buffer_overflow
	
    ; Read payload + frame end
    mov rdi, [sockfd]
    lea rsi, [receive_buffer + 7]
    mov rdx, rax
    inc rdx                         ; include frame end byte
    mov rax, 0
    syscall
    ; Zero terminate payload after frame data (exclude frame end byte)
    mov byte [receive_buffer + 7 + rax - 1], 0
    ret

read_stdin_message:
    mov rax, 0                      ; sys_read
    mov rdi, 0                      ; stdin
    lea rsi, [input_buffer]
    mov rdx, (INPUT_BUFFER_SIZE - 1)
    syscall

    test rax, rax
    jle read_done

    ; Remove newline
    dec rax
    mov byte [input_buffer + rax], 0
    mov [message_len], eax

    ; Return non-zero for success
    test eax, eax
    jz read_stdin_message           ; skip empty lines
    mov rax, 1
    ret

read_done:
    xor rax, rax
    ret

print_string_to_stdout:
    push rdi
    call strlen
    mov rdx, rax
    pop rsi

    mov rax, 1                      ; sys_write
    mov rdi, 1                      ; stdout
    syscall
    ret

print_trace:
%ifndef TRACING
    ret
%endif

print_string_to_stderr:
    push rdi
    call strlen
    mov rdx, rax
    pop rsi

    mov rax, 1     ; sys_write
    mov rdi, 2     ; stderr
    syscall
    ret

strlen:
    xor rax, rax
strlen_loop:
    cmp byte [rdi + rax], 0
    je strlen_done
    inc rax
    jmp strlen_loop
strlen_done:
    ret


; Hex dump functions for NASM x64 Linux

; Convert byte in AL to 2-character hex string
; Input: AL = byte to convert
; Output: AH = high nibble hex char, AL = low nibble hex char
byte_to_hex:
    push rbx
    mov bl, al              ; save original byte
    ; High nibble
    shr al, 4               ; shift high nibble to low
    and al, 0x0F            ; mask to 4 bits
    cmp al, 9
    jle .high_digit
    add al, 'A' - 10        ; A-F
    jmp .high_done
.high_digit:
    add al, '0'             ; 0-9
.high_done:
    mov ah, al              ; store high nibble char
    ; Low nibble
    mov al, bl              ; restore original byte
    and al, 0x0F            ; mask low nibble
    cmp al, 9
    jle .low_digit
    add al, 'A' - 10        ; A-F
    jmp .low_done
.low_digit:
    add al, '0'             ; 0-9
.low_done:
    pop rbx
    ret

; Convert buffer to hex string
; Input: RDI = buffer pointer, RDX = buffer length
; Output: hex string written to hex_out_buffer (null terminated)
dump_frame_hex:
    push rsi
    push rdi
    push rcx
    push rax

    mov byte [hex_out_buffer + 2048], 0 ; terminate with a zero byte
    mov rsi, rdi            ; source buffer
    lea rdi, [hex_out_buffer] ; destination buffer
    mov rcx, rdx            ; byte count

convert_loop:
    test rcx, rcx
    jz convert_done

    lodsb                   ; load byte from [rsi] into al, increment rsi
    call byte_to_hex        ; convert to hex chars in ah, al

    mov [rdi], ah           ; store high nibble
    inc rdi
    mov [rdi], al           ; store low nibble
    inc rdi

    dec rcx
    jmp convert_loop

convert_done:
    mov byte [rdi], 0       ; null terminate

    pop rax
    pop rcx
    pop rdi
    pop rsi
    ret

; Alternative version that adds spaces between bytes for readability
; Input: RDI = buffer pointer, RDX = buffer length
; Output: hex string with spaces written to hex_out_buffer
dump_frame_hex_spaced:
    push rsi
    push rdi
    push rcx
    push rax

    mov byte [hex_out_buffer + 2048], 0 ; terminate with a zero byte
    mov rsi, rdi            ; source buffer
    lea rdi, [hex_out_buffer] ; destination buffer
    mov rcx, rdx            ; byte count

convert_loop_spaced:
    test rcx, rcx
    jz convert_done_spaced

    lodsb                   ; load byte from [rsi] into al, increment rsi
    call byte_to_hex        ; convert to hex chars in ah, al

    mov [rdi], ah           ; store high nibble
    inc rdi
    mov [rdi], al           ; store low nibble
    inc rdi

    ; Add space between bytes (except for last byte)
    cmp rcx, 1
    je skip_space
    mov byte [rdi], ' '
    inc rdi

skip_space:
    dec rcx
    jmp convert_loop_spaced

convert_done_spaced:
    mov byte [rdi], 0       ; null terminate

    pop rax
    pop rcx
    pop rdi
    pop rsi
    ret

; Calculate string length 
; Input: rsi = string pointer
; Output: rcx = length
str_len:
    push rax
    push rsi
    xor rcx, rcx
.count_loop:
    mov al, [rsi]
    test al, al
    jz .done
    inc rcx
    inc rsi
    jmp .count_loop
.done:
    pop rsi
    pop rax
    ret

; Copy command line argument to buffer if present and non-empty
; Input: rsi = source string pointer, rdi = destination buffer, rcx = buffer size
; Modifies: rax, rdx
copy_argument:
    push rsi
    push rdi
    push rcx
    
    ; Check if argument exists and is not empty
    test rsi, rsi
    jz .done
    cmp byte [rsi], 0
    je .done
    
    ; Copy argument to buffer
    dec rcx                     ; leave space for null terminator
.copy_loop:
    test rcx, rcx
    jz .copy_done
    mov al, [rsi]
    test al, al
    jz .copy_done
    mov [rdi], al
    inc rsi
    inc rdi  
    dec rcx
    jmp .copy_loop
.copy_done:
    mov byte [rdi], 0
    
.done:
    pop rcx
    pop rdi
    pop rsi
    ret

; Prompt for password with echo disabled
prompt_password:
    push rax
    push rdi
    push rsi
    push rdx
    
    ; Print password prompt to stderr
    mov rax, 1                  ; sys_write
    mov rdi, 2                  ; stderr
    mov rsi, password_prompt
    mov rdx, password_prompt_len
    syscall
    
    ; Disable terminal echo (basic implementation)
    ; Read password from stdin
    mov rax, 0                  ; sys_read
    mov rdi, 0                  ; stdin
    mov rsi, runtime_password
    mov rdx, PASSWORD_MAX - 1
    syscall
    
    ; Remove trailing newline if present
    test rax, rax
    jz .password_done
    mov rdi, runtime_password
    add rdi, rax
    dec rdi
    cmp byte [rdi], 10          ; newline
    jne .password_done
    mov byte [rdi], 0
    
.password_done:
    pop rdx
    pop rsi
    pop rdi
    pop rax
    ret

cleanup_exit:
    mov rax, 3                      ; sys_close
    mov rdi, [sockfd]
    syscall

    mov rax, 60                     ; sys_exit
    xor rdi, rdi
    syscall

show_usage:
    mov rdi, usage_msg
    call print_string_to_stderr
    jmp exit_error

mode_error:
    mov rdi, mode_err
    call print_string_to_stderr
    jmp exit_error

dns_fail_handler:
    mov rdi, error_dns_fail
    call print_string_to_stderr
    jmp exit_error

socket_fail_handler:
    mov rdi, error_sock_fail
    call print_string_to_stderr
    jmp exit_error

connect_fail_handler:
    mov rdi, error_conn_fail
    call print_string_to_stderr
    jmp exit_error

frame_buffer_overflow:
    mov rdi, error_frame_overflow
    call print_string_to_stderr
    jmp exit_error

receive_buffer_overflow:
    mov rdi, error_receive_buffer_overflow
    call print_string_to_stderr
    jmp exit_error

exit_error:
    mov rax, 60                     ; sys_exit
    mov rdi, 1                      ; exit code 1
    syscall
