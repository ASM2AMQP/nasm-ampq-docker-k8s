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

; Structure definition for addrinfo hints
struc hints_t
    .ai_flags    resq 1      ; int, usually 4 bytes but qword for alignment
    .ai_family   resq 1
    .ai_socktype resq 1
    .ai_protocol resq 1
    ; no need for ai_addr, ai_canonname, ai_next here
    ; add padding if you want 32 bytes aligned or so
endstruc

; Size of the hints structure
hints_t_size equ 32

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
        db (sasl_end - sasl_start) ; response length (1 byte)
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
    sockaddr       resb 128        ; Increased size to accommodate both IPv4 and IPv6
    receive_buffer resb RECEIVE_BUFFER_SIZE
    frame_buffer   resb FRAME_BUFFER_SIZE
    input_buffer   resb INPUT_BUFFER_SIZE
    message_len    resd 1
    hex_out_buffer: resb 2049
    addrinfo_result resq 1         ; Pointer to getaddrinfo result
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
    runtime_args_provided resb 1          ; flag: 1 if any runtime args provided, 0 for all defaults

section .text
    global _start
    extern getaddrinfo
    extern freeaddrinfo


_start:
    ; Check arguments - at least mode required
    mov rax, [rsp]
    cmp rax, 2
    jl show_usage
    
    ; Initialize runtime buffers with default values
    call init_runtime_defaults
    
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
    ; If username was provided as argument AND is not empty, prompt for password
    ; Check if argc >= 3 (meaning username argument was provided)
    mov rbx, [rsp]              ; argc
    cmp rbx, 3
    jl .init_port_default
    ; Also check if username is not empty
    cmp byte [runtime_username], 0
    je .init_port_default
    call prompt_password

.init_port_default:
    ; Initialize port string if not provided
    cmp byte [runtime_port], 0
    jne .parse_mode
    ; Convert compile-time PORT to string in runtime_port
    mov rdi, runtime_port
    mov rax, PORT
    call int_to_string

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
    ; Align stack for C call
    push rbp
    mov rbp, rsp
    and rsp, -16
    
    ; Allocate hints structure on stack
    sub rsp, hints_t_size
    
    ; Initialize hints structure on stack
    mov qword [rsp + hints_t.ai_flags], 0      ; ai_flags = 0
    mov qword [rsp + hints_t.ai_family], 0     ; ai_family = AF_UNSPEC for dual-stack
    mov qword [rsp + hints_t.ai_socktype], 1   ; ai_socktype = SOCK_STREAM
    mov qword [rsp + hints_t.ai_protocol], 0   ; ai_protocol = 0 (any)

    ; Use runtime_host if set, otherwise use default host_str
    mov rdi, runtime_host
    cmp byte [rdi], 0       ; check if runtime_host is empty
    jne .use_runtime_host
    mov rdi, host_str       ; use default if runtime_host is empty
.use_runtime_host:
    
    ; Prepare port string - use runtime port if provided, otherwise convert default
    mov rsi, runtime_port
    cmp byte [rsi], 0
    jne .call_getaddrinfo
    
    ; Convert compile-time PORT to string for getaddrinfo
    push rdi                ; save hostname
    mov rdi, runtime_port   ; destination buffer
    mov rax, PORT           ; port number
    call int_to_string      ; convert to string
    pop rdi                 ; restore hostname
    mov rsi, runtime_port   ; use converted port string

.call_getaddrinfo:
    ; Call getaddrinfo(hostname, port_string, hints, &result)
    ; rdi = hostname (already set)
    ; rsi = port string (already set) 
    mov rdx, rsp            ; pointer to stack-allocated hints structure
    mov rcx, addrinfo_result
    call getaddrinfo

    mov rsp, rbp
    pop rbp

    test rax, rax
    jnz dns_fail_handler    ; getaddrinfo returns 0 on success

    ; Try each address until one connects
    mov rsi, [addrinfo_result]  ; First addrinfo structure

.try_address:
    test rsi, rsi
    jz connect_fail_handler     ; No more addresses to try

    ; Save current addrinfo pointer
    mov r8, rsi

    ; Create socket with the address family from addrinfo  
    mov rax, 41             ; sys_socket
    mov edi, [rsi + 4]      ; ai_family from addrinfo
    push rsi                ; save addrinfo pointer before overwriting rsi
    mov rsi, 1              ; SOCK_STREAM
    mov rdx, 0              ; protocol
    syscall
    pop rsi                 ; restore addrinfo pointer

    test rax, rax
    js .try_next_address    ; socket creation failed, try next
    mov [sockfd], eax       ; save socket fd

    ; Connect using the sockaddr from addrinfo
    ; Save r8 since syscalls can modify it
    push r8
    mov rax, 42             ; sys_connect
    mov rdi, [sockfd]
    mov rsi, [r8 + 24]      ; ai_addr from addrinfo
    mov edx, [r8 + 16]      ; ai_addrlen from addrinfo  
    syscall
    pop r8                  ; restore r8

    test rax, rax
    jns .connection_success ; Connection successful

    ; Close failed socket and try next address
    push r8                 ; save r8 again
    mov rax, 3              ; sys_close
    mov rdi, [sockfd]
    syscall
    pop r8                  ; restore r8

.try_next_address:
    mov rsi, [r8 + 40]      ; ai_next - move to next address (fixed offset)
    jmp .try_address

.connection_success:
    
    ; Free the addrinfo result
    push rbp
    mov rbp, rsp
    and rsp, -16
    mov rdi, [addrinfo_result]
    call freeaddrinfo
    mov rsp, rbp
    pop rbp
    
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
    ; Check if any runtime arguments were provided
    cmp byte [runtime_args_provided], 0
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
    mov word [rdi], 0x0A00      ; class 10 (Connection) - big endian
    add rdi, 2
    mov word [rdi], 0x0B00      ; method 11 (StartOk) - big endian
    add rdi, 2
    
    ; Client properties table (empty for simplicity)
    mov dword [rdi], 0
    add rdi, 4
    
    ; Mechanism (PLAIN) - shortstr format: 1 byte length + string
    mov byte [rdi], 5           ; length 5 (1 byte for shortstr)
    inc rdi
    mov dword [rdi], 'PLAI'     ; First 4 chars: P,L,A,I
    add rdi, 4
    mov byte [rdi], 'N'         ; Last char: N
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
    
    ; Write auth string length as 4-byte big endian
    mov eax, edx
    bswap eax
    mov [rdi], eax              ; auth string length (4 bytes big endian)
    add rdi, 4
    
    ; Auth string format: \0username\0password
    mov byte [rdi], 0           ; first null
    inc rdi
    
    ; Copy username
    mov rsi, runtime_username
    call str_len                ; get username length in rcx
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
    call str_len                ; get password length in rcx
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
    
    ; Locale - shortstr format: 1 byte length + string
    mov byte [rdi], 5           ; length 5 (1 byte for shortstr)
    inc rdi
    mov dword [rdi], 'en_U'     ; First 4 chars
    add rdi, 4
    mov byte [rdi], 'S'         ; Last char
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
    bswap eax
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
    mov word [rdi], 0x0A00      ; class 10 (Connection) - big endian
    add rdi, 2
    mov word [rdi], 0x2800      ; method 40 (Open) - big endian
    add rdi, 2
    
    ; Virtual host - use runtime or default
    mov rsi, runtime_vhost
    cmp byte [rsi], 0
    jne .use_runtime_vhost
    mov rsi, vhost
    mov rcx, vhost_len
    jmp .copy_vhost
    
.use_runtime_vhost:
    call str_len                ; get length in rcx
    
.copy_vhost:
    mov [rdi], cl               ; vhost length
    inc rdi
    movzx rcx, cl               ; ensure rcx contains only the length value
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
    bswap eax                   ; convert to big endian
    mov [rsi], eax              ; set payload size
    
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
    mov word [rdi], 0x0100      ; channel 1 - big endian
    add rdi, 2
    add rdi, 4                  ; skip payload size
    
    ; Method header
    mov word [rdi], 0x2800      ; class 40 (Exchange) - big endian
    add rdi, 2
    mov word [rdi], 0x0A00      ; method 10 (Declare) - big endian
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
    movzx rcx, cl               ; ensure rcx contains only the length value
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
    bswap eax
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
    mov word [rdi], 0x0100      ; channel 1 - big endian
    add rdi, 2
    add rdi, 4                  ; skip payload size
    
    ; Method header
    mov word [rdi], 0x3200      ; class 50 (Queue) - big endian
    add rdi, 2
    mov word [rdi], 0x0A00      ; method 10 (Declare) - big endian
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
    movzx rcx, cl               ; ensure rcx contains only the length value
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
    bswap eax
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
    mov word [rdi], 0x0100      ; channel 1 - big endian
    add rdi, 2
    add rdi, 4                  ; skip payload size
    
    ; Method header
    mov word [rdi], 0x3200      ; class 50 (Queue) - big endian
    add rdi, 2
    mov word [rdi], 0x1400      ; method 20 (Bind) - big endian
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
    movzx rcx, cl               ; ensure rcx contains only the length value
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
    movzx rcx, cl
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
    movzx rcx, cl
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
    bswap eax
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
    mov word [rdi], 0x0100      ; channel 1 - big endian
    add rdi, 2
    add rdi, 4                  ; skip payload size
    
    ; Method header
    mov word [rdi], 0x3C00      ; class 60 (Basic) - big endian
    add rdi, 2
    mov word [rdi], 0x1400      ; method 20 (Consume) - big endian
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
    movzx rcx, cl
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
    bswap eax
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
    mov word [rdi], 0x0100      ; channel 1 - big endian
    add rdi, 2
    add rdi, 4                  ; skip payload size
    
    ; Method header
    mov word [rdi], 0x3C00      ; class 60 (Basic) - big endian
    add rdi, 2
    mov word [rdi], 0x2800      ; method 40 (Publish) - big endian
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
    movzx rcx, cl               ; ensure rcx contains only the length value
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
    movzx rcx, cl
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
    bswap eax
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
    cmp ax, 0x003C                  ; Basic class (big endian)
    jne wait_loop

    mov ax, [receive_buffer + 9]
    cmp ax, 0x003C                  ; Deliver method (big endian)
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

; Initialize runtime configuration buffers with compile-time defaults
init_runtime_defaults:
    push rsi
    push rdi
    push rcx
    push rax
    
    ; Initialize flag to indicate no runtime args provided yet
    mov byte [runtime_args_provided], 0
    
    ; Initialize username with default
    mov rsi, username
    mov rdi, runtime_username
    mov rcx, username_len
    call copy_string_with_len
    
    ; Initialize password with default
    mov rsi, password
    mov rdi, runtime_password
    mov rcx, password_len
    call copy_string_with_len
    
    ; Initialize host with default (copy until null terminator)
    mov rsi, host_str
    mov rdi, runtime_host
    mov rcx, HOSTNAME_MAX - 1
    call copy_string_until_null
    
    ; Initialize vhost with default
    mov rsi, vhost
    mov rdi, runtime_vhost
    mov rcx, vhost_len
    call copy_string_with_len
    
    ; Initialize queue name with default
    mov rsi, queue_name
    mov rdi, runtime_queuename
    mov rcx, queue_name_len
    call copy_string_with_len
    
    ; Initialize exchange with default
    mov rsi, exchange
    mov rdi, runtime_exchange
    mov rcx, exchange_len
    call copy_string_with_len
    
    ; Initialize routing key with default
    mov rsi, routing_key
    mov rdi, runtime_routingkey
    mov rcx, routing_key_len
    call copy_string_with_len
    
    pop rax
    pop rcx
    pop rdi
    pop rsi
    ret

; Copy string with known length
; Input: rsi = source, rdi = dest, rcx = length
copy_string_with_len:
    push rsi
    push rdi
    push rcx
    
.copy_loop:
    test rcx, rcx
    jz .done
    mov al, [rsi]
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .copy_loop
    
.done:
    mov byte [rdi], 0       ; null terminate
    pop rcx
    pop rdi
    pop rsi
    ret

; Copy string until null terminator (with max length)
; Input: rsi = source, rdi = dest, rcx = max length
copy_string_until_null:
    push rsi
    push rdi
    push rcx
    
.copy_loop:
    test rcx, rcx
    jz .done
    mov al, [rsi]
    test al, al
    jz .done
    mov [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp .copy_loop
    
.done:
    mov byte [rdi], 0       ; null terminate
    pop rcx
    pop rdi
    pop rsi
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
    
    ; Mark that runtime arguments were provided
    mov byte [runtime_args_provided], 1
    
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

; Convert integer to string (simple implementation for small positive numbers)
; Input: RAX = integer, RDI = destination buffer
; Output: null-terminated string in buffer
int_to_string:
    push rbx
    push rcx
    push rdx
    
    mov rbx, 10         ; divisor
    mov rcx, 0          ; digit counter
    
    ; Handle zero case
    test rax, rax
    jnz .convert_loop
    mov byte [rdi], '0'
    mov byte [rdi + 1], 0
    jmp .done
    
.convert_loop:
    test rax, rax
    jz .reverse_digits
    
    xor rdx, rdx        ; clear remainder
    div rbx             ; divide by 10
    add dl, '0'         ; convert remainder to ASCII
    push rdx            ; store digit on stack
    inc rcx             ; increment digit count
    jmp .convert_loop
    
.reverse_digits:
    test rcx, rcx
    jz .add_null
    pop rdx
    mov [rdi], dl
    inc rdi
    dec rcx
    jmp .reverse_digits
    
.add_null:
    mov byte [rdi], 0   ; null terminator
    
.done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Convert string to integer (simple implementation for positive numbers)
; Input: RDI = string pointer
; Output: RAX = integer value
string_to_int:
    push rbx
    push rcx
    push rdx
    
    xor rax, rax        ; result
    xor rbx, rbx        ; temp
    mov rcx, 10         ; multiplier
    
.convert_loop:
    mov bl, [rdi]       ; get next character
    test bl, bl         ; check for null terminator
    jz .done
    
    ; Check if character is digit
    cmp bl, '0'
    jl .done
    cmp bl, '9'
    jg .done
    
    ; Convert char to digit and add to result
    sub bl, '0'         ; convert ASCII to digit
    mul rcx             ; result *= 10
    add rax, rbx        ; result += digit
    
    inc rdi             ; next character
    jmp .convert_loop
    
.done:
    pop rdx
    pop rcx
    pop rbx
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
