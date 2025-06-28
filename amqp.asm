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
                   db "  Password will be read from stdin if user is provided", 10, 0
    newline        db 10, 0 ; recycle the newline from the usage message
    password_prompt db "Password: ", 0
    mode_err       db "Unknown mode. Use -s (sender) or -r (receiver)", 10, 0

    ; Error messages
    error_dns_fail       db "DNS resolution failed", 10, 0
    error_sock_fail      db "Socket creation failed", 10, 0
    error_conn_fail      db "Connection failed", 10, 0
    error_frame_overflow db "Frame Overflow", 10, 0
    error_receive_buffer_overflow db "Receive Buffer Overflow", 10, 0
    error_arg_too_long   db "Argument too long", 10, 0
    error_invalid_port   db "Invalid port number", 10, 0

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
    receive_buffer resb RECEIVE_BUFFER_SIZE
    frame_buffer   resb FRAME_BUFFER_SIZE
    input_buffer   resb INPUT_BUFFER_SIZE
    message_len    resd 1
    hex_out_buffer: resb 2049
    
    ; Runtime configuration buffers
    runtime_username    resb 64
    runtime_password    resb 128
    runtime_hostname    resb 256
    runtime_port        resw 1
    runtime_vhost       resb 128
    runtime_queue       resb 256
    runtime_exchange    resb 256
    runtime_routing_key resb 256
    ;; hex_out_buffer: times 2048 db 0    ; Buffer for hex output (1024 bytes * 2 + null)

section .text
    global _start
    extern gethostbyname

_start:
    ; Check minimum arguments (at least mode is required)
    mov rax, [rsp]
    cmp rax, 1
    jle show_usage
    
    ; Initialize runtime config with compile-time defaults
    call init_runtime_config
    
    ; Parse mode (required)
    mov rsi, [rsp + 16]
    cmp byte [rsi], '-'
    jne mode_error
    mov al, [rsi + 1]
    cmp al, 's'
    je check_optional_args_send
    cmp al, 'r'
    je check_optional_args_receive
    jmp mode_error

check_optional_args_send:
    mov rax, [rsp]
    cmp rax, 3
    jl mode_send  ; If only 2 args (program + mode), skip optional parsing
    call parse_optional_args
    jmp mode_send

check_optional_args_receive:
    mov rax, [rsp]
    cmp rax, 3
    jl mode_receive  ; If only 2 args (program + mode), skip optional parsing
    call parse_optional_args
    jmp mode_receive

; Initialize runtime config with compile-time defaults
init_runtime_config:
    ; Copy username
    mov rsi, username
    mov rdi, runtime_username
    mov rcx, username_len
    rep movsb
    mov byte [rdi], 0
    
    ; Copy password
    mov rsi, password
    mov rdi, runtime_password
    mov rcx, password_len
    rep movsb
    mov byte [rdi], 0
    
    ; Copy hostname
    mov rsi, host_str
    mov rdi, runtime_hostname
    call strcpy
    
    ; Copy port
    mov ax, [port_be]
    mov [runtime_port], ax
    
    ; Copy vhost
    mov rsi, vhost
    mov rdi, runtime_vhost
    mov rcx, vhost_len
    rep movsb
    mov byte [rdi], 0
    
    ; Copy queue name
    mov rsi, queue_name
    mov rdi, runtime_queue
    mov rcx, queue_name_len
    rep movsb
    mov byte [rdi], 0
    
    ; Copy exchange
    mov rsi, exchange
    mov rdi, runtime_exchange
    mov rcx, exchange_len
    rep movsb
    mov byte [rdi], 0
    
    ; Copy routing key
    mov rsi, routing_key
    mov rdi, runtime_routing_key
    mov rcx, routing_key_len
    rep movsb
    mov byte [rdi], 0
    ret

; Parse optional arguments and override defaults
parse_optional_args:
    mov rax, [rsp]       ; argc
    cmp rax, 3           ; Need at least 3 args for username
    jl .done             ; If < 3 args, skip all optional processing
    
    ; Check if username provided (argv[2])
    mov rsi, [rsp + 24]  ; argv[2]
    test rsi, rsi
    jz .check_host
    cmp byte [rsi], 0
    je .check_host
    
    ; Copy username
    mov rdi, runtime_username
    call safe_strcpy
    jc .arg_too_long
    
    ; Prompt for password
    call read_password

.check_host:
    mov rax, [rsp]
    cmp rax, 4
    jl .done
    mov rsi, [rsp + 32]  ; argv[3] - host
    test rsi, rsi
    jz .check_port
    cmp byte [rsi], 0
    je .check_port
    mov rdi, runtime_hostname
    call safe_strcpy
    jc .arg_too_long

.check_port:
    mov rax, [rsp]
    cmp rax, 5
    jl .done
    mov rsi, [rsp + 40]  ; argv[4] - port
    test rsi, rsi
    jz .check_vhost
    cmp byte [rsi], 0
    je .check_vhost
    call simple_atoi
    cmp rax, 65535
    ja .invalid_port
    ; Convert to network byte order and store
    xchg al, ah
    mov [runtime_port], ax

.check_vhost:
    mov rax, [rsp]
    cmp rax, 6
    jl .done
    mov rsi, [rsp + 48]  ; argv[5] - vhost
    test rsi, rsi
    jz .check_queue
    cmp byte [rsi], 0
    je .check_queue
    mov rdi, runtime_vhost
    call safe_strcpy
    jc .arg_too_long

.check_queue:
    mov rax, [rsp]
    cmp rax, 7
    jl .done
    mov rsi, [rsp + 56]  ; argv[6] - queue
    test rsi, rsi
    jz .check_exchange
    cmp byte [rsi], 0
    je .check_exchange
    mov rdi, runtime_queue
    call safe_strcpy
    jc .arg_too_long

.check_exchange:
    mov rax, [rsp]
    cmp rax, 8
    jl .done
    mov rsi, [rsp + 64]  ; argv[7] - exchange
    test rsi, rsi
    jz .check_routing_key
    cmp byte [rsi], 0
    je .check_routing_key
    mov rdi, runtime_exchange
    call safe_strcpy
    jc .arg_too_long

.check_routing_key:
    mov rax, [rsp]
    cmp rax, 9
    jl .done
    mov rsi, [rsp + 72]  ; argv[8] - routing key
    test rsi, rsi
    jz .done
    cmp byte [rsi], 0
    je .done
    mov rdi, runtime_routing_key
    call safe_strcpy
    jc .arg_too_long

.done:
    ret

.arg_too_long:
    mov rdi, error_arg_too_long
    call print_string_to_stderr
    jmp exit_error

.invalid_port:
    mov rdi, error_invalid_port
    call print_string_to_stderr
    jmp exit_error

; Safe string copy with bounds checking
; Input: RSI = source, RDI = dest (assumes 256 byte max)
; Output: CF = 1 if too long
safe_strcpy:
    push rcx
    mov rcx, 255
.loop:
    lodsb
    stosb
    test al, al
    jz .done
    loop .loop
    ; String too long
    stc
    jmp .exit
.done:
    clc
.exit:
    pop rcx
    ret

; Simple string to integer conversion
; Input: RSI = string pointer  
; Output: RAX = integer value
simple_atoi:
    push rcx
    xor rax, rax
    mov rcx, 10
.loop:
    mov dl, [rsi]
    test dl, dl
    jz .done
    cmp dl, '0'
    jb .done
    cmp dl, '9'
    ja .done
    sub dl, '0'
    imul rax, rcx
    movzx rdx, dl
    add rax, rdx
    inc rsi
    jmp .loop
.done:
    pop rcx
    ret

; Parse port string to network byte order
; Input: RSI = port string
; Output: CF = 1 if invalid
parse_port:
    push rax
    push rbx
    push rcx
    push rdx
    
    xor rax, rax
    mov rcx, 10
    
.loop:
    mov bl, [rsi]
    test bl, bl
    jz .convert
    
    ; Check if digit
    cmp bl, '0'
    jb .invalid
    cmp bl, '9'
    ja .invalid
    
    ; Convert digit
    sub bl, '0'
    movzx rdx, bl
    
    ; Multiply current result by 10 and add digit
    imul rax, rcx
    add rax, rdx
    
    ; Check overflow
    cmp rax, 65535
    ja .invalid
    
    inc rsi
    jmp .loop

.convert:
    ; Convert to network byte order
    mov bx, ax
    xchg bl, bh        ; swap bytes for network order
    mov [runtime_port], bx
    clc
    jmp .done

.invalid:
    stc
.done:
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

; Read password with echo disabled
read_password:
    push rax
    push rdi
    push rsi
    
    ; Print prompt
    mov rdi, password_prompt
    call print_string_to_stdout
    
    ; Read password (simplified - just read from stdin)
    mov rax, 0          ; sys_read
    mov rdi, 0          ; stdin
    mov rsi, runtime_password
    mov rdx, 127        ; max length
    syscall
    
    ; Remove newline
    test rax, rax
    jz .done
    dec rax
    mov byte [runtime_password + rax], 0
    
.done:
    pop rsi
    pop rdi
    pop rax
    ret

; Copy null-terminated string
strcpy:
    push rax
.loop:
    lodsb
    stosb
    test al, al
    jnz .loop
    pop rax
    ret

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

    mov rdi, runtime_hostname
    call gethostbyname

    mov rsp, rbp
    pop rbp

    test rax, rax
    jz dns_fail_handler

    ; Extract IP from hostent structure
    mov rsi, rax
    mov rdi, [rsi + 24]     ; h_addr_list
    test rdi, rdi
    jz dns_fail_handler
    mov rdi, [rdi]          ; first address
    test rdi, rdi
    jz dns_fail_handler

    ; Setup sockaddr_in
    mov word [sockaddr], 2          ; AF_INET (little endian on x86)
    mov ax, [runtime_port]
    mov [sockaddr + 2], ax          ; port (big endian)
    mov eax, [rdi]                  ; IP (already network order)
    mov [sockaddr + 4], eax
    mov qword [sockaddr + 8], 0     ; zero padding

    ; Create socket
    mov rax, 41                     ; sys_socket
    mov rdi, 2                      ; AF_INET
    mov rsi, 1                      ; SOCK_STREAM
    mov rdx, 0                      ; protocol
    syscall

    test rax, rax
    js socket_fail_handler
    mov [sockfd], eax

    ; Connect
    mov rax, 42                     ; sys_connect
    mov rdi, [sockfd]
    lea rsi, [sockaddr]
    mov rdx, 16
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
    call build_connection_start_ok_frame
    mov rdi, frame_buffer
    mov rdx, rax    ; frame size returned by build function
    call send_frame
    ret

; Build Connection.StartOk frame with runtime credentials
; Returns frame size in RAX
build_connection_start_ok_frame:
    push rbx
    push rcx
    push rsi
    push rdi
    
    mov rdi, frame_buffer
    
    ; Frame type (1 = method frame)
    mov byte [rdi], 1
    inc rdi
    
    ; Channel (0)
    mov word [rdi], 0
    add rdi, 2
    
    ; Payload size placeholder
    mov rbx, rdi  ; save position for payload size
    add rdi, 4
    
    ; Method header: Connection.StartOk (class 10, method 11)
    mov byte [rdi], 0
    mov byte [rdi+1], 10
    mov byte [rdi+2], 0
    mov byte [rdi+3], 11
    add rdi, 4
    
    ; Properties table (empty)
    mov dword [rdi], 0
    add rdi, 4
    
    ; Mechanism (PLAIN)
    mov byte [rdi], 5
    inc rdi
    mov dword [rdi], 'NIAL'  ; PLAIN in little-endian  
    mov byte [rdi+4], 'P'
    add rdi, 5
    
    ; Response length placeholder
    mov rcx, rdi
    add rdi, 4
    
    ; SASL response: \0username\0password
    mov byte [rdi], 0
    inc rdi
    
    ; Copy runtime username
    mov rsi, runtime_username
.copy_user:
    lodsb
    test al, al
    jz .user_done
    stosb
    jmp .copy_user
.user_done:
    mov byte [rdi], 0
    inc rdi
    
    ; Copy runtime password  
    mov rsi, runtime_password
.copy_pass:
    lodsb
    test al, al
    jz .pass_done
    stosb
    jmp .copy_pass
.pass_done:
    
    ; Calculate SASL response length
    sub rdi, rcx
    sub rdi, 4
    mov eax, edi
    bswap eax   ; convert to network byte order
    mov [rcx], eax
    add rdi, rcx
    add rdi, 4
    
    ; Locale
    mov byte [rdi], 5
    inc rdi
    mov dword [rdi], 'SU_n'  ; en_US in little-endian
    mov byte [rdi+4], 'e'
    add rdi, 5
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate total payload size
    sub rdi, rbx
    sub rdi, 4
    mov eax, edi
    bswap eax   ; convert to network byte order  
    mov [rbx], eax
    
    ; Calculate total frame size
    add rdi, rbx
    add rdi, 4
    sub rdi, frame_buffer
    mov rax, rdi
    
    pop rdi
    pop rsi
    pop rcx
    pop rbx
    ret

send_connection_tune_ok:
    mov rdi, conn_tune_ok_frame
    mov rdx, (conn_tune_ok_payload_end - conn_tune_ok_frame + 1)
    call send_frame
    ret

send_connection_open:
    call build_connection_open_frame
    mov rdi, frame_buffer
    mov rdx, rax
    call send_frame
    ret

; Build Connection.Open frame with runtime vhost
; Returns frame size in RAX
build_connection_open_frame:
    push rbx
    push rcx
    push rsi
    push rdi
    
    mov rdi, frame_buffer
    
    ; Frame type (1 = method frame)
    mov byte [rdi], 1
    inc rdi
    
    ; Channel (0)
    mov word [rdi], 0
    add rdi, 2
    
    ; Payload size placeholder
    mov rbx, rdi
    add rdi, 4
    
    ; Method header: Connection.Open (class 10, method 40)
    mov byte [rdi], 0
    mov byte [rdi+1], 10
    mov byte [rdi+2], 0
    mov byte [rdi+3], 40
    add rdi, 4
    
    ; Virtual host length + string
    mov rsi, runtime_vhost
    call strlen
    mov byte [rdi], al
    inc rdi
    
    ; Copy vhost
    mov rsi, runtime_vhost
.copy_vhost:
    lodsb
    test al, al
    jz .vhost_done
    stosb
    jmp .copy_vhost
.vhost_done:
    
    ; Reserved fields (2 bytes)
    mov word [rdi], 0
    add rdi, 2
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate payload size
    sub rdi, rbx
    sub rdi, 4
    mov eax, edi
    bswap eax
    mov [rbx], eax
    
    ; Calculate total frame size
    add rdi, rbx
    add rdi, 4
    sub rdi, frame_buffer
    mov rax, rdi
    
    pop rdi
    pop rsi
    pop rcx
    pop rbx
    ret

open_channel:
    mov rdi, channel_open_frame
    mov rdx, (channel_open_payload_end - channel_open_frame + 1)
    call send_frame
    call receive_frame
    ret

declare_exchange:
    mov rdi, exchange_declare_frame
    mov rdx, (exchange_declare_payload_end - exchange_declare_frame + 1)
    call send_frame
    call receive_frame
    ret

declare_queue:
    mov rdi, queue_declare_frame
    mov rdx, (queue_declare_payload_end - queue_declare_frame + 1)
    call send_frame
    call receive_frame
    ret

bind_queue:
    mov rdi, queue_bind_frame
    mov rdx, (queue_bind_payload_end - queue_bind_frame + 1)
    call send_frame
    call receive_frame
    ret

start_consuming:
    mov rdi, basic_consume_frame
    mov rdx, (basic_consume_payload_end - basic_consume_frame + 1)
    call send_frame
    call receive_frame
    ret

publish_message:
    ; Send Basic.Publish method frame
    mov rdi, basic_publish_frame
    mov rdx, (basic_publish_payload_end - basic_publish_frame + 1)
    call send_frame

    ; Send content header
    call send_content_header

    ; Send content body
    call send_content_body
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
