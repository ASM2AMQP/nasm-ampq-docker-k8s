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
    mode_err       db "Unknown mode. Use -s (sender) or -r (receiver)", 10, 0

    ; Error messages
    error_dns_fail       db "DNS resolution failed", 10, 0
    error_sock_fail      db "Socket creation failed", 10, 0
    error_conn_fail      db "Connection failed", 10, 0
    error_frame_overflow db "Frame Overflow", 10, 0
    error_receive_buffer_overflow db "Receive Buffer Overflow", 10, 0
    error_arg_too_long   db "Argument too long", 10, 0
    error_invalid_port   db "Invalid port number", 10, 0
    error_termios_fail   db "Terminal setup failed", 10, 0
    error_password_too_long db "Password too long", 10, 0
    
    ; Password prompt
    password_prompt      db "Password: ", 0

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

; Runtime configuration buffer sizes
%define USERNAME_MAX 64
%define PASSWORD_MAX 128
%define HOSTNAME_MAX 256
%define QUEUENAME_MAX 256
%define EXCHANGE_MAX 256
%define VHOST_MAX 128
%define ROUTINGKEY_MAX 256
	
section .bss
    sockfd         resd 1
    sockaddr       resb 16
    receive_buffer resb RECEIVE_BUFFER_SIZE
    frame_buffer   resb FRAME_BUFFER_SIZE
    input_buffer   resb INPUT_BUFFER_SIZE
    message_len    resd 1
    hex_out_buffer: resb 2049
    ;; hex_out_buffer: times 2048 db 0    ; Buffer for hex output (1024 bytes * 2 + null)
    
    ; Runtime configuration buffers
    runtime_username   resb USERNAME_MAX
    runtime_password   resb PASSWORD_MAX
    runtime_hostname   resb HOSTNAME_MAX
    runtime_queuename  resb QUEUENAME_MAX
    runtime_exchange   resb EXCHANGE_MAX
    runtime_vhost      resb VHOST_MAX
    runtime_routingkey resb ROUTINGKEY_MAX
    runtime_port       resd 1
    
    ; Runtime string lengths
    runtime_username_len   resd 1
    runtime_password_len   resd 1
    runtime_hostname_len   resd 1
    runtime_queuename_len  resd 1
    runtime_exchange_len   resd 1
    runtime_vhost_len      resd 1
    runtime_routingkey_len resd 1
    
    ; Terminal state for password input
    termios_orig  resb 60  ; struct termios
    termios_new   resb 60  ; struct termios

section .text
    global _start
    extern gethostbyname

_start:
    ; Check minimum arguments (at least mode is required)
    mov rax, [rsp]
    cmp rax, 1
    jle show_usage
    
    ; Initialize runtime configuration with compile-time defaults
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
    call parse_optional_args
    jmp mode_send

check_optional_args_receive:
    call parse_optional_args
    jmp mode_receive

; Initialize runtime configuration with compile-time defaults
init_runtime_config:
    push rsi
    push rdi
    push rcx
    push rax
    
    ; Copy username default
    mov rsi, username
    mov rdi, runtime_username
    mov rcx, username_len
    rep movsb
    mov byte [rdi], 0
    mov dword [runtime_username_len], username_len
    
    ; Copy password default  
    mov rsi, password
    mov rdi, runtime_password
    mov rcx, password_len
    rep movsb
    mov byte [rdi], 0
    mov dword [runtime_password_len], password_len
    
    ; Copy hostname default
    mov rsi, host_str
    mov rdi, runtime_hostname
    call strcpy_with_len
    mov [runtime_hostname_len], eax
    
    ; Copy vhost default
    mov rsi, vhost
    mov rdi, runtime_vhost
    mov rcx, vhost_len
    rep movsb
    mov byte [rdi], 0
    mov dword [runtime_vhost_len], vhost_len
    
    ; Copy queue name default
    mov rsi, queue_name
    mov rdi, runtime_queuename
    mov rcx, queue_name_len
    rep movsb
    mov byte [rdi], 0
    mov dword [runtime_queuename_len], queue_name_len
    
    ; Copy exchange default
    mov rsi, exchange
    mov rdi, runtime_exchange
    mov rcx, exchange_len
    rep movsb
    mov byte [rdi], 0
    mov dword [runtime_exchange_len], exchange_len
    
    ; Copy routing key default
    mov rsi, routing_key
    mov rdi, runtime_routingkey
    mov rcx, routing_key_len
    rep movsb
    mov byte [rdi], 0
    mov dword [runtime_routingkey_len], routing_key_len
    
    ; Set port default
    mov dword [runtime_port], PORT
    
    pop rax
    pop rcx
    pop rdi
    pop rsi
    ret

; Parse optional arguments if provided
; Arguments: argv in [rsp+16], [rsp+24], etc.
parse_optional_args:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rax, [rsp + 48]  ; argc (adjust for pushes)
    cmp rax, 2
    jle parse_done  ; Only mode provided, use defaults
    
    ; Parse username (argv[2])
    cmp rax, 3
    jl parse_done
    mov rsi, [rsp + 72]  ; argv[2] (adjust for pushes)
    call check_empty_string
    test rax, rax
    jnz parse_hostname  ; Empty string, skip to next
    
    mov rsi, [rsp + 72]  ; argv[2]
    mov rdi, runtime_username
    mov rdx, USERNAME_MAX - 1
    call safe_strcpy
    test rax, rax
    jz arg_too_long_error
    mov [runtime_username_len], eax
    
    ; Username provided, need to read password
    call read_password_from_stdin
    
parse_hostname:
    ; Parse hostname (argv[3])
    mov rax, [rsp + 48]  ; argc
    cmp rax, 4
    jl parse_done
    mov rsi, [rsp + 80]  ; argv[3]
    call check_empty_string
    test rax, rax
    jnz parse_port
    
    mov rsi, [rsp + 80]  ; argv[3]
    mov rdi, runtime_hostname
    mov rdx, HOSTNAME_MAX - 1
    call safe_strcpy
    test rax, rax
    jz arg_too_long_error
    mov [runtime_hostname_len], eax
    
parse_port:
    ; Parse port (argv[4])
    mov rax, [rsp + 48]  ; argc
    cmp rax, 5
    jl parse_vhost
    mov rsi, [rsp + 88]  ; argv[4]
    call check_empty_string
    test rax, rax
    jnz parse_vhost
    
    mov rsi, [rsp + 88]  ; argv[4]
    call parse_port_string
    test rax, rax
    jz invalid_port_error
    mov [runtime_port], eax
    
parse_vhost:
    ; Parse vhost (argv[5])
    mov rax, [rsp + 48]  ; argc
    cmp rax, 6
    jl parse_queuename
    mov rsi, [rsp + 96]  ; argv[5]
    call check_empty_string
    test rax, rax
    jnz parse_queuename
    
    mov rsi, [rsp + 96]  ; argv[5]
    mov rdi, runtime_vhost
    mov rdx, VHOST_MAX - 1
    call safe_strcpy
    test rax, rax
    jz arg_too_long_error
    mov [runtime_vhost_len], eax
    
parse_queuename:
    ; Parse queue name (argv[6])
    mov rax, [rsp + 48]  ; argc
    cmp rax, 7
    jl parse_exchange
    mov rsi, [rsp + 104]  ; argv[6]
    call check_empty_string
    test rax, rax
    jnz parse_exchange
    
    mov rsi, [rsp + 104]  ; argv[6]
    mov rdi, runtime_queuename
    mov rdx, QUEUENAME_MAX - 1
    call safe_strcpy
    test rax, rax
    jz arg_too_long_error
    mov [runtime_queuename_len], eax
    
parse_exchange:
    ; Parse exchange (argv[7])
    mov rax, [rsp + 48]  ; argc
    cmp rax, 8
    jl parse_routingkey
    mov rsi, [rsp + 112]  ; argv[7]
    call check_empty_string
    test rax, rax
    jnz parse_routingkey
    
    mov rsi, [rsp + 112]  ; argv[7]
    mov rdi, runtime_exchange
    mov rdx, EXCHANGE_MAX - 1
    call safe_strcpy
    test rax, rax
    jz arg_too_long_error
    mov [runtime_exchange_len], eax
    
parse_routingkey:
    ; Parse routing key (argv[8])
    mov rax, [rsp + 48]  ; argc
    cmp rax, 9
    jl parse_done
    mov rsi, [rsp + 120]  ; argv[8]
    call check_empty_string
    test rax, rax
    jnz parse_done
    
    mov rsi, [rsp + 120]  ; argv[8]
    mov rdi, runtime_routingkey
    mov rdx, ROUTINGKEY_MAX - 1
    call safe_strcpy
    test rax, rax
    jz arg_too_long_error
    mov [runtime_routingkey_len], eax
    
parse_done:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Helper functions for argument parsing

; Check if string is empty
; Input: RSI = string pointer
; Output: RAX = 1 if empty, 0 if not empty
check_empty_string:
    cmp byte [rsi], 0
    je string_is_empty
    xor rax, rax
    ret
string_is_empty:
    mov rax, 1
    ret

; Safe string copy with length limit
; Input: RSI = source, RDI = dest, RDX = max length (excluding null terminator)
; Output: RAX = actual length copied (0 if too long)
safe_strcpy:
    push rcx
    push rsi
    push rdi
    
    xor rcx, rcx  ; counter
copy_loop:
    cmp rcx, rdx
    jge copy_too_long
    
    mov al, [rsi + rcx]
    mov [rdi + rcx], al
    test al, al
    jz copy_success
    
    inc rcx
    jmp copy_loop
    
copy_too_long:
    xor rax, rax
    jmp copy_exit
    
copy_success:
    mov rax, rcx  ; return length
    
copy_exit:
    pop rdi
    pop rsi
    pop rcx
    ret

; String copy with length calculation
; Input: RSI = source, RDI = dest  
; Output: RAX = length copied
strcpy_with_len:
    push rcx
    push rsi
    push rdi
    
    xor rcx, rcx
strcpy_len_loop:
    mov al, [rsi + rcx]
    mov [rdi + rcx], al
    test al, al
    jz strcpy_len_done
    inc rcx
    jmp strcpy_len_loop
    
strcpy_len_done:
    mov rax, rcx
    pop rdi
    pop rsi
    pop rcx
    ret

; Parse port string to integer
; Input: RSI = string pointer
; Output: RAX = port number (0 if invalid)
parse_port_string:
    push rbx
    push rcx
    push rdx
    
    xor rax, rax  ; result
    xor rbx, rbx  ; digit
    
parse_port_loop:
    mov bl, [rsi]
    test bl, bl
    jz parse_port_done
    
    ; Check if digit
    cmp bl, '0'
    jl parse_port_invalid
    cmp bl, '9'
    jg parse_port_invalid
    
    ; Convert and accumulate
    sub bl, '0'
    imul rax, rax, 10
    add rax, rbx
    
    ; Check overflow (max port 65535)
    cmp rax, 65535
    jg parse_port_invalid
    
    inc rsi
    jmp parse_port_loop
    
parse_port_done:
    ; Check minimum port (1)
    test rax, rax
    jz parse_port_invalid
    jmp parse_port_exit
    
parse_port_invalid:
    xor rax, rax
    
parse_port_exit:
    pop rdx
    pop rcx
    pop rbx
    ret

; Read password from stdin with echo disabled
read_password_from_stdin:
    push rax
    push rdi
    push rsi
    push rdx
    
    ; Print password prompt
    mov rdi, password_prompt
    call print_string_to_stderr
    
    ; Check if stdin is a terminal (optional - try termios first)
    mov rax, 16           ; sys_ioctl
    mov rdi, 0            ; stdin
    mov rsi, 0x5401       ; TCGETS
    lea rdx, [termios_orig]
    syscall
    test rax, rax
    js password_no_termios ; If not a terminal, skip termios
    
    ; Copy to new termios
    mov rsi, termios_orig
    mov rdi, termios_new
    mov rcx, 60
    rep movsb
    
    ; Disable echo (clear ECHO bit in c_lflag)
    and dword [termios_new + 12], 0xFFFFFFF7  ; clear bit 3 (ECHO)
    
    ; Set new terminal attributes  
    mov rax, 16           ; sys_ioctl
    mov rdi, 0            ; stdin
    mov rsi, 0x5402       ; TCSETS
    lea rdx, [termios_new]
    syscall
    test rax, rax
    js password_no_termios ; If setting fails, continue without echo control
    
password_no_termios:
    ; Read password
    mov rax, 0            ; sys_read
    mov rdi, 0            ; stdin
    mov rsi, runtime_password
    mov rdx, PASSWORD_MAX - 1
    syscall
    test rax, rax
    jle password_read_error
    
    ; Remove newline if present and null terminate
    mov rcx, rax
    dec rcx
    cmp byte [runtime_password + rcx], 10
    jne password_no_newline
    mov byte [runtime_password + rcx], 0
    mov [runtime_password_len], ecx
    jmp password_restore_terminal
    
password_no_newline:
    mov byte [runtime_password + rax], 0
    mov [runtime_password_len], eax
    
password_restore_terminal:
    ; Try to restore original terminal attributes (ignore errors)
    mov rax, 16           ; sys_ioctl
    mov rdi, 0            ; stdin
    mov rsi, 0x5402       ; TCSETS
    lea rdx, [termios_orig]
    syscall
    
    ; Print newline to stderr
    mov rdi, newline
    call print_string_to_stderr
    
    pop rdx
    pop rsi
    pop rdi
    pop rax
    ret

password_read_error:
    ; Try to restore terminal first (ignore errors)
    mov rax, 16           ; sys_ioctl
    mov rdi, 0            ; stdin
    mov rsi, 0x5402       ; TCSETS
    lea rdx, [termios_orig]
    syscall
    
    mov rdi, error_password_too_long
    call print_string_to_stderr
    jmp exit_error

; Error handlers for argument parsing
arg_too_long_error:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    mov rdi, error_arg_too_long
    call print_string_to_stderr
    jmp exit_error

invalid_port_error:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    mov rdi, error_invalid_port
    call print_string_to_stderr
    jmp exit_error

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
    ; Convert runtime_port to big endian
    mov eax, [runtime_port]
    xchg al, ah                     ; swap bytes for big endian
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
    mov rdx, rax  ; length returned from build function
    call send_frame
    ret

; Build Connection.StartOk frame dynamically
; Output: RAX = frame length, frame built in frame_buffer
build_connection_start_ok_frame:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rdi, frame_buffer
    
    ; Frame header
    mov byte [rdi], 1               ; frame type (method)
    mov word [rdi + 1], 0           ; channel 0 (big endian)
    
    ; Calculate payload size (we'll update this later)
    mov rbx, rdi                    ; save frame start
    add rdi, 7                      ; skip frame header
    mov rcx, rdi                    ; save payload start
    
    ; Payload: Connection.StartOk method
    mov word [rdi], 0x0A00          ; class 10 (big endian)
    mov word [rdi + 2], 0x0B00      ; method 11 (big endian)
    add rdi, 4
    
    ; Client properties (empty table)
    mov dword [rdi], 0              ; empty table
    add rdi, 4
    
    ; Mechanism
    mov byte [rdi], 5               ; length
    mov dword [rdi + 1], "PLAI"     ; "PLAIN" part 1
    mov byte [rdi + 5], "N"         ; "PLAIN" part 2
    add rdi, 6
    
    ; SASL response length (we'll calculate this)
    mov rsi, rdi                    ; save position for length field
    add rdi, 4                      ; skip length field
    mov rdx, rdi                    ; save start of SASL data
    
    ; SASL response: null + username + null + password
    mov byte [rdi], 0               ; first null
    inc rdi
    
    ; Copy username
    mov rax, [runtime_username_len]
    mov rcx, rax
    push rsi
    mov rsi, runtime_username
    rep movsb
    pop rsi
    
    mov byte [rdi], 0               ; second null
    inc rdi
    
    ; Copy password  
    mov rax, [runtime_password_len]
    mov rcx, rax
    push rsi
    push rdx
    mov rsi, runtime_password
    rep movsb
    pop rdx
    pop rsi
    
    ; Calculate SASL response length
    push rdi
    sub rdi, rdx                    ; SASL length = current pos - start
    mov rax, rdi
    
    ; Store SASL length in big endian
    bswap eax
    mov [rsi], eax
    pop rdi
    
    ; Locale
    mov byte [rdi], 5               ; length
    mov dword [rdi + 1], "en_U"     ; "en_US" part 1
    mov byte [rdi + 5], "S"         ; "en_US" part 2
    add rdi, 6
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate payload size
    push rdi
    sub rdi, rcx                    ; payload size = current pos - payload start
    mov rax, rdi
    
    ; Store payload size in big endian (3 bytes)
    mov [rbx + 3], ah               ; high byte
    mov [rbx + 4], al               ; middle byte  
    mov byte [rbx + 5], 0           ; low byte (sizes are small)
    mov byte [rbx + 6], 0           ; reserved
    shr rax, 8
    mov [rbx + 5], al               ; correct middle byte
    shr rax, 8  
    mov [rbx + 4], al               ; correct high byte
    
    pop rdi
    
    ; Calculate total frame length
    sub rdi, rbx
    mov rax, rdi
    
    pop rdi
    pop rsi
    pop rdx
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
    mov rdx, rax  ; length returned from build function
    call send_frame
    ret

; Build Connection.Open frame dynamically  
; Output: RAX = frame length, frame built in frame_buffer
build_connection_open_frame:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rdi, frame_buffer
    
    ; Frame header
    mov byte [rdi], 1               ; frame type (method)
    mov word [rdi + 1], 0           ; channel 0 (big endian)
    
    ; Calculate payload size (we'll update this later)
    mov rbx, rdi                    ; save frame start
    add rdi, 7                      ; skip frame header
    mov rcx, rdi                    ; save payload start
    
    ; Payload: Connection.Open method
    mov word [rdi], 0x0A00          ; class 10 (big endian)
    mov word [rdi + 2], 0x2800      ; method 40 (big endian)
    add rdi, 4
    
    ; Virtual host length and string
    mov rax, [runtime_vhost_len]
    mov [rdi], al                   ; vhost length (1 byte)
    inc rdi
    
    ; Copy vhost
    mov rcx, rax
    mov rsi, runtime_vhost
    rep movsb
    
    ; Reserved fields
    mov word [rdi], 0               ; reserved
    add rdi, 2
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate payload size
    push rdi
    sub rdi, rcx                    ; payload size = current pos - payload start
    mov rax, rdi
    
    ; Store payload size in big endian (3 bytes)
    mov [rbx + 3], ah               ; high byte
    mov [rbx + 4], al               ; middle byte  
    mov byte [rbx + 5], 0           ; low byte
    mov byte [rbx + 6], 0           ; reserved
    shr rax, 8
    mov [rbx + 5], al               ; correct middle byte
    shr rax, 8  
    mov [rbx + 4], al               ; correct high byte
    
    pop rdi
    
    ; Calculate total frame length
    sub rdi, rbx
    mov rax, rdi
    
    pop rdi
    pop rsi
    pop rdx
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
    call build_exchange_declare_frame
    mov rdi, frame_buffer
    mov rdx, rax  ; length returned from build function
    call send_frame
    call receive_frame
    ret

; Build Exchange.Declare frame dynamically
; Output: RAX = frame length, frame built in frame_buffer
build_exchange_declare_frame:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rdi, frame_buffer
    
    ; Frame header
    mov byte [rdi], 1               ; frame type (method)
    mov word [rdi + 1], 0x0100      ; channel 1 (big endian)
    
    ; Calculate payload size (we'll update this later)
    mov rbx, rdi                    ; save frame start
    add rdi, 7                      ; skip frame header
    mov rcx, rdi                    ; save payload start
    
    ; Payload: Exchange.Declare method
    mov word [rdi], 0x2800          ; class 40 (big endian)
    mov word [rdi + 2], 0x0A00      ; method 10 (big endian)
    add rdi, 4
    
    ; Reserved
    mov word [rdi], 0               ; reserved
    add rdi, 2
    
    ; Exchange name length and string
    mov rax, [runtime_exchange_len]
    mov [rdi], al                   ; exchange length (1 byte)
    inc rdi
    
    ; Copy exchange name
    mov rcx, rax
    mov rsi, runtime_exchange
    rep movsb
    
    ; Exchange type (topic)
    mov byte [rdi], 5               ; length
    mov dword [rdi + 1], "topi"     ; "topic" part 1
    mov byte [rdi + 5], "c"         ; "topic" part 2
    add rdi, 6
    
    ; Flags: durable=1
    mov byte [rdi], 0b00000010      ; durable
    inc rdi
    
    ; Arguments (empty table)
    mov dword [rdi], 0              ; empty table
    add rdi, 4
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate payload size
    push rdi
    sub rdi, rcx                    ; payload size = current pos - payload start
    mov rax, rdi
    
    ; Store payload size in big endian (3 bytes)
    mov [rbx + 3], ah               ; high byte
    mov [rbx + 4], al               ; middle byte  
    mov byte [rbx + 5], 0           ; low byte
    mov byte [rbx + 6], 0           ; reserved
    shr rax, 8
    mov [rbx + 5], al               ; correct middle byte
    shr rax, 8  
    mov [rbx + 4], al               ; correct high byte
    
    pop rdi
    
    ; Calculate total frame length
    sub rdi, rbx
    mov rax, rdi
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

declare_queue:
    call build_queue_declare_frame
    mov rdi, frame_buffer
    mov rdx, rax
    call send_frame
    call receive_frame
    ret

; Build Queue.Declare frame dynamically
build_queue_declare_frame:
    push rbx
    push rcx
    push rsi
    push rdi
    
    mov rdi, frame_buffer
    mov byte [rdi], 1               ; frame type
    mov word [rdi + 1], 0x0100      ; channel 1
    mov rbx, rdi
    add rdi, 7
    mov rcx, rdi
    
    mov word [rdi], 0x3200          ; class 50 (big endian)
    mov word [rdi + 2], 0x0A00      ; method 10
    mov word [rdi + 4], 0           ; reserved
    add rdi, 6
    
    mov rax, [runtime_queuename_len]
    mov [rdi], al
    inc rdi
    push rcx
    mov rcx, rax
    mov rsi, runtime_queuename
    rep movsb
    pop rcx
    
    mov byte [rdi], 0               ; flags
    mov dword [rdi + 1], 0          ; arguments
    add rdi, 5
    mov byte [rdi], 0xCE
    inc rdi
    
    push rdi
    sub rdi, rcx
    mov rax, rdi
    mov [rbx + 3], ah
    mov [rbx + 4], al
    mov byte [rbx + 5], 0
    mov byte [rbx + 6], 0
    shr rax, 8
    mov [rbx + 5], al
    shr rax, 8
    mov [rbx + 4], al
    pop rdi
    
    sub rdi, rbx
    mov rax, rdi
    
    pop rdi
    pop rsi
    pop rcx
    pop rbx
    ret

bind_queue:
    call build_queue_bind_frame
    mov rdi, frame_buffer
    mov rdx, rax
    call send_frame
    call receive_frame
    ret

; Build Queue.Bind frame dynamically
build_queue_bind_frame:
    push rbx
    push rcx
    push rsi
    push rdi
    
    mov rdi, frame_buffer
    mov byte [rdi], 1
    mov word [rdi + 1], 0x0100
    mov rbx, rdi
    add rdi, 7
    mov rcx, rdi
    
    mov word [rdi], 0x3200          ; class 50
    mov word [rdi + 2], 0x1400      ; method 20
    mov word [rdi + 4], 0           ; reserved
    add rdi, 6
    
    ; Queue name
    mov rax, [runtime_queuename_len]
    mov [rdi], al
    inc rdi
    push rcx
    mov rcx, rax
    mov rsi, runtime_queuename
    rep movsb
    pop rcx
    
    ; Exchange name
    mov rax, [runtime_exchange_len]
    mov [rdi], al
    inc rdi
    push rcx
    mov rcx, rax
    mov rsi, runtime_exchange
    rep movsb
    pop rcx
    
    ; Routing key
    mov rax, [runtime_routingkey_len]
    mov [rdi], al
    inc rdi
    push rcx
    mov rcx, rax
    mov rsi, runtime_routingkey
    rep movsb
    pop rcx
    
    mov byte [rdi], 0               ; nowait
    mov dword [rdi + 1], 0          ; arguments
    add rdi, 5
    mov byte [rdi], 0xCE
    inc rdi
    
    push rdi
    sub rdi, rcx
    mov rax, rdi
    mov [rbx + 3], ah
    mov [rbx + 4], al
    mov byte [rbx + 5], 0
    mov byte [rbx + 6], 0
    shr rax, 8
    mov [rbx + 5], al
    shr rax, 8
    mov [rbx + 4], al
    pop rdi
    
    sub rdi, rbx
    mov rax, rdi
    
    pop rdi
    pop rsi
    pop rcx
    pop rbx
    ret

start_consuming:
    call build_basic_consume_frame
    mov rdi, frame_buffer
    mov rdx, rax
    call send_frame
    ret

; Build Basic.Consume frame dynamically
build_basic_consume_frame:
    push rbx
    push rcx
    push rsi
    push rdi
    
    mov rdi, frame_buffer
    mov byte [rdi], 1
    mov word [rdi + 1], 0x0100
    mov rbx, rdi
    add rdi, 7
    mov rcx, rdi
    
    mov word [rdi], 0x3C00          ; class 60
    mov word [rdi + 2], 0x1400      ; method 20
    mov word [rdi + 4], 0           ; reserved
    add rdi, 6
    
    mov rax, [runtime_queuename_len]
    mov [rdi], al
    inc rdi
    push rcx
    mov rcx, rax
    mov rsi, runtime_queuename
    rep movsb
    pop rcx
    
    mov byte [rdi], 0               ; consumer tag
    mov byte [rdi + 1], 0b00000010  ; flags: no_ack
    mov dword [rdi + 2], 0          ; arguments
    add rdi, 6
    mov byte [rdi], 0xCE
    inc rdi
    
    push rdi
    sub rdi, rcx
    mov rax, rdi
    mov [rbx + 3], ah
    mov [rbx + 4], al
    mov byte [rbx + 5], 0
    mov byte [rbx + 6], 0
    shr rax, 8
    mov [rbx + 5], al
    shr rax, 8
    mov [rbx + 4], al
    pop rdi
    
    sub rdi, rbx
    mov rax, rdi
    
    pop rdi
    pop rsi
    pop rcx
    pop rbx
    ret

publish_message:
    ; Send Basic.Publish method frame
    call build_basic_publish_frame
    mov rdi, frame_buffer
    mov rdx, rax
    call send_frame

    ; Send content header
    call send_content_header

    ; Send content body
    call send_content_body
    ret

; Build Basic.Publish frame dynamically
build_basic_publish_frame:
    push rbx
    push rcx
    push rsi
    push rdi
    
    mov rdi, frame_buffer
    mov byte [rdi], 1
    mov word [rdi + 1], 0x0100
    mov rbx, rdi
    add rdi, 7
    mov rcx, rdi
    
    mov word [rdi], 0x3C00          ; class 60
    mov word [rdi + 2], 0x2800      ; method 40
    mov word [rdi + 4], 0           ; reserved
    add rdi, 6
    
    ; Exchange name
    mov rax, [runtime_exchange_len]
    mov [rdi], al
    inc rdi
    push rcx
    mov rcx, rax
    mov rsi, runtime_exchange
    rep movsb
    pop rcx
    
    ; Routing key
    mov rax, [runtime_routingkey_len]
    mov [rdi], al
    inc rdi
    push rcx
    mov rcx, rax
    mov rsi, runtime_routingkey
    rep movsb
    pop rcx
    
    mov byte [rdi], 0               ; flags
    mov byte [rdi + 1], 0xCE        ; frame end
    add rdi, 2
    
    push rdi
    sub rdi, rcx
    mov rax, rdi
    mov [rbx + 3], ah
    mov [rbx + 4], al
    mov byte [rbx + 5], 0
    mov byte [rbx + 6], 0
    shr rax, 8
    mov [rbx + 5], al
    shr rax, 8
    mov [rbx + 4], al
    pop rdi
    
    sub rdi, rbx
    mov rax, rdi
    
    pop rdi
    pop rsi
    pop rcx
    pop rbx
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
