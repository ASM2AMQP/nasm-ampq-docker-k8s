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

; Socket constants for getaddrinfo
AF_UNSPEC       equ 0       ; IPv4 or IPv6
SOCK_STREAM     equ 1       ; TCP stream socket

; Structure definition for addrinfo hints
struc hints_t
    .ai_flags    resd 1      ; int, 4 bytes
    .ai_family   resd 1      ; int, 4 bytes
    .ai_socktype resd 1      ; int, 4 bytes
    .ai_protocol resd 1      ; int, 4 bytes
    .ai_addrlen  resd 1      ; socklen_t, 4 bytes  
    .ai_addr     resq 1      ; pointer, 8 bytes
    .ai_canonname resq 1     ; pointer, 8 bytes
    .ai_next     resq 1      ; pointer, 8 bytes
endstruc

; Size of the hints structure (must match actual struct size)
addrinfo_hints_size equ 40

section .data
    ; String values
    username       db USERNAME, 0
    password       db PASSWORD, 0
    vhost          db VHOST, 0
    exchange       db EXCHANGE, 0
    routing_key    db ROUTINGKEY, 0
    queue_name     db QUEUENAME, 0
    host_str       db HOST, 0

    ; Precomputed lengths (excluding null terminators)
    username_len       equ 5          ; "guest"
    password_len       equ 5          ; "guest" 
    vhost_len          equ 1          ; "/"
    exchange_len       equ 11         ; "my_exchange"
    routing_key_len    equ 8          ; "my.topic"
    queue_name_len     equ 8          ; "my_queue"

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

    ; Frame construction utilities - all frames built dynamically

%define RECEIVE_BUFFER_SIZE 4096
%define FRAME_BUFFER_SIZE 512
%define INPUT_BUFFER_SIZE 512

section .bss
    sockfd         resd 1
    sockaddr       resb 128        ; Increased size to accommodate both IPv4 and IPv6
    receive_buffer resb RECEIVE_BUFFER_SIZE
    frame_buffer   resb FRAME_BUFFER_SIZE
    ; Configuration pointers (resolved at runtime from argv or defaults)
    config_username_ptr  resq 1    ; Pointer to username string
    config_password_ptr  resq 1    ; Pointer to password string  
    config_host_ptr      resq 1    ; Pointer to host string
    config_port_ptr      resq 1    ; Pointer to port string
    config_vhost_ptr     resq 1    ; Pointer to vhost string
    config_queuename_ptr resq 1    ; Pointer to queuename string
    config_exchange_ptr  resq 1    ; Pointer to exchange string
    config_routingkey_ptr resq 1   ; Pointer to routingkey string
    ; Temporary buffers (only when needed)
    port_string_buffer   resb 16   ; Buffer for integer-to-string conversion
    password_buffer      resb 128  ; Buffer for prompted password input

section .text
    global _start
    extern getaddrinfo
    extern freeaddrinfo

; Content header frame construction utility
; Build Content Header frame on stack  
; Input: RDI = destination buffer, RSI = message length
; Output: RAX = frame size
build_content_header_frame:
    push rcx
    push rdx
    push r8
    
    mov r8, rdi                 ; Save destination
    mov rdx, rsi                ; Save message length
    
    ; Frame header
    mov byte [rdi], 2           ; frame type header
    inc rdi
    mov word [rdi], 0x0100      ; channel 1 (big endian)
    add rdi, 2
    mov dword [rdi], 0x0E000000 ; payload size 14 (big endian)
    add rdi, 4
    
    ; Payload
    mov word [rdi], 0x3C00      ; class id 60 (Basic) big endian
    add rdi, 2
    mov word [rdi], 0           ; weight 0
    add rdi, 2
    
    ; Body size (8 bytes big endian)
    mov dword [rdi], 0          ; upper 4 bytes = 0
    add rdi, 4
    mov eax, edx                ; message length
    call write_be32_at_rdi      ; lower 4 bytes in big endian
    add rdi, 4
    
    ; Property flags
    mov word [rdi], 0           ; no properties
    add rdi, 2
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate size
    mov rax, rdi
    sub rax, r8
    
    pop r8
    pop rdx
    pop rcx
    ret

; Build Connection.TuneOk frame on stack
; Input: RDI = destination buffer
; Output: RAX = frame size
build_connection_tune_ok_frame:
    push rsi
    push rcx
    push rdx
    
    mov rsi, rdi                ; Save destination
    
    ; Frame header
    mov byte [rdi], 1           ; frame type
    inc rdi
    mov word [rdi], 0           ; channel 0 (big endian)
    add rdi, 2
    mov dword [rdi], 0x0A000000 ; payload size 10 (big endian)
    add rdi, 4
    
    ; Payload
    mov dword [rdi], 0x1F000A00 ; Connection.TuneOk (class 10, method 31) big endian
    add rdi, 4
    mov word [rdi], 0x0100      ; channel max 1 (big endian)
    add rdi, 2
    mov dword [rdi], 0x00000200 ; frame max 131072 (big endian)
    add rdi, 4
    mov word [rdi], 0           ; heartbeat 0
    add rdi, 2
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate size
    mov rax, rdi
    sub rax, rsi
    
    pop rdx
    pop rcx
    pop rsi
    ret

; Build Channel.Open frame on stack
; Input: RDI = destination buffer
; Output: RAX = frame size
build_channel_open_frame:
    push rsi
    push rcx
    push rdx
    
    mov rsi, rdi                ; Save destination
    
    ; Frame header
    mov byte [rdi], 1           ; frame type
    inc rdi
    mov word [rdi], 0x0100      ; channel 1 (big endian)
    add rdi, 2
    mov dword [rdi], 0x05000000 ; payload size 5 (big endian)
    add rdi, 4
    
    ; Payload
    mov dword [rdi], 0x0A001400 ; Channel.Open (class 20, method 10) big endian
    add rdi, 4
    mov byte [rdi], 0           ; reserved
    inc rdi
    
    ; Frame end
    mov byte [rdi], 0xCE
    inc rdi
    
    ; Calculate size
    mov rax, rdi
    sub rax, rsi
    
    pop rdx
    pop rcx
    pop rsi
    ret

; Helper function: Write 32-bit value in big endian at RDI
; Input: EAX = value, RDI = destination
write_be32_at_rdi:
    mov byte [rdi + 3], al
    shr eax, 8
    mov byte [rdi + 2], al
    shr eax, 8
    mov byte [rdi + 1], al
    shr eax, 8
    mov byte [rdi], al
    ret

; Helper function: Copy string safely with length limit
; Input: RDI = destination, RSI = source, RCX = max length
copy_string_safe:
    push rax
    push rcx
    push rsi
    push rdi
    
.copy_loop:
    test rcx, rcx
    jz .done
    mov al, [rsi]
    mov [rdi], al
    test al, al                 ; Check for null terminator
    jz .done
    inc rsi
    inc rdi
    dec rcx
    jmp .copy_loop
.done:
    ; Ensure null termination
    mov byte [rdi], 0
    
    pop rdi
    pop rsi
    pop rcx
    pop rax
    ret

; Helper function: Clear memory for security
; Input: RDI = memory address, RCX = length
clear_memory:
    push rax
    push rcx
    push rdi
    
    xor eax, eax                ; Clear with zeros
.clear_loop:
    test rcx, rcx
    jz .clear_done
    mov [rdi], al
    inc rdi
    dec rcx
    jmp .clear_loop
.clear_done:
    
    pop rdi
    pop rcx
    pop rax
    ret

_start:
    ; Check arguments - at least mode required
    mov rax, [rsp]
    cmp rax, 2
    jl show_usage
    
    ; Preserve argc across function call
    push rax
    
    ; Initialize configuration pointers with default values
    call init_config_pointers
    
    ; Restore argc
    pop rax
    
    ; Parse optional arguments: [user] [host] [port] [vhost] [queuename] [exchange] [routingkey]
    ; argc stored in rax, argv pointers start at [rsp + 16]
    
    ; Parse username (argv[2])
    cmp rax, 3
    jl .parse_host
    mov rsi, [rsp + 24]         ; argv[2]
    ; Check if argument is non-empty string
    cmp byte [rsi], 0
    je .parse_host              ; Skip if empty
    mov [config_username_ptr], rsi
    
.parse_host:
    ; Parse host (argv[3])  
    cmp rax, 4
    jl .parse_port
    mov rsi, [rsp + 32]         ; argv[3]
    cmp byte [rsi], 0
    je .parse_port              ; Skip if empty
    mov [config_host_ptr], rsi
    
.parse_port:
    ; Parse port (argv[4])
    cmp rax, 5
    jl .parse_vhost
    mov rsi, [rsp + 40]         ; argv[4]
    cmp byte [rsi], 0
    je .parse_vhost             ; Skip if empty
    mov [config_port_ptr], rsi
    
.parse_vhost:
    ; Parse vhost (argv[5])
    cmp rax, 6
    jl .parse_queuename
    mov rsi, [rsp + 48]         ; argv[5]
    cmp byte [rsi], 0
    je .parse_queuename         ; Skip if empty
    mov [config_vhost_ptr], rsi
    
.parse_queuename:
    ; Parse queuename (argv[6])
    cmp rax, 7
    jl .parse_exchange
    mov rsi, [rsp + 56]         ; argv[6]
    cmp byte [rsi], 0
    je .parse_exchange          ; Skip if empty
    mov [config_queuename_ptr], rsi
    
.parse_exchange:
    ; Parse exchange (argv[7])
    cmp rax, 8
    jl .parse_routingkey
    mov rsi, [rsp + 64]         ; argv[7]
    cmp byte [rsi], 0
    je .parse_routingkey        ; Skip if empty
    mov [config_exchange_ptr], rsi
    
.parse_routingkey:
    ; Parse routingkey (argv[8])
    cmp rax, 9
    jl .check_password
    mov rsi, [rsp + 72]         ; argv[8]
    cmp byte [rsi], 0
    je .check_password          ; Skip if empty
    mov [config_routingkey_ptr], rsi

.check_password:
    ; If username was provided as argument AND is not from defaults, prompt for password
    ; Check if argc >= 3 (meaning username argument was provided)
    mov rbx, [rsp]              ; argc
    cmp rbx, 3
    jl .parse_mode
    ; Check if username pointer is not pointing to default
    mov rax, [config_username_ptr]
    cmp rax, username
    je .parse_mode              ; Skip if still pointing to default
    ; Also check if username is not empty
    cmp byte [rax], 0
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

; Initialize runtime configuration buffers with compile-time defaults
init_config_pointers:
    ; Initialize configuration pointers to compile-time defaults
    mov rax, username
    mov [config_username_ptr], rax
    
    mov rax, password
    mov [config_password_ptr], rax
    
    mov rax, host_str
    mov [config_host_ptr], rax
    
    ; Initialize port as string - convert PORT constant to string
    mov rdi, port_string_buffer
    mov rax, PORT
    call int_to_string
    mov rax, port_string_buffer
    mov [config_port_ptr], rax
    
    mov rax, vhost
    mov [config_vhost_ptr], rax
    
    mov rax, queue_name
    mov [config_queuename_ptr], rax
    
    mov rax, exchange
    mov [config_exchange_ptr], rax
    
    mov rax, routing_key
    mov [config_routingkey_ptr], rax
    
    ret

show_usage:
    mov rdi, usage_msg
    call print_string_to_stderr
    jmp exit_error

mode_error:
    mov rdi, mode_err
    call print_string_to_stderr
    jmp exit_error

mode_send:
    call setup_connection
    call setup_channel_and_exchange

    mov rdi, trace_read_stdin
    call print_trace

    ; Allocate input buffer on stack for message reading
    push rbp
    mov rbp, rsp
    sub rsp, INPUT_BUFFER_SIZE
    and rsp, -16  ; align stack

send_loop:
    ; Pass input buffer address to read_stdin_message
    mov rdi, rsp  ; input buffer address
    call read_stdin_message
    test rax, rax
    jz .cleanup_send_exit

    ; Save message length on stack for use by publish_message
    push rax                        ; message length

    mov rdi, trace_publish
    call print_trace

    ; Pass input buffer address and message length to publish_message  
    mov rdi, rsp  ; input buffer address (note: now offset by 8 due to push)
    add rdi, 8    ; adjust for pushed message length
    mov rsi, [rsp] ; message length from stack
    call publish_message

    pop rax       ; clean up message length from stack

    mov rdi, trace_send
    call print_trace

    jmp send_loop

.cleanup_send_exit:
    mov rsp, rbp
    pop rbp
    jmp cleanup_exit

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
    
    ; Allocate space for hints structure and addrinfo result pointer on stack
    sub rsp, addrinfo_hints_size + 8    ; +8 for addrinfo result pointer
    
    ; Initialize hints structure on stack (zero the whole structure first)
    push rdi
    mov rdi, rsp
    add rdi, 8          ; account for saved rdi
    mov rcx, addrinfo_hints_size + 8    ; also clear the result pointer
    xor rax, rax
    rep stosb
    pop rdi
    
    ; Set the fields we need
    mov dword [rsp + hints_t.ai_flags], 0          ; ai_flags = 0
    mov dword [rsp + hints_t.ai_family], AF_UNSPEC ; ai_family = AF_UNSPEC (IPv4 or IPv6)
    mov dword [rsp + hints_t.ai_socktype], SOCK_STREAM ; ai_socktype = SOCK_STREAM (TCP)
    mov dword [rsp + hints_t.ai_protocol], 0       ; ai_protocol = 0 (any)

    ; Use configured hostname and port pointers
    mov rdi, [config_host_ptr]      ; hostname from config pointer
    mov rsi, [config_port_ptr]      ; port string from config pointer

.call_getaddrinfo:
    ; Call getaddrinfo(hostname, port_string, hints, &result)
    ; rdi = hostname (already set)
    ; rsi = port string (already set) 
    mov rdx, rsp            ; pointer to stack-allocated hints structure
    lea rcx, [rsp + addrinfo_hints_size]  ; pointer to addrinfo result pointer on stack
    call getaddrinfo

    test rax, rax
    jnz .cleanup_and_fail   ; getaddrinfo returns 0 on success

    ; Try each address until one connects
    mov rsi, [rsp + addrinfo_hints_size]  ; Load addrinfo result pointer from stack

.try_address:
    test rsi, rsi
    jz .cleanup_and_connect_fail     ; No more addresses to try

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
    ; Free the addrinfo result and clean up stack
    ; addrinfo result pointer is at [rsp + addrinfo_hints_size]
    mov rdi, [rsp + addrinfo_hints_size]
    call freeaddrinfo
    
    ; Restore original stack pointer and return
    mov rsp, rbp
    pop rbp
    ret

.cleanup_and_fail:
    ; Clean up stack and jump to failure handler
    mov rsp, rbp
    pop rbp
    jmp dns_fail_handler

.cleanup_and_connect_fail:
    ; Free addrinfo and jump to connect failure handler
    ; addrinfo result pointer is at [rsp + addrinfo_hints_size]
    mov rdi, [rsp + addrinfo_hints_size]
    call freeaddrinfo
    
    ; Restore original stack pointer and jump to failure handler
    mov rsp, rbp
    pop rbp
    jmp connect_fail_handler

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
    ; Build frame with configured username and password directly
    ; No need to copy - use pointers directly for frame construction
    sub rsp, FRAME_BUFFER_SIZE      ; Only allocate frame buffer on stack
    
    mov rdi, rsp                    ; Stack frame buffer
    mov rsi, [config_username_ptr]  ; Username from config pointer
    mov rdx, [config_password_ptr]  ; Password from config pointer
    call build_connection_start_ok_frame
    
    ; Send frame
    mov rdi, rsp                    ; Stack frame buffer
    mov edx, eax                    ; frame size returned in eax
    call send_frame
    
    add rsp, FRAME_BUFFER_SIZE
    ret

; Build Connection.StartOk frame with runtime credentials
; Input: RDI = destination buffer, RSI = username buffer, RDX = password buffer
; Output: RAX = frame size
build_connection_start_ok_frame:
    push rcx
    push r8
    push r9
    push r10
    
    mov r8, rsi                 ; Save username pointer
    mov r9, rdx                 ; Save password pointer
    mov r10, rdi                ; Save destination buffer pointer
    
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
    mov rsi, r8                 ; username
    call str_len
    mov rdx, rcx                ; username length
    
    mov rsi, r9                 ; password
    call str_len                ; password length in rcx
    
    add rdx, rcx                ; username + password lengths
    add rdx, 2                  ; + 2 null separators
    
    ; Write auth string length as 4-byte big endian
    mov eax, edx                ; auth response length
    mov rsi, rdi                ; destination for length
    call write_be32_at_rsi      ; write 4-byte big endian length
    add rdi, 4
    
    ; Auth string format: \0username\0password
    mov byte [rdi], 0           ; first null
    inc rdi
    
    ; Copy username
    mov rsi, r8                 ; username buffer
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
    mov rsi, r9                 ; password buffer
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
    sub rax, r10                ; Subtract frame start (destination buffer)
    sub rax, 8                  ; subtract frame header
    mov rsi, r10                ; Frame start
    add rsi, 3                  ; Payload size location
    call write_be32_at_rsi
    
    ; Return total frame size
    mov rax, rdi
    sub rax, r10                ; Subtract frame start (destination buffer)
    
    pop r10
    pop r9
    pop r8
    pop rcx
    ret

send_connection_tune_ok:
    ; Allocate frame on stack
    sub rsp, 32                 ; Allocate space for frame
    mov rdi, rsp                ; Use stack space as buffer
    call build_connection_tune_ok_frame
    mov rdx, rax                ; Frame size
    mov rdi, rsp                ; Frame buffer
    call send_frame
    add rsp, 32                 ; Restore stack
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
    
    ; Virtual host - use configured pointer
    mov rsi, [config_vhost_ptr]     ; get vhost from config pointer
    call str_len                    ; get length in rcx
    mov [rdi], cl                   ; vhost length
    inc rdi
    movzx rcx, cl                   ; ensure rcx contains only the length value
    rep movsb                       ; copy vhost string
    
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
    call write_be32_at_rsi      ; convert to big endian
    
    ; Return total frame size in eax
    mov rax, rdi
    sub rax, frame_buffer
    
    pop rcx
    pop rdi
    pop rsi
    ret

open_channel:
    ; Allocate frame on stack
    sub rsp, 32                 ; Allocate space for frame
    mov rdi, rsp                ; Use stack space as buffer
    call build_channel_open_frame
    mov rdx, rax                ; Frame size
    mov rdi, rsp                ; Frame buffer
    call send_frame
    add rsp, 32                 ; Restore stack
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
    
    ; Exchange name - use configured pointer
    mov rsi, [config_exchange_ptr]  ; get exchange from config pointer
    call str_len                    ; get length in rcx
    mov [rdi], cl                   ; exchange name length
    inc rdi
    movzx rcx, cl                   ; ensure rcx contains only the length value
    rep movsb                       ; copy exchange name
    
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
    call write_be32_at_rsi
    
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
    
    ; Queue name - use configured pointer
    mov rsi, [config_queuename_ptr] ; get queue name from config pointer
    call str_len                    ; get length in rcx
    mov [rdi], cl                   ; queue name length
    inc rdi
    movzx rcx, cl                   ; ensure rcx contains only the length value
    rep movsb                       ; copy queue name
    
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
    call write_be32_at_rsi
    
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
    
    ; Queue name - use configured pointer
    mov rsi, [config_queuename_ptr] ; get queue name from config pointer
    call str_len                    ; get length in rcx
    mov [rdi], cl                   ; queue name length
    inc rdi
    movzx rcx, cl                   ; ensure rcx contains only the length value
    rep movsb                       ; copy queue name
    
    ; Exchange name - use configured pointer
    mov rsi, [config_exchange_ptr]  ; get exchange from config pointer
    call str_len                    ; get length in rcx
    mov [rdi], cl                   ; exchange name length
    inc rdi
    movzx rcx, cl
    rep movsb                       ; copy exchange name
    
    ; Routing key - use configured pointer
    mov rsi, [config_routingkey_ptr] ; get routing key from config pointer
    call str_len                     ; get length in rcx
    mov [rdi], cl                    ; routing key length
    inc rdi
    movzx rcx, cl
    rep movsb                        ; copy routing key
    
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
    call write_be32_at_rsi
    
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
    
    ; Queue name - use configured pointer
    mov rsi, [config_queuename_ptr] ; get queue name from config pointer
    call str_len                    ; get length in rcx
    mov [rdi], cl                   ; queue name length
    inc rdi
    movzx rcx, cl
    rep movsb                       ; copy queue name
    
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
    call write_be32_at_rsi
    
    ; Return total frame size
    mov rax, rdi
    sub rax, frame_buffer
    
    pop rcx
    pop rdi
    pop rsi
    ret

publish_message:
    ; Input: RDI = input buffer address, RSI = message length
    push rdi  ; save input buffer address
    push rsi  ; save message length
    
    ; Build and send dynamic Basic.Publish method frame
    call build_basic_publish_frame
    mov rdi, frame_buffer
    mov edx, eax                ; frame size returned in eax
    call send_frame

    ; Send content header
    mov rsi, [rsp]              ; message length from stack
    call send_content_header

    ; Send content body with input buffer address and message length
    mov rdi, [rsp + 8]          ; get input buffer address
    mov rsi, [rsp]              ; message length
    call send_content_body
    
    pop rsi   ; restore message length
    pop rdi   ; restore input buffer address
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
    
    ; Exchange name - use configured pointer
    mov rsi, [config_exchange_ptr]  ; get exchange from config pointer
    call str_len                    ; get length in rcx
    mov [rdi], cl                   ; exchange name length
    inc rdi
    movzx rcx, cl                   ; ensure rcx contains only the length value
    rep movsb                       ; copy exchange name
    
    ; Routing key - use configured pointer
    mov rsi, [config_routingkey_ptr] ; get routing key from config pointer
    call str_len                     ; get length in rcx
    mov [rdi], cl                    ; routing key length
    inc rdi
    movzx rcx, cl
    rep movsb                        ; copy routing key
    
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
    call write_be32_at_rsi
    
    ; Return total frame size
    mov rax, rdi
    sub rax, frame_buffer
    
    pop rcx
    pop rdi
    pop rsi
    ret

send_content_header:
    ; Input: RSI = message length
    ; Allocate frame on stack
    sub rsp, 32                 ; Allocate space for frame
    mov rdi, rsp                ; Use stack space as buffer
    ; RSI already contains message length
    call build_content_header_frame
    mov rdx, rax                ; Frame size
    
    ; Output frame as hex to stderr for debugging
    mov rdi, rsp                ; Frame start
    call dump_frame_hex_spaced  ; Print hex directly to stderr
    mov rdi, newline            ; Add newline
    call print_trace
    
    ; Send frame
    mov rdi, rsp                ; Frame buffer
    call send_frame
    add rsp, 32                 ; Restore stack
    ret

send_content_body:
    ; Input: RDI = input buffer address, RSI = message length
    push rdi  ; save input buffer address
    push rsi  ; save message length
    
    ; Build AMQP body frame
    lea rdi, [frame_buffer]
    mov byte [rdi], 3               ; body frame type
    mov word [rdi + 1], 0x0100      ; channel 1 (big endian)
    ; Frame size (big endian)
    mov eax, [rsp]                  ; message length from stack
    cmp eax, FRAME_BUFFER_SIZE - 8
    ja frame_buffer_overflow
    mov rsi, rdi
    add rsi, 3                      ; point to frame size field
    call write_be32_at_rsi          ; write frame size in big endian
    ; Copy message
    mov rsi, [rsp + 8]              ; input buffer address from stack
    add rdi, 7
    mov ecx, [rsp]                  ; message length from stack
    rep movsb
    ; Frame end
    mov byte [rdi], 0xCE

    ; Output frame as hex to stderr
    lea rdi, [frame_buffer]         ; frame start
    mov edx, [rsp]                  ; message length from stack
    add rdx, 8                      ; + 8 for frame header (7) + frame end (1)
    call dump_frame_hex_spaced      ; Print hex directly to stderr

    ; Send frame
    lea rdi, [frame_buffer]
    mov edx, [rsp]                  ; message length from stack
    add rdx, 8
    call send_frame
    
    pop rsi   ; restore message length
    pop rdi   ; restore input buffer address
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
    cmp ax, 0x3C00                  ; Basic class (60 in network byte order read as little endian)
    jne wait_loop

    mov ax, [receive_buffer + 9]
    cmp ax, 0x3C00                  ; Deliver method (60 in network byte order read as little endian)
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
    ; Convert from big endian to little endian
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
    ; Input: RDI = input buffer address
    push rdi  ; save input buffer address
    
    mov rax, 0                      ; sys_read
    mov rdi, 0                      ; stdin
    mov rsi, [rsp]                  ; input buffer address from stack
    mov rdx, (INPUT_BUFFER_SIZE - 1)
    syscall

    test rax, rax
    jle read_done

    ; Remove newline
    dec rax
    mov rsi, [rsp]                  ; input buffer address
    mov byte [rsi + rax], 0

    ; Return message length in RAX
    test eax, eax
    jz .skip_empty_line
    
    pop rdi   ; restore and discard input buffer address
    ; RAX already contains message length
    ret

.skip_empty_line:
    pop rdi   ; restore input buffer address 
    jmp read_stdin_message          ; skip empty lines

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
; Convert frame to hex and print to stderr for debugging  
; Input: RDI = buffer pointer, RDX = buffer length
dump_frame_hex:
%ifdef TRACING
    push rsi
    push rdi
    push rcx
    push rax
    push rbp
    mov rbp, rsp
    
    ; Allocate small hex buffer on stack (64 bytes should be enough for debugging)
    sub rsp, 64
    
    mov rsi, rdi            ; source buffer
    mov rdi, rsp            ; destination buffer (stack)
    mov rcx, rdx            ; byte count
    ; Limit to fit in our small buffer (max 30 bytes -> 60 hex chars + null)
    cmp rcx, 30
    jle .convert_start
    mov rcx, 30

.convert_start:
    mov rbx, rcx            ; save original count

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
    
    ; Print the hex string
    mov rax, 1              ; sys_write
    mov rdi, 2              ; stderr
    mov rsi, rsp            ; hex buffer
    mov rdx, rbx            ; byte count * 2
    shl rdx, 1              ; double for hex chars
    syscall

    mov rsp, rbp
    pop rbp
    pop rax
    pop rcx
    pop rdi
    pop rsi
%endif
    ret

; Alternative version that adds spaces between bytes for readability
; Input: RDI = buffer pointer, RDX = buffer length  
dump_frame_hex_spaced:
%ifdef TRACING
    push rsi
    push rdi
    push rcx
    push rax
    push rbp
    mov rbp, rsp
    
    ; Allocate small hex buffer on stack (96 bytes for spaced output)
    sub rsp, 96
    
    mov rsi, rdi            ; source buffer
    mov rdi, rsp            ; destination buffer (stack)
    mov rcx, rdx            ; byte count
    ; Limit to fit in our buffer (max 20 bytes -> 40 hex chars + 19 spaces + null = 60)
    cmp rcx, 20
    jle .convert_start_spaced
    mov rcx, 20

.convert_start_spaced:
    mov rbx, rcx            ; save original count

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
    
    ; Print the hex string  
    mov rax, 1              ; sys_write
    mov rdi, 2              ; stderr
    mov rsi, rsp            ; hex buffer
    ; Calculate length: bytes * 2 (hex) + bytes - 1 (spaces)
    mov rdx, rbx
    shl rdx, 1              ; bytes * 2
    add rdx, rbx            ; + bytes  
    dec rdx                 ; - 1 (no space after last byte)
    syscall

    mov rsp, rbp
    pop rbp
    pop rax
    pop rcx
    pop rdi
    pop rsi
%endif
    ret

; Helper function to write 32-bit value in big-endian format
; Input: eax = value, rsi = destination address
write_be32_at_rsi:
    push rdx
    ; Write bytes in big-endian order (network byte order)
    mov edx, eax
    shr edx, 24
    mov [rsi], dl               ; bits 31-24 (MSB)
    mov edx, eax
    shr edx, 16  
    mov [rsi+1], dl             ; bits 23-16
    mov edx, eax
    shr edx, 8
    mov [rsi+2], dl             ; bits 15-8  
    mov [rsi+3], al             ; bits 7-0 (LSB)
    pop rdx
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
    mov rsi, password_buffer
    mov rdx, 127                ; Leave space for null terminator
    syscall
    
    ; Remove trailing newline if present
    test rax, rax
    jz .password_done
    mov rdi, password_buffer
    add rdi, rax
    dec rdi
    cmp byte [rdi], 10          ; newline
    jne .set_password_ptr
    mov byte [rdi], 0
    
.set_password_ptr:
    ; Update password pointer to point to entered password
    mov rax, password_buffer
    mov [config_password_ptr], rax
    
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
