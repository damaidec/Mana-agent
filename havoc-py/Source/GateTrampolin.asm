bits 64

section .text

global PrepareSyscall
global DoSyscall

PrepareSyscall:
    xor r11, r11
    xor r10, r10
    mov r11, rcx
    mov r10, rdx
    ret

DoSyscall:
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret

;.code

;PrepareSyscall PROC

;  xor r11, r11
;  xor r10, r10
;  mov r11, rcx
;  mov r10, rdx
;  ret


;PrepareSyscall ENDP

;DoSyscall Proc

;  push r10
;  xor rax, rax
;  mov r10, rcx
;  mov eax, r11d
;  ret
	
;DoSyscall ENDP

;end
