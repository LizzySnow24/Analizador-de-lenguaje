.MODEL SMALL
.CODE
Inicio:
mov Ax, @Data
mov Ds, Ax

mov Ax, Ax

SaltoMien0:
mov Dx, offset c+2
mov Si, Dx
mov Cl, byte ptr [Si]
 
mov Dx, offset Var1
mov Si, Dx
mov Ch, byte ptr [Si] 

cmp Cl,Ch

je SaltoMien1
mov Ah,09h
mov Dx,offset Var2
int 21h

mov Ah, 09h 
mov Dx,offset salto00
int 21h

mov Ah, 0Ah 
mov Dx,offset n
int 21h

mov Ah, 09h 
mov Dx,offset salto00
int 21h

xor Ax, Ax 
xor Bx, Bx 
mov Dx, offset n+2
mov Si, Dx
mov Al, byte ptr [Si] 
sub Al, 48

mov Dx, offset Var3
mov Si, Dx
mov Bl, byte ptr [Si] 
sub Bl, 48

div Bl 
mov j, Ah
add j, 48

Salto1:
mov Dx, offset j
mov Si, Dx
mov Cl, byte ptr [Si]
 
mov Dx, offset Var4
mov Si, Dx
mov Ch, byte ptr [Si] 

cmp Cl,Ch

jne Salto2
mov Ah,09h
mov Dx,offset Var5
int 21h

mov Ah, 09h 
mov Dx,offset salto00
int 21h

mov Al, Var6
sub Al, '0'
xor Cx, Cx
mov Si, offset n +2
mov Cl, byte ptr [Si]
sub Cl, '0'

sub Cl, Al
add Cl, 1

mov byte ptr [a], 1
add a, 48

SaltoPer1:

push Cx
mov Dx, offset a
mov Si, Dx
mov Al, byte ptr [Si] 
sub Al, 48

mov Dx, offset Var7
mov Si, Dx
mov Ah, byte ptr [Si] 
sub Ah, 48

mul Ah 
mov b, Al
add b, 48

mov Ah,09h
mov Dx,offset  b
int 21h

mov Ah, 09h 
mov Dx,offset salto00
int 21h

inc Var6
pop Cx
inc a
loop SaltoPer1

jmp Salto3

Salto2:

jmp Salto3

Salto3:

Salto4:
mov Dx, offset j
mov Si, Dx
mov Cl, byte ptr [Si]
 
mov Dx, offset Var8
mov Si, Dx
mov Ch, byte ptr [Si] 

cmp Cl,Ch

je Salto5
mov Ah,09h
mov Dx,offset Var9
int 21h

mov Ah, 09h 
mov Dx,offset salto00
int 21h

mov Al, Var10
sub Al, '0'
xor Cx, Cx
mov Si, offset n +2
mov Cl, byte ptr [Si]
sub Cl, '0'

sub Cl, Al
add Cl, 1

mov byte ptr [a], 1
add a, 48

SaltoPer2:

push Cx
mov Dx, offset a
mov Si, Dx
mov Al, byte ptr [Si] 
sub Al, 48

mov Dx, offset Var11
mov Si, Dx
mov Ah, byte ptr [Si] 
sub Ah, 48

mul Ah 
mov b, Al
add b, 48

xor Cx, Cx
mov Dx, offset b
mov Si, Dx
mov Cl, byte ptr [Si] 
sub Cl, 48

mov Dx, offset Var12
mov Si, Dx
mov Ch, byte ptr [Si] 
sub Ch, 48

xor b, 0
mov b, Cl
sub b, Ch
add b, 48

mov Ah,09h
mov Dx,offset  b
int 21h

mov Ah, 09h 
mov Dx,offset salto00
int 21h

inc Var10
pop Cx
inc a
loop SaltoPer2

jmp Salto6

Salto5:

jmp Salto6

Salto6:

mov Ah,09h
mov Dx,offset Var13
int 21h

mov Ah, 09h 
mov Dx,offset salto00
int 21h

mov Ah, 0Ah 
mov Dx,offset c
int 21h

mov Ah, 09h 
mov Dx,offset salto00
int 21h

jmp SaltoMien0

SaltoMien1:

mov Ah, 4Ch
int 21h
.DATA
 j  db 255, ?, 255 dup("$")
 n  db 255, ?, 255 dup("$")
 c  db 255, ?, 255 dup("$")
 b  db 255, ?, 255 dup("$")
 a  db 255, ?, 255 dup("$")
salto00 db 10,13,10,13,"$"
Var1 db '1','$'
Var2 db 'Ingrese valor: $'
Var3 db '2','$'
Var4 db '0','$'
Var5 db 'Es par$'
Var6 db '1', '$'
Var7 db '2','$'
Var8 db '0','$'
Var9 db 'Es impar$'
Var10 db '1', '$'
Var11 db '2','$'
Var12 db '1','$'
Var13 db 'Si quiere seguir escriba un valor diferente de 1: $'
.STACK
END Inicio
