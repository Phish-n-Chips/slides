
all: 64

64: chal1-64 chal2-64 chal3-64 chal4-64 chal5-64
64n: chal1-64n chal2-64n chal3-64n chal4-64n chal5-64n
64s: chal1-64s chal2-64s chal3-64s chal4-64s chal5-64s

32: chal1-32 chal2-32 chal3-32 chal4-32 chal5-32
32n: chal1-32n chal2-32n chal3-32n chal4-32n chal5-32n
32s: chal1-32s chal2-32s chal3-32s chal4-32s chal5-32s

clean:
	rm -f chal?-32 chal?-64 chal?-32n chal?-64n chal?-32s chal?-64s stkdbg??.so *.o

stkdbg32.so: stkdbg.c
	gcc -m32 -O1 -shared -o $@ $^

stkdbg64.so: stkdbg.c
	gcc -m64 -O1 -shared -o $@ $^

LDS_chal1=
LDS_chal2=
LDS_chal3=
LDS_chal4=-Wl,-T,chal4.lds
LDS_chal5=-Wl,-T,chal5.lds

chal%-32: chal%.c stkdbg32.so
	gcc -m32 -O0 -fno-pic -no-pie -fno-stack-protector -Wl,--build-id=none ${LDS_chal$(*F)} -L. -o $@ $< ./stkdbg32.so

chal%-64: chal%.c stkdbg64.so
	gcc -m64 -O0 -fno-pic -no-pie -fno-stack-protector -Wl,--build-id=none ${LDS_chal$(*F)} -L. -o $@ $< ./stkdbg64.so

chal%-32n: chal%.c
	gcc -m32 -O0 -DNO_DUMP -fno-pic -no-pie -fno-stack-protector -Wl,--build-id=none ${LDS_chal$(*F)} -L. -o $@ $<

chal%-64n: chal%.c
	gcc -m64 -O0 -DNO_DUMP -fno-pic -no-pie -fno-stack-protector -Wl,--build-id=none ${LDS_chal$(*F)} -L. -o $@ $<

chal%-32s: chal%.c stkdbg.c
	gcc -m32 -O0 -fno-pic -no-pie -fno-stack-protector -Wl,--build-id=none ${LDS_chal$(*F)} -o $@ $^

chal%-64s: chal%.c stkdbg.c
	gcc -m64 -O0 -fno-pic -no-pie -fno-stack-protector -Wl,--build-id=none ${LDS_chal$(*F)} -o $@ $^
