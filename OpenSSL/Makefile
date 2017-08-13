CC = gcc

#openssl  安装路径
LIBPATH = /usr/local/ssl/include
LIBSSL = /usr/local/ssl/lib64

OBJ = TestOpenssl.o
RM = rm -f

TARGERT = OPENSSLTEST_P7B


$(TARGERT):$(OBJ)
	$(CC) -o $(TARGERT) $(OBJ)  -L $(LIBSSL) -lssl -lcrypto -ldl

$(OBJ):%.o:%.c
	$(CC) -c $< -o $@ -I $(LIBPATH)

clean:
	rm -f $(TARGERT) *.o
