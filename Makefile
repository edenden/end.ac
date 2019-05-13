CC = gcc
CFLAGS = -Wall -O2 -g -std=gnu99
LDFLAGS = -lbpf -lpthread -lelf

TARGET = main.out
TARGET-SRCS = main.c epoll.c forward.c lib.c driver.c thread.c
TARGET-OBJS = $(subst .c,.o,$(TARGET-SRCS))

all: ${TARGET}

${TARGET}: ${TARGET-OBJS}
	$(CC) -o $@ $^ ${LDFLAGS}

.c.o:
	$(CC) ${CFLAGS} -o $@ -c $<

.PHONY: clean
clean:
	rm -f ${TARGET} ${TARGET-OBJS}
