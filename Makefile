.POSIX:

CFLAGS = -Wall -Wextra -Werror -std=c99 -O2
LDFLAGS = -O2

OBJS = src/main.o

all: diskwise
diskwise: $(OBJS)
	${CC} $(LDFLAGS) -o $@ $(OBJS)

clean:
	rm -rf $(OBJS) diskwise
