CC?=gcc
CFLAGS=-Wall -g
OBJECTS=main.o ptrace.o trace.o

itrace: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ -ludis86

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	-rm -f $(OBJECTS) itrace
