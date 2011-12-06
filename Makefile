
CC=gcc

CFLAGS+=-c -Wall -O3 -fno-strict-aliasing -DOSX 
LDFLAGS+=-lpcap -lpthread -lz

SOURCES=sniffer.c  create-interface.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=sniffer

all: clean $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
		$(CC) $(LDFLAGS) -lz -lpcap -lpthread $(OBJECTS) -o $@

.c.o:
		$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o sniffer
