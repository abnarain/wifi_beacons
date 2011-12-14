
CC=gcc

CFLAGS+=-c -Wall -O3 -fno-strict-aliasing -DOSX
LDFLAGS+=-lpcap  -lz

SOURCES=sniffer.c  create-interface.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=wifi_beacons

all: clean $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) -lz -lpcap  $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o wifi_beacons
