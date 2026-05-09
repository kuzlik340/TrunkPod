CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=gnu11
LDFLAGS = -lpcap
TARGET  = traffic_parser

all: $(TARGET)

$(TARGET): traffic_parser.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/sbin/$(TARGET)

.PHONY: all clean install
