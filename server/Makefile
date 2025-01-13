TARGET ?= aesdsocket

CC ?= ${CROSS_COMPILE)gcc
CFLAGS ?= -g -Wall -Werror
LDFLAGS ?= -lpthread -lrt

all: $(TARGET)

$(TARGET): $(TARGET).o
	$(CC) -o $(TARGET) $(TARGET).o $(CFLAGS) 

$(TARGET).o: $(TARGET).c
	$(CC) -c $(TARGET).c -o $(TARGET).o $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(TARGET) $(TARGET).o
