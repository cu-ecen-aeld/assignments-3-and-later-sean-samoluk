TARGET = aesdsocket

CC = gcc
CFLAGS += -Wall -Werror

all: $(TARGET)


$(TARGET): $(TARGET).o
	$(CROSS_COMPILE)$(CC) -o $(TARGET) $(TARGET).o $(CFLAGS)

$(TARGET).o: $(TARGET).c
	$(CROSS_COMPILE)$(CC) -c $(TARGET).c -o $(TARGET).o $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(TARGET) $(TARGET).o
