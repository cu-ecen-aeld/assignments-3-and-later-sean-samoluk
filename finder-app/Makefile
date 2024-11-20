TARGET = writer

CC = gcc

all: $(TARGET)


$(TARGET): $(TARGET).o
	$(CROSS_COMPILE)$(CC) -o $(TARGET) $(TARGET).o

$(TARGET).o: $(TARGET).c
	$(CROSS_COMPILE)$(CC) -c $(TARGET).c -o $(TARGET).o

.PHONY: clean
clean:
	rm -f $(TARGET) $(TARGET).o
