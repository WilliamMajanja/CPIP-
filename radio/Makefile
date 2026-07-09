CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -pthread -std=c11
LDFLAGS = -pthread
TARGET  = radio_if

.PHONY: all clean run-sim

all: $(TARGET)

$(TARGET): radio_if.c radio_if.h
	$(CC) $(CFLAGS) -o $@ radio_if.c $(LDFLAGS)

clean:
	rm -f $(TARGET)

run-sim: $(TARGET)
	./$(TARGET) --sim
