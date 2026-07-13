CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -pthread -std=c11
LDFLAGS = -pthread
TARGET  = radio_if

.PHONY: all clean run-sim run-lora rtl

all: $(TARGET)

$(TARGET): radio_if.c radio_if.h
	$(CC) $(CFLAGS) -o $@ radio_if.c $(LDFLAGS)

rtl: radio_if.c radio_if.h
	$(CC) $(CFLAGS) -DUSE_RTLSDR -o $(TARGET) radio_if.c $(LDFLAGS) -lrtlsdr -lm

clean:
	rm -f $(TARGET)

run-sim: $(TARGET)
	./$(TARGET) --sim

run-lora: $(TARGET)
	./$(TARGET) --lora --freq 915000000 --sf 9 --bw 125000

run-tnc: $(TARGET)
	./$(TARGET) --tnc --device /dev/ttyUSB0 --baud 115200