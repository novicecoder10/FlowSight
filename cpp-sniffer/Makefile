CC = g++
CFLAGS = -std=c++17 -Wall -O3 -flto -march=native -pthread
LDFLAGS = -lpcap -lssl -lcrypto -pthread

SRC = main.cpp sniffer.cpp utils.cpp
OBJ = $(SRC:.cpp=.o)

TARGET = packet_sniffer

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)