CXX = g++
CXXFLAGS = -std=c++17 -Wall
LDFLAGS = -lpcap

SRC = src/sniffer.cpp
OBJ = $(SRC:.cpp=.o)
TARGET = bin/sniff

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(OBJ) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
