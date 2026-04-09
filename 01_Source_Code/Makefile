CXX      = g++
CC       = gcc
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
CFLAGS   = -std=c11  -Wall -Wextra -O2
TARGET   = cryptvault

CPP_SRCS = main.cpp vault.cpp
C_SRCS   = vault_io.c
OBJS     = $(CPP_SRCS:.cpp=.o) $(C_SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) vault.bin

.PHONY: all clean