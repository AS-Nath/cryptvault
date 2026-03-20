CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
TARGET   = cryptvault
SRCS     = main.cpp vault.cpp
OBJS     = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) vault.bin

.PHONY: all clean
