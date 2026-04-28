TARGET = netfilter-test
SRC = main.cpp

all:$(TARGET)

$(TARGET): $(SRC)
	g++ -o $(TARGET) $(SRC) -lnetfilter_queue

clean:
	rm -f $(TARGET)

