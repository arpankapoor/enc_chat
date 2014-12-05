CC = gcc -g
CXX = g++ -g
LIB = -lpolarssl
CFLAGS = -Wall -std=gnu11 $(LIB)
CXXFLAGS = -Wall -std=c++11 $(LIB)
MAINS = client server adduser

all: $(MAINS)

server: server.o util.o
	$(CXX) $(CXXFLAGS) -o $@ $^

client: client.o util.o
	$(CXX) $(CXXFLAGS) -o $@ $^

adduser: adduser.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o $(MAINS)
