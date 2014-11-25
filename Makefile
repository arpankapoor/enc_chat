CC = gcc -g
CXX = g++ -g
INC = -I./polarssl/include
CFLAGS = -Wall -std=gnu11 $(INC)
CXXFLAGS = -Wall -std=c++11 $(INC)
DEPS = polarssl/library/*.o
MAINS = client server adduser

all: $(MAINS)

server: server.o util.o $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $^

client: client.o util.o $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $^

adduser: adduser.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $^

polarssl/library/*.o:
	cd polarssl && $(MAKE) all && cd ..

clean:
	rm -f *.o $(MAINS)
