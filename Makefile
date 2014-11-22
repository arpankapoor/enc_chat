CC = gcc -g
CXX = g++ -g
CFLAGS = -Wall -std=gnu11
CXXFLAGS = -Wall -std=c++14
CSRCS = pssl_aes.c pssl_aesni.c pssl_net.c pssl_sha1.c
COBJS = $(CSRCS:.c=.o)
MAINS = client server adduser

all: $(MAINS)

server: server.o util.o $(COBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

client: client.o util.o $(COBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

adduser: adduser.o pssl_sha1.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o $(MAINS)
