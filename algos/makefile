CC=gcc
CXXFLAGS = -O2 -I.. -march=native
CFLAGS= $(CXXFLAGS) -std=gnu99
LDFLAGS=-O2 -lm -lstdc++

SOURCES=scrypt.c \
	sha256.c \
	crypto/Lyra2.c \
	crypto/Lyra2RE.c \
	crypto/Sponge.c \
	crypto/blake.c \
	crypto/block.cpp \
	crypto/bmw.c \
	crypto/cubehash.c \
	crypto/dag.cpp \
	crypto/groestl.c \
	crypto/keccak.c \
	crypto/skein.c \
	nightcap.cpp

OBJECTS=$(SOURCES:%.c=%.o) $(SOURCES:%.cpp=%.o)
OUTPUT=libalgos.a

all: $(SOURCES) $(OUTPUT)

$(OUTPUT): $(OBJECTS)
	ar rc $@ $(OBJECTS)
	touch ../stratum.cpp

.cpp.o:
	$(CC) $(CXXFLAGS) -c $< -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o
	rm -f crypto/*.o
