
IDA = ../..

TARGET=prxldr.ldw
OBJS = prxldr.o

CC = g++
INC = -I$(IDA)/include

CFLAGS = -DWIN32 -D__NT__ -D__IDP__ -mrtd -DUSE_DANGEROUS_FUNCTIONS -DUSE_STANDARD_FILE_FUNCTIONS $(INC)
CXXFLAGS = $(CFLAGS)
LDFLAGS = --static -Wl,--dll -shared
# -Wl -shared -s
LIBS = $(IDA)/lib/x86_win_gcc_32/ida.a


all:$(TARGET)

$(TARGET):$(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS) $(LDFLAGS)
	cp -af $@ "/d/Program Files/IDA61/loaders"

clean:
	rm -f *.o
	rm -f $(TARGET)














