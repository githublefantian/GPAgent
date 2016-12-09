TARGET=ports_statistics
SOURCES=$(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SOURCES))
LOCLIB=     # ./jdis_msmtp/*.a
INCLUDE=    # -I/usr/include/mysql
DB_LIB=-lpcap
#debug=y
ifeq ($(debug),y)
CFLAGS += -g -O1 -Wall -MD
else
CFLAGS += -s -O2 -Wall -MD
endif

CXX:=gcc

all: $(OBJS)
	$(CXX) $(CFLAGS) -o $(TARGET) $(OBJS) $(LOCLIB)  $(DB_LIB)

.c.o:
	@echo compile $@;$(CXX) $(INCLUDE) $(CFLAGS) $< -c

clean:
	-rm -rf $(TARGET) *.o *.d *.a