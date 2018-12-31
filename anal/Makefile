NAME=anal_m7700
export PATH := $(PATH)../r2_bin/include/libr/
R2_PLUGIN_PATH=$(shell r2 -hh|grep LIBR_PLUGINS|awk '{print $$2}')
CFLAGS=-g -fPIC -I ../r2_bin/libr/include # $(shell pkg-config --cflags r_asm)
LDFLAGS=-shared -I ../r2_bin/libr/include  # $(shell pkg-config --libs r_asm) -L ../r2_bin/include
OBJS=$(NAME).o
SO_EXT=$(shell uname|grep -q Darwin && echo dylib || echo so)
LIB=$(NAME).$(SO_EXT)

all: $(LIB)

clean:
	rm -f $(LIB) $(OBJS)

$(LIB): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $(LIB)

install:
	cp -f $(NAME).$(SO_EXT) $(R2_PLUGIN_PATH)

uninstall:
	rm -f $(R2_PLUGIN_PATH)/$(NAME).$(SO_EXT)
