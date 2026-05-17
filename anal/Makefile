NAME=anal_m7700
R2_PLUGIN_PATH=$(shell r2 -hh 2>/dev/null | grep LIBR_PLUGINS | awk '{print $$2}')
CFLAGS=-g -fPIC $(shell PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --cflags r_anal 2>/dev/null || echo -I/usr/local/include/libr)
LDFLAGS=-shared
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
