.PHONY : build clean prepare

default :
	@echo "======================================="
	@echo "Please use 'make build' command to build it.."
	@echo "Please use 'make clean' command to clean all."
	@echo "======================================="

CC = cc
RM = rm -rf
MV = mv

INCLUDES += -I../../src -I../../../src -I/usr/local/include
LIBS += -L../ -L../../ -L../../../ -L/usr/local/LIBS
CFLAGS += -g0 -O3 -shared -fPIC
MICRO += -fno-omit-frame-pointer -Wno-implicit-fallthrough -Wall -Wextra -Wno-unused-parameter
DLL += -lcore -lnghttp2

build:
	@$(CC) -o lhpack.so lhpack.c hpack.c common.c $(INCLUDES) $(LIBS) $(CFLAGS) $(MICRO) $(DLL)
	@$(MV) *.so ../

clean:
	@$(RM) main *.so
