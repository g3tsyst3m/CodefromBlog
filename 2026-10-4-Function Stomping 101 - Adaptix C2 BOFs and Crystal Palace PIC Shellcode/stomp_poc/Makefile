# stomp_poc — Remote Function Stomping PoC
# Build with MinGW cross-compiler (x64 target)

CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -O2 -Wall -Wextra
LDLIBS  = -lcomdlg32 -static
TARGET  = stomp.exe

.PHONY: all clean

all: $(TARGET)

$(TARGET): stomp.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGET)
