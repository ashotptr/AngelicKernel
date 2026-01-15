# Compiler Settings
CC = gcc
LD = ld
OBJCOPY = objcopy

# GNU-EFI Paths (Standard for Ubuntu/Debian)
# If compilation fails, check if these exist on your machine
EFIINC = /usr/include/efi
EFILIB = /usr/lib
LIB = /usr/lib

# Compiler Flags
# Added -DGNU_EFI_USE_MS_ABI to fix the calling convention crash
CFLAGS = -I. -I./include -I./lwip/src/include \
         -I$(EFIINC) -I$(EFIINC)/x86_64 -I$(EFIINC)/protocol \
         -fno-stack-protector -fpic -fshort-wchar -mno-red-zone \
         -Wall -Wextra -DEFI_FUNCTION_WRAPPER -DGNU_EFI_USE_MS_ABI

# Linker Flags
LDFLAGS = -nostdlib -znocombreloc -shared -Bsymbolic -L $(EFILIB) -L $(LIB) \
          -T $(EFILIB)/elf_x86_64_efi.lds

# Source Files
# We start with just the kernel. We will add lwip/*.c files here later.
SRCS = src/kernel.c
OBJS = $(SRCS:.c=.o)

# Output Target
TARGET = unikernel.efi

all: $(TARGET)

# Link Step
$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $(EFILIB)/crt0-efi-x86_64.o $(OBJS) -o unikernel.so -lgnuefi -lefi
	$(OBJCOPY) -j .text -j .sdata -j .data -j .dynamic -j .dynsym  -j .rel \
	            -j .rela -j .rel.* -j .rela.* -j .reloc \
	            --target efi-app-x86_64 --subsystem=10 unikernel.so $(TARGET)
	@echo "SUCCESS: $(TARGET) created."

# Compile Step
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) *.so *.efi