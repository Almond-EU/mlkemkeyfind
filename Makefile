CC = gcc
CFLAGS = -Wall -Wformat -O3

BINDIR = bin
SRCDIR = src
OBJDIR = obj
INCDIR = include

_BIN = mlkemkeyfind
BIN = $(addprefix $(BINDIR)/, $(_BIN))
SRC = $(wildcard $(SRCDIR)/*.c) $(wildcard $(SRCDIR)/**/*.c)
_OBJ = $(patsubst $(SRCDIR)/%.c, %.o, $(SRC))
OBJ = $(addprefix $(OBJDIR)/, $(_OBJ))

all: $(BIN)

$(BIN): $(BINDIR) $(OBJDIR) $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(BIN)

$(BINDIR):
	mkdir -p $(BINDIR)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@ -I$(INCDIR)

.PHONY: clean

clean:
	rm -rf $(OBJDIR) $(BINDIR)
