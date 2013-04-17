BINDIR=bin
INCDIR=include
SRCDIR=src

PLATFORM=ML3
FLAGS=-ansi -D$(PLATFORM)
CARDFLAGS=$(FLAGS) -I$(INCDIR) -Falu -O
SIMFLAGS=$(FLAGS) -g -I$(INCDIR) -DSIMULATOR

HEADERS=$(wildcard $(INCDIR)/*.h)
SOURCES=$(wildcard $(SRCDIR)/*.c)

SMARTCARD=$(BINDIR)/IRMAcard.smartcard-$(PLATFORM).alu
SIMULATOR=$(BINDIR)/IRMAcard.simulator-$(PLATFORM).hzx

all: simulator smartcard

$(BINDIR):
	mkdir $(BINDIR)

simulator: $(HEADERS) $(SOURCES) $(SIMULATOR)

$(SIMULATOR): $(HEADERS) $(SOURCES) $(BINDIR)
	hcl $(SIMFLAGS) $(SOURCES) -o $(SIMULATOR)

smartcard: $(HEADERS) $(SOURCES) $(SMARTCARD)

$(SMARTCARD): $(HEADERS) $(SOURCES) $(BINDIR)
	hcl $(CARDFLAGS) $(SOURCES) -o $(SMARTCARD)

clean:
	rm -rf $(BINDIR) $(SRCDIR)/*~ $(INCDIR)/*~

.PHONY: all clean simulator smartcard
