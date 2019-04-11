# IPK project 2
# @author Juraj Holub <xholub40@stud.fit.vutbr.cz>
# @date 2019

CC = g++
CFLAGS = -I -g -lpcap
OBJ = main.o \
	  argument_parser.o \
	  tcp_scanner.o \
	  udp_scanner.o \
	  scanner.o
EXECUTABLE = ipk-scan

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

%.o: %.cpp %.h
	$(CC) -c $< $(CFLAGS)

.PHONY: pack clean
pack:
	cp doc/manual.pdf . && tar -czvf xholub40.tar *.cpp *.h Makefile README manual.pdf

clean:
	rm -rf *.o *.out $(EXECUTABLE)
