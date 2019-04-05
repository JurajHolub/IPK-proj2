# IPK project 2
# @author Juraj Holub <xholub40@stud.fit.vutbr.cz>
# @date 2019

CC = g++
CFLAGS = -I -g -Werror -Wall
OBJ = main.o \
	  argument_parser.o
EXECUTABLE = ipk-scan

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ 

%.o: %.cpp %.h
	$(CC) $(CFLAGS) -c $<

.PHONY: run doc pack clean test
run: $(EXECUTABLE)
	./$(EXECUTABLE)

pack:
	cp doc/dokumentace.pdf . && zip xholub40.zip *.c *.h Makefile rozdeleni dokumentace.pdf

clean:
	rm -rf *.o *.out $(EXECUTABLE)
test:
	cd tests && bash test_outputs.bash
