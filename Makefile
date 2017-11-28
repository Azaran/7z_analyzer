PROGRAM=7z_analyser

INCLUDES=-I./include
SRCS=LzmaDec.cpp SevenZFormat.cpp main.cpp


CXX=g++
CXXOPTS=--std=c++11
CXXFLAGS=-Wall -Wextra -pedantic -g

OBJS=$(SRCS:.cpp=.o)

all: $(PROGRAM)

%.o : %.cpp
	$(CXX) $(CXXOPTS) $(INCLUDES) -c $< 
	
$(PROGRAM):$(OBJS)
	$(CXX) -o $(PROGRAM) $(OBJS) $(CXXFLAGS) $(CXXOPTS)

.PHONY: clean
clean: 
	rm *.o $(PROGRAM)
