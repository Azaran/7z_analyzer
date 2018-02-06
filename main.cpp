#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <cstring>
#include <cstdlib>

#include "SevenZFormat.h"

void PrintHelp() {
    std::cout << "Usage: ./7z_analyzer <.7z archive>" << std::endl;
};

int CheckParameters(int argc, char *argv[], std::ifstream& in){

    if (argc != 2) {
	PrintHelp();
	return 1;
    } else {
	if ((strcmp(argv[1], "--help") == 0) || (strcmp(argv[1], "-h") == 0)) {
	    PrintHelp();
	    exit(0);
	}
	else
	    in.open(argv[1]);
    }
    if (!in.is_open()) {
	std::cerr << "ERROR: Couldn't open the archive" << std::endl;
	return 2;
    } else
	return 0;
}

int main (int argc, char *argv[]) {
    
    SevenZFormat archive;

    if (CheckParameters(argc, argv, archive.getStream()) > 0){
	return 1;
    }

    archive.process();
    archive.finish();

    return 0;

}
