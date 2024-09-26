#include <stdio.h>
#include <stdlib.h>

	int main(int argc, char *argv[]) {
		
		//check for correct command line argument
		if(argc != 2) {
			fprintf(stderr, "Invalid command");
			//return error
			return 1;
		}
		//else return success
		return 0;
	}
