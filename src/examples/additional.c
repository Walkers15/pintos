#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int main (int argc, char** argv) {
	if (argc != 5) {
// printf("Invalid Argument!! \n");
	}
	int a = atoi(argv[1]);
	int b = atoi(argv[2]);
	int c = atoi(argv[3]);
	int d = atoi(argv[4]);
	// printf("HI IM ADDITIONAL %d\n", a);
	// printf("%d\n", fibonacci(a));
	// printf("CALL MAX OF FOUT INT! \n");
	// max_of_four_int(a, a, a, a);
// printf("%u %d\n", fibonacci(a), max_of_four_int(a, b, c ,d));

}
