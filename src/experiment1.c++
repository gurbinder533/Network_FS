#include <unistd.h>
#include <iostream>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <ctime>
#include <chrono>

using std::cout;
using std::endl;

#define DATA_SIZE 8192
#define SMALL_WRITE 1024

static const char* NFS_path = "/u/gill/AOS/lab2/build/NFS_file.txt";
static const char* FUSE_path = "/tmp/fuse/file.txt";
int main() {
	
	using namespace std::chrono;
	high_resolution_clock::time_point start, end ;

 	int fd_rand = open("/dev/urandom", O_RDONLY);
	char data[DATA_SIZE];
	int readSize = read(fd_rand, &data, DATA_SIZE);
	printf("read 1 size : %d\n", readSize);

	close(fd_rand);
        
	start = high_resolution_clock::now();
        int fd = open(FUSE_path, O_RDWR);
	end = high_resolution_clock::now();
	auto time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	cout << "Time for 1st open = "<<time_taken << " ms"<<endl;

	start = high_resolution_clock::now();
	int writeSize = write(fd, &data, DATA_SIZE);
	end = high_resolution_clock::now();
	time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	cout << "write 1 size :"<< writeSize << " Time Taken = " << time_taken<< " ms" <<endl;;
	close(fd);

	start = high_resolution_clock::now();
	fd = open(FUSE_path, O_RDWR);
	end = high_resolution_clock::now();
	time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	cout << "Time for 2nd open = "<<time_taken << " ms"<<endl;

	char data_read[DATA_SIZE];
	start = high_resolution_clock::now();
	readSize = read(fd, &data_read, DATA_SIZE);
	end = high_resolution_clock::now();
	time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	cout << "read 2 size :"<< readSize << " Time Taken = " << time_taken<< " ms" << endl;;

	close(fd);


#ifdef MORE_OPENS
	int opens = 40;
	int writes = 5;
	char buf[SMALL_WRITE];
	int small_write = 0;
	fd_rand = open("/dev/urandom", O_RDONLY);
	read(fd_rand, &buf, SMALL_WRITE);
	close(fd_rand);
 
	start = high_resolution_clock::now();
	for (int i = 0; i < (opens - 1); ++i) {
		fd = open(FUSE_path, O_RDWR);
//		cout << "fd = " << fd << endl;
		if (!fd)
			perror("opening file");
		close(fd);
	}  
	for (int i = 0; i < writes; ++i) { 
		fd = open(FUSE_path, O_RDWR);
//		cout << "write fd = " << fd << endl;
		if (!fd)
			perror("opening file for writing");

		small_write = write(fd, &buf, SMALL_WRITE);	
		if (small_write != SMALL_WRITE)
			perror("small write Error");
		close(fd);
	}

	end = high_resolution_clock::now();
	time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	cout << "opens  :"<< opens << "  writes :" << writes << " Time Taken = " << time_taken<<" ms" << endl;;
#endif


	return 0;
}



