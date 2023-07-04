#include "my_stdlib.h"
#include <catch2/catch_test_macros.hpp>

#include <unistd.h>
#include <cmath>
#include <sys/wait.h>
#include <unistd.h>


void performCorruption() {
    // Allocate memory
    void* ptr1 = smalloc(16);  // Allocate 16 bytes
    REQUIRE(ptr1 != nullptr);
    void* ptr2 = smalloc(32);  // Allocate 32 bytes
    REQUIRE(ptr2 != nullptr);

    // Overflow the first allocation
    char* overflowPtr = reinterpret_cast<char*>(ptr1);
    for (int i = 0; i < 2000; i++) {
        overflowPtr[i] = 'A';
    }

    // Allocate more memory
    void* ptr3 = smalloc(64);  // Allocate 64 bytes
    REQUIRE(ptr3 != nullptr);

    // Free the allocations
    sfree(ptr1);
    sfree(ptr2);
    sfree(ptr3);

}
#define MAX_ALLOCATION_SIZE (1e8)
#define MMAP_THRESHOLD (128 * 1024)
#define MIN_SPLIT_SIZE (128)
#define MAX_ELEMENT_SIZE (128*1024)
//static inline size_t aligned_size(size_t size)
//{
//    return (size % 8) ? (size & (size_t)(-8)) + 8 : size;
//}

#define verify_blocks(allocated_blocks, allocated_bytes, free_blocks, free_bytes)                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        REQUIRE(_num_allocated_blocks() == allocated_blocks);                                                          \
        REQUIRE(_num_allocated_bytes() == (allocated_bytes));                                              \
        REQUIRE(_num_free_blocks() == free_blocks);                                                                    \
        REQUIRE(_num_free_bytes() == (free_bytes));                                                        \
        REQUIRE(_num_meta_data_bytes() == (_size_meta_data() * allocated_blocks));                         \
    } while (0)

#define verify_size(base)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        void *after = sbrk(0);                                                                                         \
        REQUIRE(_num_allocated_bytes() + aligned_size(_size_meta_data() * _num_allocated_blocks()) ==                  \
                (size_t)after - (size_t)base);                                                                         \
    } while (0)

#define verify_size_with_large_blocks(base, diff)                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        void *after = sbrk(0);                                                                                         \
        REQUIRE(diff == (size_t)after - (size_t)base);                                                                 \
    } while (0)
void verify_block_by_order(int order0free, int order0used, int order1free, int order1used, \
                                int order2free, int order2used,\
                                int order3free, int order3used, \
                                int order4free, int order4used, \
                                int order5free, int order5used, \
                                int order6free, int order6used, \
                                int order7free, int order7used, \
                                int order8free,int  order8used, \
                                int order9free,int  order9used, \
                                int order10free,int  order10used,
                                int big_blocks_count, long big_blocks_size  )\
                                                                                                                     \
    {                                                                                                                  \
        unsigned int __total_blocks = order0free + order0used+ order1free + order1used+ order2free + order2used+ order3free + order3used+ order4free + order4used+ order5free + order5used+ order6free + order6used+ order7free + order7used+ order8free + order8used+ order9free + order9used+ order10free + order10used + big_blocks_count       ;        \
        unsigned int __total_free_blocks = order0free+ order1free+ order2free+ order3free+ order4free+ order5free+ order6free+ order7free+ order8free+ order9free+ order10free ;                     \
        unsigned int __total_free_bytes_with_meta  = order0free*128*pow(2,0) +  order1free*128*pow(2,1) +  order2free*128*pow(2,2) +  order3free*128*pow(2,3) +  order4free*128*pow(2,4) +  order5free*128*pow(2,5) +  order6free*128*pow(2,6) +  order7free*128*pow(2,7) +  order8free*128*pow(2,8) +  order9free*128*pow(2,9)+  order10free*128*pow(2,10) ;                                                                     \
        unsigned int testing_allocated_bytes;
        if (__total_blocks==0) testing_allocated_bytes = 0;
        else testing_allocated_bytes = big_blocks_size+32 * MAX_ELEMENT_SIZE - (__total_blocks-big_blocks_count)*(_size_meta_data());
        verify_blocks(__total_blocks, testing_allocated_bytes, __total_free_blocks,__total_free_bytes_with_meta - __total_free_blocks*(_size_meta_data()));\
    }

//TEST_CASE("alignment test")
//{
//    // Initial state
//    void *base = sbrk(0);
//    REQUIRE(((size_t)base)%MAX_ELEMENT_SIZE ==0);
//
//}

TEST_CASE("Challenge 0 - Memory Utilization", "[malloc3]")
{
    // Initial state
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);

    // Allocate small block (order 0)
    void *ptr1 = smalloc(40);
    REQUIRE(ptr1 != nullptr);
//    verify_size(base);
    verify_block_by_order(1,1,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,31,0,0,0);

    // Allocate large block (order 10)
    void *ptr2 = smalloc(MAX_ELEMENT_SIZE+100);
    REQUIRE(ptr2 != nullptr);
//    verify_size_with_large_blocks(base, (128 * 1024+100 +_size_meta_data()));
    verify_block_by_order(1,1,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,31,0,1,MAX_ELEMENT_SIZE+100);

    // Allocate another small block
    void *ptr3 = smalloc(50);
    REQUIRE(ptr3 != nullptr);
    verify_block_by_order(0,2,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,31,0,1,MAX_ELEMENT_SIZE+100);

    // Free the first small block
    sfree(ptr1);
    verify_block_by_order(1,1,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,31,0,1,MAX_ELEMENT_SIZE+100);


    // Allocate another small block
    void *ptr4 = smalloc(40);
    REQUIRE(ptr4 != nullptr);
    verify_block_by_order(0,2,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,31,0,1,MAX_ELEMENT_SIZE+100);

    // Free all blocks
    sfree(ptr3);
    sfree(ptr4);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,1,MAX_ELEMENT_SIZE+100);
    sfree(ptr1); //free again
    sfree(ptr2);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0);
//    verify_size_with_large_blocks(base, 0);
//    verify_size(base);
}

TEST_CASE("test all sizes", "[malloc3]")
{
    // Initial state
//    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0);
    void * ptr;
    ptr = smalloc(128*pow(2,0) -64);
    verify_block_by_order(1,1,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,31,0,0,0);
    sfree(ptr);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0);
    ptr = smalloc(128*pow(2,1) -64);
    verify_block_by_order(0,0,1,1,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,31,0,0,0);
    sfree(ptr);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0);
    ptr = smalloc(128*pow(2,2) -64);
    verify_block_by_order(0,0,0,0,1,1,1,0,1,0,1,0,1,0,1,0,1,0,1,0,31,0,0,0);
    sfree(ptr);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0);
    ptr = smalloc(128*pow(2,3) -64);
    verify_block_by_order(0,0,0,0,0,0,1,1,1,0,1,0,1,0,1,0,1,0,1,0,31,0,0,0);
    sfree(ptr);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0);
    ptr = smalloc(128*pow(2,4) -64);
    verify_block_by_order(0,0,0,0,0,0,0,0,1,1,1,0,1,0,1,0,1,0,1,0,31,0,0,0);
    sfree(ptr);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0);
    ptr = smalloc(128*pow(2,5) -64);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,1,1,1,0,1,0,1,0,1,0,31,0,0,0);
    sfree(ptr);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0);
    ptr = smalloc(128*pow(2,6) -64);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,0,1,0,1,0,31,0,0,0);
    sfree(ptr);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0);
    ptr = smalloc(128*pow(2,7) -64);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,0,1,0,31,0,0,0);
    sfree(ptr);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0);
    ptr = smalloc(128*pow(2,8) -64);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,0,31,0,0,0);
    sfree(ptr);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0);
    ptr = smalloc(128*pow(2,9) -64);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,31,0,0,0);
    sfree(ptr);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0);
    ptr = smalloc(128*pow(2,10) -64);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,31,1,0,0);
    sfree(ptr);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,32,0,0,0);
}

TEST_CASE("Finding buddies test", "[malloc3]")
{
    std::vector<void*> allocations;

    // Allocate 64 blocks of size 128 * 2^9 - 64
    for (int i = 0; i < 64; i++)
    {
        void* ptr = smalloc(128 * std::pow(2, 9) - 64);
        REQUIRE(ptr != nullptr);
        allocations.push_back(ptr);
//        printf("%d\n",i);
//        fflush(stdout);
        verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, allocations.size()%2, allocations.size(), 32-(int)(i/2)-1, 0, 0, 0);
    }

    REQUIRE(smalloc(40) == NULL);
    // Free the allocated blocks
    while (!allocations.empty())
    {
        void* ptr = allocations.back();
        allocations.pop_back();
        sfree(ptr);
        verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, allocations.size() % 2, allocations.size(), 32 - (int)(allocations.size() / 2) -(allocations.size() % 2), 0, 0, 0);
    }

    // Verify that all blocks are merged into a single large block
    verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0);


    for (int i = 0; i < 64; i++)
    {
        void* ptr = smalloc(128 * std::pow(2, 9) - 64);
        REQUIRE(ptr != nullptr);
        allocations.push_back(ptr);
        verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, allocations.size()%2, allocations.size(), 32-(int)(i/2)-1, 0, 0, 0);
    }
    REQUIRE(smalloc(40) == NULL);
    // Free the allocated blocks
    while (!allocations.empty())
    {
        void* ptr = allocations.front();
        allocations.erase(allocations.begin());
        sfree(ptr);
        verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, allocations.size() % 2, allocations.size(), 32 - (int)(allocations.size() / 2) -(allocations.size() % 2), 0, 0, 0);
    }
    verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0);
}



TEST_CASE("multiple big allocs test", "[malloc3]")
{
    // Allocate large block (order 10)
    std::vector<void*> allocations;
    int i=1;
    for (; i < 64; i++)
    {
        void* ptr = smalloc(MAX_ELEMENT_SIZE+100);
        REQUIRE(ptr != nullptr);
        allocations.push_back(ptr);
        verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32,0,i,i*(MAX_ELEMENT_SIZE+100));
    }
    i--;

    while (!allocations.empty())
    {
        void* ptr = allocations.back();
        allocations.pop_back();
        sfree(ptr);
        i--;
        verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32,0,i,i*(MAX_ELEMENT_SIZE+100));
    }

    // Verify that all blocks are merged into a single large block
    verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0);


    for (i = 1; i < 64; i++)
    {
        void* ptr = smalloc(MAX_ELEMENT_SIZE+100);
        REQUIRE(ptr != nullptr);
        allocations.push_back(ptr);
        verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32,0,i,i*(MAX_ELEMENT_SIZE+100));
    }
    i--;
    while (!allocations.empty())
    {
        void* ptr = allocations.front();
        allocations.erase(allocations.begin());
        sfree(ptr);
        i--;
        verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32,0,i,i*(MAX_ELEMENT_SIZE+100));
    }
    verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0);
}

TEST_CASE("Exit Test", "[malloc3]") {
    SECTION("Exit with Code 0xDEADBEEF") {
        int exitCode = 0xDEADBEEF & 0xFF;  // Keep only the lower 8 bits

        pid_t pid = fork();
        if (pid == 0) {  // Child process
            performCorruption();
            std::exit(0);  // Ensure child process terminates with the desired code
        } else {  // Parent process
            int status;
            waitpid(pid, &status, 0);
            REQUIRE(WIFEXITED(status));
            REQUIRE(WEXITSTATUS(status) == exitCode);
        }
    }
}


TEST_CASE("srealloc test", "[malloc3]")
{
    // Initial state
//    verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0);

    // Allocate a small block
    void* ptr1 = smalloc(40);
    REQUIRE(ptr1 != nullptr);
    verify_block_by_order(1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 31, 0, 0, 0);

    // Reallocate to a larger size
    void* ptr2 = srealloc(ptr1, 60);
    REQUIRE(ptr2 != nullptr);
    verify_block_by_order(1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 31, 0, 0, 0);

    // Reallocate to a smaller size
    void* ptr3 = srealloc(ptr2, 30);
    REQUIRE(ptr3 != nullptr);
    verify_block_by_order(1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 31, 0, 0, 0);

    // Free the block
    sfree(ptr3);
    verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0);
}

TEST_CASE("scalloc test", "[malloc3]")
{
    // Allocate and initialize memory with zeros
    void* ptr = scalloc(5, sizeof(int));
    REQUIRE(ptr != nullptr);

    // Verify that the memory is zero-initialized
    int* arr = static_cast<int*>(ptr);
    for (int i = 0; i < 5; i++) {
        REQUIRE(arr[i] == 0);
    }

    // Modify the memory
    for (int i = 0; i < 5; i++) {
        arr[i] = i + 1;
    }

    // Reallocate the memory with a larger size
    void* newPtr = scalloc(10, sizeof(int));
    REQUIRE(newPtr != nullptr);


    // Verify that the original values are preserved in the first 5 elements
    int* newArr = static_cast<int*>(newPtr);

    // Verify that the additional elements are zero-initialized
    for (int i = 0; i < 10; i++) {
        REQUIRE(newArr[i] == 0);
        newArr[i] = i + 1;
    }

    for (int i = 0; i < 10; i++) {
        REQUIRE(newArr[i] == i + 1);
    }

    // Free the memory
    sfree(ptr);
    sfree(newPtr);
}

TEST_CASE("srealloc merges test", "[malloc3]")
{
    // Initial state
//    verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0);

    // Allocate a small block
    void* ptr1 = smalloc(40);
    REQUIRE(ptr1 != nullptr);
    verify_block_by_order(1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 31, 0, 0, 0);

    // Reallocate to a larger size
    void* ptr2 = srealloc(ptr1, 128*pow(2,2) -64);
    REQUIRE(ptr2 != nullptr);
    verify_block_by_order(0,0,0,0,1,1,1,0,1,0,1,0,1,0,1,0,1,0,1,0,31,0,0,0);
    int* newArr = static_cast<int*>(ptr2);

    // Verify  elements are copied
    for (int i = 0; i < 10; i++) {
        newArr[i] = i + 1;
    }

    // Reallocate to a larger size
    void* ptr3 = srealloc(ptr2, 100);
    REQUIRE(ptr3 != nullptr);
    REQUIRE(ptr2 == ptr3);
    verify_block_by_order(0,0,0,0,1,1,1,0,1,0,1,0,1,0,1,0,1,0,1,0,31,0,0,0);


    void* ptr4 = srealloc(ptr3, 128*pow(2,8) -64);
    verify_block_by_order(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,0,31,0,0,0);
    int* newArr2 = static_cast<int*>(ptr4);
    for (int i = 0; i < 10; i++) {
        REQUIRE(newArr2[i] == i + 1);
    }
    sfree(ptr4);
    verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0);
}


TEST_CASE("weird values", "[malloc3]")
{
    // Initial state
//    verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0);
    void* ptr = smalloc(100000001);
    REQUIRE(ptr==NULL);
    verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0);
    sfree(ptr);
    verify_block_by_order(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0);
}
