#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <time.h>

#define KILO 1024
#define MAX_BLOCK_POWER 10                     // 2^10 = 1MB, sizes are powers of 2 multiplied by 128B
#define INIT_BLOCK_COUNT 32                    // 32 * 128KB = 4MB
#define MIN_BLOCK_SIZE 128                     // 128B
#define MAX_BLOCK_SIZE (MIN_BLOCK_SIZE * KILO) // 128KB * 1024 = 128MB

#define MAX_MALLOC_SIZE 100000000

struct MallocMetadataMetadata
{
    size_t num_free_blocks = 0;      // number of free blocks
    size_t num_free_bytes = 0;       // number of free bytes
    size_t num_allocated_blocks = 0; // number of allocated blocks (including free)
    size_t num_allocated_bytes = 0;  // number of allocated bytes (including free, excluding metadata)
    size_t num_meta_data_bytes = 0;  // number of bytes used for metadata
    size_t size_meta_data = 0;       // size of the metadata
};

struct MallocMetadata
{
    int cookie;           // cookie to check if the metadata is valid
    size_t size;          // actual size of the block (including the metadata struct)
    bool is_free;         // is the block free or not
    MallocMetadata *next; // pointer to the next block in the free list of the same size
    MallocMetadata *prev; // pointer to the previous block in the free list of the same size
};

MallocMetadataMetadata memory_global_metadata;

struct BuddyArray
{
    // array of free blocks by size - each index is a power of 2, including 0 (hence the +1)
    MallocMetadata *head_by_size[MAX_BLOCK_POWER + 1]{nullptr};
    void *start_address = nullptr;

    int cookie = 0x12345678;

    /// @brief get a block's buddy (the block it was split from)
    /// @param address the address of the block
    /// @return the buddy of the block
    MallocMetadata *getBuddy(MallocMetadata *block, size_t size = 0)
    {
        validateMetadata(block);
        if (size == 0)
            size = block->size;

        if (block == nullptr || block < start_address || block >= (MallocMetadata *)((char *)start_address + MAX_BLOCK_SIZE * INIT_BLOCK_COUNT))
        {
            return nullptr;
        }

        if (size >= MAX_BLOCK_SIZE)
        {
            return nullptr;
        }

        // assume address is aligned to the block size
        return validateMetadata((MallocMetadata *)((size_t)block ^ size));
    }

    /// @brief get the index of the block in the array
    /// @param size the size of the block (including the metadata struct size)
    /// @return the index of the block in the array
    int getIndex(size_t size)
    {
        int index = 0;
        while (size > MIN_BLOCK_SIZE)
        {
            size /= 2;
            index++;
        }

        return index;
    }

    /// @brief get the index of the first available block in the array that can fit the given size
    /// @param size the size of the block (including the metadata struct size)
    /// @return the index of the first available block in the array that can fit the given size
    int getAvailableIndex(size_t size)
    {
        int index = getIndex(size);

        for (int i = index; i < MAX_BLOCK_POWER + 1; i++)
        {
            if (head_by_size[i] != nullptr)
            {
                return i;
            }
        }

        return -1;
    }

    /// @brief remove the block from the free list
    /// @param block the block to remove, must be a free block in the free list
    void removeFreeBlock(MallocMetadata *block)
    {
        validateMetadata(block);
        int index = getIndex(block->size);
        if (index == -1)
        {
            return;
        }

        // if the block is the head of the list, update the head
        if (block->prev == nullptr)
        {
            head_by_size[index] = block->next;
        }
        // otherwise, update the previous block to point to the next block
        else
        {
            block->prev->next = block->next;
        }

        // if the block is not the tail of the list
        if (block->next != nullptr)
        {
            block->next->prev = block->prev;
        }

        block->next = nullptr;
        block->prev = nullptr;

        memory_global_metadata.num_free_blocks--;
        memory_global_metadata.num_free_bytes -= block->size - sizeof(MallocMetadata);
    }

    /// @brief insert the block to the free list
    /// @param block the block to insert, must be a free block
    void insertFreeBlock(MallocMetadata *block)
    {
        validateMetadata(block);
        int index = getIndex(block->size);
        if (index == -1)
        {
            return;
        }

        // find the right place to insert
        MallocMetadata *curr = head_by_size[index];
        MallocMetadata *prev = nullptr;
        while (curr != nullptr && curr < block)
        {
            validateMetadata(curr);
            prev = curr;
            curr = curr->next;
        }

        if (prev == nullptr)
        {
            head_by_size[index] = block;
            block->next = curr;
            block->prev = nullptr;
            if (curr != nullptr)
            {
                curr->prev = block;
            }
        }
        else
        {
            block->next = curr;
            prev->next = block;
            if (curr != nullptr)
            {
                curr->prev = block;
            }
            block->prev = prev;
        }

        memory_global_metadata.num_free_blocks++;
        memory_global_metadata.num_free_bytes += block->size - sizeof(MallocMetadata);
    }

    MallocMetadata *validateMetadata(MallocMetadata *metadata)
    {
        // check cookie
        if (metadata->cookie != cookie)
        {
            exit(0xdeadbeef);
        }

        return metadata;
    }

    void splitAndFree(MallocMetadata *curr, size_t size)
    {
        validateMetadata(curr);
        if (curr->size / 2 < size || curr->size / 2 < MIN_BLOCK_SIZE)
        {
            return;
        }

        // split
        MallocMetadata *buddy = (MallocMetadata *)((char *)curr + curr->size / 2);

        buddy->size = curr->size / 2;
        buddy->is_free = true;
        buddy->next = nullptr;
        buddy->prev = nullptr;
        buddy->cookie = cookie;

        curr->size /= 2;

        // add to free list
        insertFreeBlock(buddy);

        memory_global_metadata.num_allocated_blocks++;
        memory_global_metadata.num_allocated_bytes -= sizeof(MallocMetadata);
        memory_global_metadata.num_meta_data_bytes += sizeof(MallocMetadata);
        splitAndFree(curr, size);
    }

    MallocMetadata *mergeFree(MallocMetadata *curr)
    {
        validateMetadata(curr);
        if (curr->size >= MAX_BLOCK_SIZE)
        {
            return curr;
        }

        MallocMetadata *buddy = getBuddy(curr);
        if (buddy == nullptr)
        {
            return curr;
        }

        if (buddy->is_free)
        {
            // remove from free list
            removeFreeBlock(buddy);
            removeFreeBlock(curr);

            // merge
            MallocMetadata *merged = curr < buddy ? curr : buddy;
            merged->size *= 2;
            merged->is_free = true;
            merged->next = nullptr;
            merged->prev = nullptr;

            // add to free list
            insertFreeBlock(merged);

            memory_global_metadata.num_allocated_blocks--;
            memory_global_metadata.num_allocated_bytes += sizeof(MallocMetadata);
            memory_global_metadata.num_meta_data_bytes -= sizeof(MallocMetadata);

            return mergeFree(merged);
        }

        return curr;
    }

    /// @brief only merge if all the required buddies are free for the given size
    /// @param block the block to merge
    /// @param desired_size the desired size of the block after the merge
    /// @return
    MallocMetadata *tryMerge(MallocMetadata *block, size_t desired_size)
    {
        validateMetadata(block);
        if (block->size >= MAX_BLOCK_SIZE || desired_size > MAX_BLOCK_SIZE)
        {
            return nullptr;
        }

        MallocMetadata *nextBuddy = block;
        // check if all required buddies are free
        for (int i = getIndex(block->size); i < getIndex(desired_size); i++)
        {
            MallocMetadata *buddy = getBuddy(nextBuddy, MIN_BLOCK_SIZE * (1 << i));
            if (buddy == nullptr || !buddy->is_free)
            {
                return nullptr;
            }

            nextBuddy = buddy < nextBuddy ? buddy : nextBuddy;
        }

        // we can merge all the blocks
        insertFreeBlock(block);
        return mergeFree(block);
    }
};

BuddyArray buddy_array;

void initialAlloc()
{
    // check alignment
    // size_t alignment = 32 * 128 * 1024 - ((size_t)sbrk(0) & 32 * 128 * 1024);
    // buddy_array.start_address = (char *)sbrk(MAX_BLOCK_SIZE * INIT_BLOCK_COUNT + alignment) + alignment;

    long alignment_mask = MAX_BLOCK_SIZE - 1;
    long current_address = (long)sbrk(0);
    long misalignment = current_address & alignment_mask;

    // If misaligned, calculate the adjustment to the next block, otherwise 0.
    long adjustment = misalignment ? MAX_BLOCK_SIZE - misalignment : 0;

    // Allocate the 32 blocks of 128 KB each, plus any necessary alignment.
    buddy_array.start_address = (char *)sbrk(MAX_BLOCK_SIZE * INIT_BLOCK_COUNT + adjustment) + adjustment;

    buddy_array.head_by_size[MAX_BLOCK_POWER] = (MallocMetadata *)buddy_array.start_address;

    buddy_array.cookie = rand();

    // init metadata
    void *curBlock = buddy_array.start_address;
    for (int i = 0; i < INIT_BLOCK_COUNT; i++)
    {
        MallocMetadata *metadata = (MallocMetadata *)curBlock;
        metadata->size = MAX_BLOCK_SIZE;
        metadata->is_free = true;

        // last block has no next
        metadata->next = i != INIT_BLOCK_COUNT - 1 ? (MallocMetadata *)((char *)curBlock + MAX_BLOCK_SIZE) : nullptr;

        // first block has no prev
        metadata->prev = i != 0 ? (MallocMetadata *)((char *)curBlock - MAX_BLOCK_SIZE) : nullptr;

        metadata->cookie = buddy_array.cookie;
        curBlock = metadata->next;
    }

    memory_global_metadata.num_allocated_blocks = INIT_BLOCK_COUNT;
    memory_global_metadata.num_allocated_bytes = (MAX_BLOCK_SIZE - sizeof(MallocMetadata)) * INIT_BLOCK_COUNT;
    memory_global_metadata.num_free_blocks = INIT_BLOCK_COUNT;
    memory_global_metadata.num_free_bytes = memory_global_metadata.num_allocated_bytes;
    memory_global_metadata.num_meta_data_bytes = INIT_BLOCK_COUNT * sizeof(MallocMetadata);
    memory_global_metadata.size_meta_data = sizeof(MallocMetadata);
}

/// @brief allocate memory using mmap, size should include metadata
/// @param size the size of the allocation including metadata
/// @return pointer to the allocated memory, not including metadata (user pointer)
void *mmap_smalloc(size_t size)
{
    // allocate with mmap
    void *ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED)
    {
        return nullptr;
    }

    MallocMetadata *metadata = (MallocMetadata *)ptr;
    metadata->size = size;
    metadata->is_free = false;
    metadata->cookie = buddy_array.cookie;
    metadata->next = nullptr;
    metadata->prev = nullptr;

    memory_global_metadata.num_allocated_blocks++;
    memory_global_metadata.num_meta_data_bytes += sizeof(MallocMetadata);
    memory_global_metadata.num_allocated_bytes += size - sizeof(MallocMetadata);

    return (void *)(metadata + 1);
}

void *smalloc(size_t user_size)
{

    // no allocations yet, allocate first block with requested size
    if (buddy_array.start_address == nullptr)
    {
        initialAlloc();
    }

    if (user_size == 0 || user_size > MAX_MALLOC_SIZE)
    {
        return nullptr;
    }
    // search for free block with at least size bytes

    size_t size = user_size + sizeof(MallocMetadata);

    if (size > MAX_BLOCK_SIZE)
    {
        return mmap_smalloc(size);
    }

    int index = buddy_array.getAvailableIndex(size);
    if (index == -1)
    {
        return nullptr;
    }

    MallocMetadata *curr = buddy_array.head_by_size[index];

    if (curr->is_free && curr->size >= size)
    {
        curr->is_free = false;

        buddy_array.removeFreeBlock(curr);
        buddy_array.splitAndFree(curr, size);
        return (void *)(curr + 1);
    }

    // no free block big enough was found, return nullptr
    return nullptr;
}

/// @brief allocate a block of memory with size * num bytes and initialize all bytes to 0
/// @param num the number of elements
/// @param size the size of each element
/// @return pointer to the allocated memory
void *scalloc(size_t num, size_t size)
{
    void *ptr = smalloc(num * size);
    if (ptr == nullptr)
    {
        return nullptr;
    }

    for (size_t i = 0; i < num * size; i++)
    {
        ((char *)ptr)[i] = 0;
    }

    return ptr;
}

void sfree(void *p)
{
    if (p == nullptr)
    {
        return;
    }

    MallocMetadata *metadata = buddy_array.validateMetadata((MallocMetadata *)p - 1);

    if (metadata->size > MAX_BLOCK_SIZE)
    {
        // free with munmap
        memory_global_metadata.num_allocated_blocks--;
        memory_global_metadata.num_allocated_bytes -= metadata->size - sizeof(MallocMetadata);
        memory_global_metadata.num_meta_data_bytes -= sizeof(MallocMetadata);
        munmap(metadata, metadata->size);
        return;
    }

    metadata->is_free = true;

    // add to free list sorted by address
    buddy_array.insertFreeBlock(metadata);
    buddy_array.mergeFree(metadata);
}

void *srealloc(void *oldp, size_t user_size)
{
    if (user_size == 0)
    {
        return nullptr;
    }

    if (oldp == nullptr)
    {
        return smalloc(user_size);
    }

    MallocMetadata *metadata = buddy_array.validateMetadata((MallocMetadata *)oldp - 1);

    // if the old block is big enough, return it
    if (metadata->size >= user_size + sizeof(MallocMetadata))
    {
        return oldp;
    }

    // if mmap block, allocate new block and copy data
    if (metadata->size > MAX_BLOCK_SIZE)
    {
        void *newp = mmap_smalloc(user_size + sizeof(MallocMetadata));
        if (newp == nullptr)
        {
            return nullptr;
        }

        for (size_t i = 0; i < metadata->size - sizeof(MallocMetadata); i++)
        {
            ((char *)newp)[i] = ((char *)oldp)[i];
        }

        sfree(oldp);
        return newp;
    }

    // if we can merge enough buddies to get a block big enough, merge and return
    MallocMetadata *merged = buddy_array.tryMerge(metadata, user_size + sizeof(MallocMetadata));
    if (merged != nullptr)
    {
        merged->is_free = false;
        buddy_array.removeFreeBlock(merged);
        buddy_array.splitAndFree(merged, user_size + sizeof(MallocMetadata));
        return (void *)(merged + 1);
    }

    // otherwise, allocate a new block and copy the data
    void *newp = smalloc(user_size);
    if (newp == nullptr)
    {
        return nullptr;
    }

    for (size_t i = 0; i < metadata->size - sizeof(MallocMetadata); i++)
    {
        ((char *)newp)[i] = ((char *)oldp)[i];
    }

    sfree(oldp);
    return newp;
}

/*
    5. size_t _num_free_blocks():
        ●   Returns the number of allocated blocks in the heap that are currently free.
    6. size_t _num_free_bytes():
        ●   Returns the number of bytes in all allocated blocks in the heap that are currently free,
            excluding the bytes used by the meta-data structs.
    7. size_t _num_allocated_blocks():
        ●   Returns the overall (free and used) number of allocated blocks in the heap.
    8. size_t _num_allocated_bytes():
        ● Returns the overall number (free and used) of allocated bytes in the heap, excluding
    the bytes used by the meta-data structs.
    9. size_t _num_meta_data_bytes();
    ● Returns the overall number of meta-data bytes currently in the heap.
    10. size_t _size_meta_data():
    ● Returns the number of bytes of a single meta-data structure in your system.
*/

size_t _num_free_blocks()
{
    return memory_global_metadata.num_free_blocks;
}

size_t _num_free_bytes()
{
    return memory_global_metadata.num_free_bytes;
}

size_t _num_allocated_blocks()
{
    return memory_global_metadata.num_allocated_blocks;
}

size_t _num_allocated_bytes()
{
    return memory_global_metadata.num_allocated_bytes;
}

size_t _num_meta_data_bytes()
{
    return memory_global_metadata.num_meta_data_bytes;
}

size_t _size_meta_data()
{
    return memory_global_metadata.size_meta_data;
}
