#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>

#define MAX_BLOCK_POWER 10
#define INIT_BLOCK_COUNT 32
#define MIN_BLOCK_SIZE 128
#define MAX_BLOCK_SIZE (MIN_BLOCK_SIZE * KILO)
#define KILO 1024

#define MAX_MALLOC_SIZE 100000000

struct MallocMetadataMetadata
{
    size_t num_free_blocks = 0;
    size_t num_free_bytes = 0;
    size_t num_allocated_blocks = 0;
    size_t num_allocated_bytes = 0;
    size_t num_meta_data_bytes = 0;
    size_t size_meta_data = 0;
};

struct MallocMetadata
{
    int cookie;
    size_t size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;
};

MallocMetadataMetadata memory_global_metadata;

struct BuddyArray
{
    MallocMetadata *head_by_size[MAX_BLOCK_POWER + 1]{nullptr};
    void *start_address = nullptr;

    int cookie = 0x12345678;

    MallocMetadata *getBuddy(MallocMetadata *address)
    {
        if (address == NULL || address < start_address || address >= (MallocMetadata *)((char *)start_address + MAX_BLOCK_SIZE * INIT_BLOCK_COUNT))
        {
            return NULL;
        }

        if (address->size >= MAX_BLOCK_SIZE)
        {
            return NULL;
        }

        return validateMetadata((MallocMetadata *)((size_t)address ^ getIndex(address->size)));
    }

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

    int getAvailableIndex(size_t size)
    {
        int index = getIndex(size);

        for (int i = index; i < MAX_BLOCK_POWER + 1; i++)
        {
            if (head_by_size[i] != NULL)
            {
                return i;
            }
        }

        return -1;
    }

    void removeFreeBlock(MallocMetadata *block)
    {
        validateMetadata(block);
        int index = getIndex(block->size);
        if (index == -1)
        {
            return;
        }

        if (block->prev == NULL)
        {
            head_by_size[index] = block->next;
        }
        else
        {
            block->prev->next = block->next;
        }

        if (block->next != NULL)
        {
            block->next->prev = block->prev;
        }

        block->next = NULL;
        block->prev = NULL;

        memory_global_metadata.num_free_blocks--;
        memory_global_metadata.num_free_bytes -= block->size + sizeof(MallocMetadata);
    }

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
        MallocMetadata *prev = NULL;
        while (curr != NULL && curr < block)
        {
            prev = curr;
            curr = validateMetadata(curr->next);
        }

        if (prev == NULL)
        {
            head_by_size[index] = block;
        }
        else
        {
            block->next = curr;
            prev->next = block;
            curr->prev = block;
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
};

BuddyArray buddy_array;

void initialAlloc()
{
    // check alignment
    size_t alignment = ~((size_t)sbrk(0) & 128 * 1024);
    buddy_array.start_address = (char *)sbrk(MAX_BLOCK_SIZE * INIT_BLOCK_COUNT + alignment) + alignment;
    buddy_array.head_by_size[MAX_BLOCK_POWER] = (MallocMetadata *)buddy_array.start_address;

    buddy_array.cookie = 0x1337; // todo: randomize

    void *curBlock = buddy_array.start_address;
    for (int i = 0; i < INIT_BLOCK_COUNT - 1; i++)
    {
        MallocMetadata *metadata = (MallocMetadata *)curBlock;
        metadata->size = MAX_BLOCK_SIZE;
        metadata->is_free = true;
        metadata->next = (MallocMetadata *)((char *)curBlock + MAX_BLOCK_SIZE);
        metadata->prev = NULL;
        metadata->cookie = buddy_array.cookie;
        curBlock = metadata->next;
    }

    // set prev
    for (int i = 0; i < INIT_BLOCK_COUNT - 1; i++)
    {
        MallocMetadata *metadata = (MallocMetadata *)curBlock;
        metadata->prev = (MallocMetadata *)((char *)curBlock - MAX_BLOCK_SIZE);
        curBlock = metadata->prev;
    }

    memory_global_metadata.num_allocated_blocks = INIT_BLOCK_COUNT;
    memory_global_metadata.num_allocated_bytes = (MAX_BLOCK_SIZE - sizeof(MallocMetadata)) * INIT_BLOCK_COUNT;
    memory_global_metadata.num_free_blocks = INIT_BLOCK_COUNT;
    memory_global_metadata.num_free_bytes = memory_global_metadata.num_allocated_bytes;
    memory_global_metadata.num_meta_data_bytes = INIT_BLOCK_COUNT * sizeof(MallocMetadata);
    memory_global_metadata.size_meta_data = sizeof(MallocMetadata);
}

void splitAndFree(MallocMetadata *curr, size_t size)
{
    buddy_array.validateMetadata(curr);
    if (curr->size / 2 < size || curr->size / 2 < MIN_BLOCK_SIZE)
    {
        return;
    }

    // split
    MallocMetadata *buddy = (MallocMetadata *)((char *)curr + curr->size / 2);

    buddy->size = curr->size / 2;
    buddy->is_free = true;
    buddy->next = NULL;
    buddy->prev = NULL;
    buddy->cookie = buddy_array.cookie;

    curr->size /= 2;

    // add to free list
    buddy_array.insertFreeBlock(buddy);

    memory_global_metadata.num_allocated_blocks++;
    memory_global_metadata.num_meta_data_bytes += sizeof(MallocMetadata);
    splitAndFree(buddy, size);
}

void mergeFree(MallocMetadata *curr)
{
    buddy_array.validateMetadata(curr);
    if (curr->size >= MAX_BLOCK_SIZE)
    {
        return;
    }

    MallocMetadata *buddy = buddy_array.getBuddy(curr);
    if (buddy == NULL)
    {
        return;
    }

    if (buddy->is_free)
    {
        // remove from free list
        buddy_array.removeFreeBlock(buddy);
        buddy_array.removeFreeBlock(curr);

        // merge
        MallocMetadata *merged = curr < buddy ? curr : buddy;
        merged->size *= 2;
        merged->is_free = true;
        merged->next = NULL;
        merged->prev = NULL;

        // add to free list
        buddy_array.insertFreeBlock(merged);

        memory_global_metadata.num_allocated_blocks--;
        memory_global_metadata.num_meta_data_bytes -= sizeof(MallocMetadata);

        mergeFree(merged);
    }
}

void *smalloc(size_t size)
{

    // no allocations yet, allocate first block with requested size
    if (buddy_array.start_address == nullptr)
    {
        initialAlloc();
    }

    if (size == 0 || size > MAX_MALLOC_SIZE)
    {
        return NULL;
    }
    // search for free block with at least size bytes

    size = size + sizeof(MallocMetadata);

    if (size > MAX_BLOCK_SIZE)
    {
        // allocate with mmap
        void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED)
        {
            return nullptr;
        }

        MallocMetadata *metadata = (MallocMetadata *)ptr;
        metadata->size = size;
        metadata->is_free = false;
        metadata->next = nullptr;
        metadata->prev = nullptr;

        memory_global_metadata.num_allocated_blocks++;
        memory_global_metadata.num_meta_data_bytes += sizeof(MallocMetadata);
        memory_global_metadata.num_allocated_bytes += size - sizeof(MallocMetadata);

        return (void *)(metadata + 1);
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
        splitAndFree(curr, size);
        return (void *)(curr + 1);
    }

    // no free block big enough was found, return null
    return NULL;
}

void *scalloc(size_t num, size_t size)
{
    void *ptr = smalloc(num * size);
    if (ptr == NULL)
    {
        return NULL;
    }

    for (size_t i = 0; i < num * size; i++)
    {
        ((char *)ptr)[i] = 0;
    }

    return ptr;
}

void sfree(void *p)
{
    if (p == NULL)
    {
        return;
    }

    MallocMetadata *metadata = buddy_array.validateMetadata((MallocMetadata *)p - 1);

    if (metadata->size >= MAX_BLOCK_SIZE)
    {
        // free with munmap
        munmap(metadata, metadata->size);
        memory_global_metadata.num_allocated_blocks--;
        memory_global_metadata.num_allocated_bytes -=  metadata->size + sizeof(MallocMetadata);
        memory_global_metadata.num_meta_data_bytes -= sizeof(MallocMetadata);
        return;
    }

    metadata->is_free = true;

    // add to free list sorted by address
    buddy_array.insertFreeBlock(metadata);
    mergeFree(metadata);
}

void *srealloc(void *oldp, size_t size)
{
    if (size == 0)
    {
        return NULL;
    }

    if (oldp == NULL)
    {
        return smalloc(size);
    }

    MallocMetadata *metadata = buddy_array.validateMetadata((MallocMetadata *)oldp - 1);
    if (metadata->size  >= size + sizeof(MallocMetadata))
    {
        return oldp;
    }

    void *newp = smalloc(size);
    if (newp == NULL)
    {
        return NULL;
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
