#include <unistd.h>

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
    size_t size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;
};

#define MAX_MALLOC_SIZE 100000000

MallocMetadata *head = nullptr;
MallocMetadataMetadata memory_global_metadata;

void *allocateWithMetadata(size_t size, MallocMetadata *prev = nullptr)
{
    MallocMetadata *metadata = (MallocMetadata *)sbrk(size + sizeof(MallocMetadata));
    if (metadata == nullptr)
    {
        return nullptr;
    }
    metadata->size = size;
    metadata->is_free = false;
    metadata->next = nullptr;
    metadata->prev = prev;
    if (prev != nullptr)
        prev->next = metadata;
    memory_global_metadata.num_allocated_blocks++;
    memory_global_metadata.num_allocated_bytes += size;
    memory_global_metadata.num_meta_data_bytes += sizeof(MallocMetadata);
    memory_global_metadata.size_meta_data = sizeof(MallocMetadata);

    return (void *)(metadata + 1);
}

void *smalloc(size_t size)
{
    if (size == 0 || size > MAX_MALLOC_SIZE)
    {
        return nullptr;
    }

    // no allocations yet, allocate first block with requested size
    if (head == nullptr)
    {
        void *ptr = allocateWithMetadata(size);
        head = (MallocMetadata *)ptr - 1;
        return ptr;
    }

    // search for free block with at least size bytes
    MallocMetadata *curr = head;
    MallocMetadata *prev = nullptr;
    while (curr != nullptr)
    {
        if (curr->is_free && curr->size >= size)
        {
            curr->is_free = false;
            memory_global_metadata.num_free_blocks--;
            memory_global_metadata.num_free_bytes -= curr->size;

            return (void *)(curr + 1);
        }
        prev = curr;
        curr = curr->next;
    }

    // no free block big enough was found, allocate new block with requested size
    return allocateWithMetadata(size, prev);
}

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

    MallocMetadata *metadata = (MallocMetadata *)p - 1;
    metadata->is_free = true;

    memory_global_metadata.num_free_blocks++;
    memory_global_metadata.num_free_bytes += metadata->size;
}

void *srealloc(void *oldp, size_t size)
{
    if (size == 0 || size > MAX_MALLOC_SIZE)
    {
        return nullptr;
    }

    if (oldp == nullptr)
    {
        return smalloc(size);
    }

    MallocMetadata *metadata = (MallocMetadata *)oldp - 1;
    if (metadata->size >= size)
    {
        return oldp;
    }

    void *newp = smalloc(size);
    if (newp == nullptr)
    {
        return nullptr;
    }

    for (size_t i = 0; i < metadata->size; i++)
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