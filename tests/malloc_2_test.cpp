#include "my_stdlib.h"
#include <catch2/catch_test_macros.hpp>

#include <unistd.h>

#define MAX_ALLOCATION_SIZE (1e8)

#define verify_blocks(allocated_blocks, allocated_bytes, free_blocks, free_bytes)                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        REQUIRE(_num_allocated_blocks() == allocated_blocks);                                                          \
        REQUIRE(_num_allocated_bytes() == allocated_bytes);                                                            \
        REQUIRE(_num_free_blocks() == free_blocks);                                                                    \
        REQUIRE(_num_free_bytes() == free_bytes);                                                                      \
        REQUIRE(_num_meta_data_bytes() == _size_meta_data() * allocated_blocks);                                       \
    } while (0)

#define verify_size(base)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        void *after = sbrk(0);                                                                                         \
        REQUIRE(_num_allocated_bytes() + _size_meta_data() * _num_allocated_blocks() == (size_t)after - (size_t)base); \
    } while (0)

TEST_CASE("Sanity", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);
    void *base = sbrk(0);
    char *a = (char *)smalloc(10);
    REQUIRE(a != nullptr);
    REQUIRE((size_t)base + _size_meta_data() == (size_t)a);
    verify_blocks(1, 10, 0, 0);
    verify_size(base);
    sfree(a);
    verify_blocks(1, 10, 1, 10);
    verify_size(base);
}

TEST_CASE("Check size", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    char *a = (char *)smalloc(1);
    REQUIRE(a != nullptr);
    void *after = sbrk(0);
    REQUIRE(1 + _size_meta_data() == (size_t)after - (size_t)base);

    verify_blocks(1, 1, 0, 0);
    verify_size(base);

    char *b = (char *)smalloc(10);
    REQUIRE(b != nullptr);
    after = sbrk(0);
    REQUIRE(11 + _size_meta_data() * 2 == (size_t)after - (size_t)base);

    verify_blocks(2, 11, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(2, 11, 1, 1);
    verify_size(base);
    sfree(b);
    verify_blocks(2, 11, 2, 11);
    verify_size(base);
}

TEST_CASE("0 size", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);
    void *base = sbrk(0);
    char *a = (char *)smalloc(0);
    REQUIRE(a == nullptr);
    void *after = sbrk(0);
    REQUIRE(after == base);
    verify_blocks(0, 0, 0, 0);
    verify_size(base);
}

TEST_CASE("Max size", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);
    void *base = sbrk(0);
    char *a = (char *)smalloc(MAX_ALLOCATION_SIZE);
    REQUIRE(a != nullptr);
    void *after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE + _size_meta_data() == (size_t)after - (size_t)base);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 0, 0);
    verify_size(base);

    char *b = (char *)smalloc(MAX_ALLOCATION_SIZE + 1);
    REQUIRE(b == nullptr);
    after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE + _size_meta_data() == (size_t)after - (size_t)base);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 1, MAX_ALLOCATION_SIZE);
    verify_size(base);
}

TEST_CASE("free", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    char *a = (char *)smalloc(10);
    REQUIRE(a != nullptr);
    char *b = (char *)smalloc(10);
    REQUIRE(b != nullptr);
    char *c = (char *)smalloc(10);
    REQUIRE(c != nullptr);

    verify_blocks(3, 30, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(3, 30, 1, 10);
    verify_size(base);
    sfree(b);
    verify_blocks(3, 30, 2, 20);
    verify_size(base);
    sfree(c);
    verify_blocks(3, 30, 3, 30);
    verify_size(base);

    char *new_a = (char *)smalloc(10);
    REQUIRE(a == new_a);
    char *new_b = (char *)smalloc(10);
    REQUIRE(b == new_b);
    char *new_c = (char *)smalloc(10);
    REQUIRE(c == new_c);

    verify_blocks(3, 30, 0, 0);
    verify_size(base);

    sfree(new_a);
    verify_blocks(3, 30, 1, 10);
    verify_size(base);
    sfree(new_b);
    verify_blocks(3, 30, 2, 20);
    verify_size(base);
    sfree(new_c);
    verify_blocks(3, 30, 3, 30);
    verify_size(base);
}

TEST_CASE("free 2", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    char *a = (char *)smalloc(10);
    REQUIRE(a != nullptr);
    char *b = (char *)smalloc(10);
    REQUIRE(b != nullptr);
    char *c = (char *)smalloc(10);
    REQUIRE(c != nullptr);

    verify_blocks(3, 30, 0, 0);
    verify_size(base);

    sfree(b);
    verify_blocks(3, 30, 1, 10);
    verify_size(base);
    sfree(a);
    verify_blocks(3, 30, 2, 20);
    verify_size(base);
    sfree(c);
    verify_blocks(3, 30, 3, 30);
    verify_size(base);

    char *new_a = (char *)smalloc(10);
    REQUIRE(a == new_a);
    char *new_b = (char *)smalloc(10);
    REQUIRE(b == new_b);
    char *new_c = (char *)smalloc(10);
    REQUIRE(c == new_c);

    verify_blocks(3, 30, 0, 0);
    verify_size(base);

    sfree(new_a);
    verify_blocks(3, 30, 1, 10);
    verify_size(base);
    sfree(new_b);
    verify_blocks(3, 30, 2, 20);
    verify_size(base);
    sfree(new_c);
    verify_blocks(3, 30, 3, 30);
    verify_size(base);
}

TEST_CASE("free 3", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    char *a = (char *)smalloc(10);
    REQUIRE(a != nullptr);
    char *b = (char *)smalloc(10);
    REQUIRE(b != nullptr);
    char *c = (char *)smalloc(10);
    REQUIRE(c != nullptr);

    verify_blocks(3, 30, 0, 0);
    verify_size(base);

    sfree(c);
    verify_blocks(3, 30, 1, 10);
    verify_size(base);
    sfree(a);
    verify_blocks(3, 30, 2, 20);
    verify_size(base);
    sfree(b);
    verify_blocks(3, 30, 3, 30);
    verify_size(base);

    char *new_a = (char *)smalloc(10);
    REQUIRE(a == new_a);
    char *new_b = (char *)smalloc(10);
    REQUIRE(b == new_b);
    char *new_c = (char *)smalloc(10);
    REQUIRE(c == new_c);

    verify_blocks(3, 30, 0, 0);
    verify_size(base);

    sfree(new_a);
    verify_blocks(3, 30, 1, 10);
    verify_size(base);
    sfree(new_b);
    verify_blocks(3, 30, 2, 20);
    verify_size(base);
    sfree(new_c);
    verify_blocks(3, 30, 3, 30);
    verify_size(base);
}

TEST_CASE("Reuse", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    char *a = (char *)smalloc(10);
    REQUIRE(a != nullptr);

    verify_blocks(1, 10, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(1, 10, 1, 10);
    verify_size(base);

    char *b = (char *)smalloc(10);
    REQUIRE(b != nullptr);
    REQUIRE(b == a);

    verify_blocks(1, 10, 0, 0);
    verify_size(base);

    sfree(b);
    verify_blocks(1, 10, 1, 10);
    verify_size(base);
}

TEST_CASE("Reuse two blocks", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    char *a = (char *)smalloc(10);
    REQUIRE(a != nullptr);

    verify_blocks(1, 10, 0, 0);
    verify_size(base);

    char *b = (char *)smalloc(10);
    REQUIRE(b != nullptr);
    REQUIRE(b != a);

    verify_blocks(2, 20, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(2, 20, 1, 10);
    verify_size(base);

    char *c = (char *)smalloc(10);
    REQUIRE(c != nullptr);
    REQUIRE(c == a);

    verify_blocks(2, 20, 0, 0);
    verify_size(base);

    sfree(b);
    verify_blocks(2, 20, 1, 10);
    verify_size(base);
    sfree(c);
    verify_blocks(2, 20, 2, 20);
    verify_size(base);
}

TEST_CASE("Reuse two blocks reverse", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    char *a = (char *)smalloc(10);
    REQUIRE(a != nullptr);

    verify_blocks(1, 10, 0, 0);
    verify_size(base);

    char *b = (char *)smalloc(10);
    REQUIRE(b != nullptr);
    REQUIRE(b != a);

    verify_blocks(2, 20, 0, 0);
    verify_size(base);

    sfree(b);
    verify_blocks(2, 20, 1, 10);
    verify_size(base);

    char *c = (char *)smalloc(10);
    REQUIRE(c != nullptr);
    REQUIRE(c == b);

    verify_blocks(2, 20, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(2, 20, 1, 10);
    verify_size(base);
    sfree(c);
    verify_blocks(2, 20, 2, 20);
    verify_size(base);
}

TEST_CASE("Reuse two blocks both", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    char *a = (char *)smalloc(10);
    REQUIRE(a != nullptr);

    verify_blocks(1, 10, 0, 0);
    verify_size(base);

    char *b = (char *)smalloc(10);
    REQUIRE(b != nullptr);
    REQUIRE(b != a);

    verify_blocks(2, 20, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(2, 20, 1, 10);
    verify_size(base);
    sfree(b);
    verify_blocks(2, 20, 2, 20);
    verify_size(base);

    char *c = (char *)smalloc(10);
    REQUIRE(c != nullptr);
    REQUIRE(c == a);

    verify_blocks(2, 20, 1, 10);
    verify_size(base);

    sfree(c);
    verify_blocks(2, 20, 2, 20);
    verify_size(base);
}

TEST_CASE("Reuse two blocks sizes small", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    char *a = (char *)smalloc(10);
    REQUIRE(a != nullptr);

    verify_blocks(1, 10, 0, 0);
    verify_size(base);

    char *b = (char *)smalloc(100);
    REQUIRE(b != nullptr);
    REQUIRE(b != a);

    verify_blocks(2, 110, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(2, 110, 1, 10);
    verify_size(base);
    sfree(b);
    verify_blocks(2, 110, 2, 110);
    verify_size(base);

    char *c = (char *)smalloc(10);
    REQUIRE(c != nullptr);
    REQUIRE(c == a);

    verify_blocks(2, 110, 1, 100);
    verify_size(base);

    sfree(c);
    verify_blocks(2, 110, 2, 110);
    verify_size(base);
}

TEST_CASE("Reuse two blocks sizes large", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    char *a = (char *)smalloc(10);
    REQUIRE(a != nullptr);

    verify_blocks(1, 10, 0, 0);
    verify_size(base);

    char *b = (char *)smalloc(100);
    REQUIRE(b != nullptr);
    REQUIRE(b != a);

    verify_blocks(2, 110, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(2, 110, 1, 10);
    verify_size(base);
    sfree(b);
    verify_blocks(2, 110, 2, 110);
    verify_size(base);

    char *c = (char *)smalloc(100);
    REQUIRE(c != nullptr);
    REQUIRE(c == b);

    verify_blocks(2, 110, 1, 10);
    verify_size(base);

    sfree(c);
    verify_blocks(2, 110, 2, 110);
    verify_size(base);
}

TEST_CASE("scalloc", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    char *a = (char *)scalloc(10, 1);
    REQUIRE(a != nullptr);
    for (size_t i = 0; i < 10; i++)
    {
        REQUIRE(a[i] == 0);
    }

    verify_blocks(1, 10, 0, 0);
    verify_size(base);

    int *b = (int *)scalloc(100, sizeof(int));
    REQUIRE(b != nullptr);
    for (size_t i = 0; i < 10; i++)
    {
        REQUIRE(b[i] == 0);
    }

    verify_blocks(2, sizeof(int) * 100 + 10, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(2, sizeof(int) * 100 + 10, 1, 10);
    verify_size(base);
    sfree(b);
    verify_blocks(2, sizeof(int) * 100 + 10, 2, sizeof(int) * 100 + 10);
    verify_size(base);
}

TEST_CASE("scalloc taint", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    int *a = (int *)scalloc(100, sizeof(int));
    REQUIRE(a != nullptr);
    for (size_t i = 0; i < 100; i++)
    {
        REQUIRE(a[i] == 0);
    }

    verify_blocks(1, sizeof(int) * 100, 0, 0);
    verify_size(base);

    for (size_t i = 0; i < 100; i++)
    {
        a[i] = i;
    }

    sfree(a);
    verify_blocks(1, sizeof(int) * 100, 1, sizeof(int) * 100);
    verify_size(base);

    int *b = (int *)scalloc(100, sizeof(int));
    REQUIRE(b != nullptr);
    REQUIRE(a == b);
    for (size_t i = 0; i < 100; i++)
    {
        REQUIRE(b[i] == 0);
    }

    verify_blocks(1, sizeof(int) * 100, 0, 0);
    verify_size(base);

    sfree(b);
    verify_blocks(1, sizeof(int) * 100, 1, sizeof(int) * 100);
    verify_size(base);
}

TEST_CASE("scalloc 0 size", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);
    void *base = sbrk(0);
    char *a = (char *)scalloc(0, 10);
    REQUIRE(a == nullptr);
    void *after = sbrk(0);
    REQUIRE(after == base);
    verify_blocks(0, 0, 0, 0);
    verify_size(base);
    a = (char *)scalloc(10, 0);
    REQUIRE(a == nullptr);
    after = sbrk(0);
    REQUIRE(after == base);
    verify_blocks(0, 0, 0, 0);
    verify_size(base);
}

TEST_CASE("scalloc Max size num", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);
    void *base = sbrk(0);
    char *a = (char *)scalloc(MAX_ALLOCATION_SIZE, 1);
    REQUIRE(a != nullptr);
    void *after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE + _size_meta_data() == (size_t)after - (size_t)base);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 0, 0);
    verify_size(base);

    char *b = (char *)scalloc(MAX_ALLOCATION_SIZE + 1, 1);
    REQUIRE(b == nullptr);
    after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE + _size_meta_data() == (size_t)after - (size_t)base);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 1, MAX_ALLOCATION_SIZE);
    verify_size(base);
}

TEST_CASE("scalloc Max size size", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);
    void *base = sbrk(0);
    char *a = (char *)scalloc(1, MAX_ALLOCATION_SIZE);
    REQUIRE(a != nullptr);
    void *after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE + _size_meta_data() == (size_t)after - (size_t)base);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 0, 0);
    verify_size(base);

    char *b = (char *)scalloc(1, MAX_ALLOCATION_SIZE + 1);
    REQUIRE(b == nullptr);
    after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE + _size_meta_data() == (size_t)after - (size_t)base);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 1, MAX_ALLOCATION_SIZE);
    verify_size(base);
}

TEST_CASE("scalloc Max size both", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);
    void *base = sbrk(0);
    char *a = (char *)scalloc(MAX_ALLOCATION_SIZE / 8, 8);
    REQUIRE(a != nullptr);
    void *after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE + _size_meta_data() == (size_t)after - (size_t)base);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 0, 0);
    verify_size(base);

    char *b = (char *)scalloc(MAX_ALLOCATION_SIZE / 8, 9);
    REQUIRE(b == nullptr);
    after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE + _size_meta_data() == (size_t)after - (size_t)base);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 0, 0);
    verify_size(base);
    b = (char *)scalloc(9, MAX_ALLOCATION_SIZE / 8);
    REQUIRE(b == nullptr);
    after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE + _size_meta_data() == (size_t)after - (size_t)base);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 1, MAX_ALLOCATION_SIZE);
    verify_size(base);
}

TEST_CASE("realloc", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    int *a = (int *)srealloc(nullptr, 10 * sizeof(int));
    REQUIRE(a != nullptr);

    for (int i = 0; i < 10; i++)
    {
        a[i] = i;
    }

    verify_blocks(1, 10 * sizeof(int), 0, 0);
    verify_size(base);

    int *b = (int *)srealloc(a, 100 * sizeof(int));
    REQUIRE(b != nullptr);
    REQUIRE(b != a);
    for (int i = 0; i < 10; i++)
    {
        REQUIRE(b[i] == i);
    }

    verify_blocks(2, sizeof(int) * 110, 1, sizeof(int) * 10);
    verify_size(base);

    sfree(b);
    verify_blocks(2, sizeof(int) * 110, 2, sizeof(int) * 110);
    verify_size(base);
}

TEST_CASE("realloc shrink", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);

    void *base = sbrk(0);
    int *a = (int *)srealloc(nullptr, 100 * sizeof(int));
    REQUIRE(a != nullptr);

    for (int i = 0; i < 10; i++)
    {
        a[i] = i;
    }

    verify_blocks(1, 100 * sizeof(int), 0, 0);
    verify_size(base);

    int *b = (int *)srealloc(a, 10 * sizeof(int));
    REQUIRE(b != nullptr);
    REQUIRE(b == a);
    for (int i = 0; i < 10; i++)
    {
        REQUIRE(b[i] == i);
    }

    verify_blocks(1, sizeof(int) * 100, 0, 0);
    verify_size(base);

    sfree(b);
    verify_blocks(1, sizeof(int) * 100, 1, sizeof(int) * 100);
    verify_size(base);
}

TEST_CASE("srealloc Max size", "[malloc2]")
{
    verify_blocks(0, 0, 0, 0);
    void *base = sbrk(0);
    char *a = (char *)srealloc(nullptr, MAX_ALLOCATION_SIZE);
    REQUIRE(a != nullptr);
    void *after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE + _size_meta_data() == (size_t)after - (size_t)base);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 0, 0);
    verify_size(base);

    char *b = (char *)srealloc(a, MAX_ALLOCATION_SIZE + 1);
    REQUIRE(b == nullptr);
    after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE + _size_meta_data() == (size_t)after - (size_t)base);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 0, 0);
    verify_size(base);

    char *c = (char *)srealloc(nullptr, MAX_ALLOCATION_SIZE + 1);
    REQUIRE(c == nullptr);
    after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE + _size_meta_data() == (size_t)after - (size_t)base);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 0, 0);
    verify_size(base);

    sfree(a);
    verify_blocks(1, MAX_ALLOCATION_SIZE, 1, MAX_ALLOCATION_SIZE);
    verify_size(base);
}
