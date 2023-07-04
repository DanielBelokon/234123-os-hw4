#include "my_stdlib.h"
#include <catch2/catch_test_macros.hpp>

#include <unistd.h>

#define MAX_ALLOCATION_SIZE (1e8)

TEST_CASE("Sanity", "[malloc1]")
{
    void *base = sbrk(0);
    char *a = (char *)smalloc(10);
    REQUIRE(a != nullptr);
    REQUIRE(base == a);
}

TEST_CASE("Check size", "[malloc1]")
{
    void *base = sbrk(0);
    char *a = (char *)smalloc(1);
    REQUIRE(a != nullptr);
    REQUIRE(base == a);
    void *after = sbrk(0);
    REQUIRE(1 == (size_t)after - (size_t)base);

    char *b = (char *)smalloc(10);
    REQUIRE(b != nullptr);
    REQUIRE((char *)base + 1 == b);
    after = sbrk(0);
    REQUIRE(11 == (size_t)after - (size_t)base);
}

TEST_CASE("0 size", "[malloc1]")
{
    void *base = sbrk(0);
    char *a = (char *)smalloc(0);
    REQUIRE(a == nullptr);
    void *after = sbrk(0);
    REQUIRE(after == base);
}

TEST_CASE("Max size", "[malloc1]")
{
    void *base = sbrk(0);
    char *a = (char *)smalloc(MAX_ALLOCATION_SIZE);
    REQUIRE(a != nullptr);
    void *after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE == (size_t)after - (size_t)base);

    char *b = (char *)smalloc(MAX_ALLOCATION_SIZE + 1);
    REQUIRE(b == nullptr);
    after = sbrk(0);
    REQUIRE(MAX_ALLOCATION_SIZE == (size_t)after - (size_t)base);
}
