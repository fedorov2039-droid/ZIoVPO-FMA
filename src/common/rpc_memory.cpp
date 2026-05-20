#include "common/rpc_memory.h"

#include <cstdlib>

extern "C" void* __RPC_USER MIDL_user_allocate(size_t size)
{
    return std::malloc(size);
}

extern "C" void __RPC_USER MIDL_user_free(void* pointer)
{
    std::free(pointer);
}
