#pragma once

#include <cstddef>
#include <rpc.h>

extern "C" {
void* __RPC_USER MIDL_user_allocate(size_t size);
void __RPC_USER MIDL_user_free(void* pointer);
}
