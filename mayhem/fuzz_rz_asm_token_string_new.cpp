#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "rz_asm.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int src_width = provider.ConsumeIntegralInRange<int>(0, INT_MAX);
    int src_height = provider.ConsumeIntegralInRange<int>(0, INT_MAX);
    int dest_width_inout = provider.ConsumeIntegral<int>();
    int dest_height_inout = provider.ConsumeIntegral<int>();
    int font_ratio = provider.ConsumeFloatingPointInRange<float>(1, 100);
    int zoom = provider.ConsumeIntegral<int>();
    int stretch = provider.ConsumeIntegral<int>();

    std::string str = provider.ConsumeRandomLengthString();
    const char* cstr = str.c_str();
    rz_asm_token_string_new(cstr);

    return 0;
}