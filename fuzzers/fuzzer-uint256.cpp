#include "fuzzer.h"
#include "uint256.h"
#include "arith_uint256.h"

inline arith_uint256 arith_uint256V(const std::vector<unsigned char>& vch)
{
    return UintToArith256(uint256(vch));
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char* str = (char*)malloc(size+1);
    memcpy(str, data, size);
    str[size] = 0x00;
    uint256 U = uint256S(str);
    free(str);
    U.GetHex();
    U.ToString();
    U.size();
    
    if ( size < 32 ) {
        return 0;
    }
    arith_uint256 V = arith_uint256V(std::vector<unsigned char>(data,data+32));
    V <<= 1;
    V <<= 2;
    V /= 3;
    V *= 4;
    V -= 5;
    V += 4294967296;
    if ( V != 0 )
        V /= V;
    V.ToString();
    V.size();
    V.GetLow64();
    return 0;
}
