#include "fuzzer.h"
#include "merkleblock.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::vector<uint256> v;
    std::vector<bool> v2;
    const uint8_t* ptr = data;
    size_t num_uint256 = size / 32;
    if ( num_uint256 == 0 ) {
        return 0;
    }
    while ( num_uint256 > 0 ) {
        uint256 u = uint256(std::vector<unsigned char>(ptr, ptr+32));
        v.push_back(u);
        v2.push_back(*ptr & 1 ? true : false);
        ptr += 32;
        num_uint256--;
    }
    CPartialMerkleTree pmt(v, v2);

    // serialize
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << pmt;

    // deserialize into a tester copy
    CPartialMerkleTree pmt2;
    ss >> pmt2;

    // extract merkle root and matched txids from copy
    std::vector<uint256> vMatchTxid2;
    std::vector<unsigned int> vIndex;
    uint256 merkleRoot2 = pmt2.ExtractMatches(vMatchTxid2, vIndex);
    return 0;
}
