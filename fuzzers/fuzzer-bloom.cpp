#include "fuzzer.h"
#include "bloom.h"

/* Fuzzes:
 *  - class CBloomFilter (with variable nElements)
 *    methods:
 *              - insert()
 *              - contains()
 *              - clear()
 */

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const uint8_t* subbuffer;

    /* Reserve first 32 bytes of input data for setting options/variables */
    if ( size < 32 ) {
        return 0;
    }

    subbuffer = data;
    data += 32;
    size -= 32;

    uint32_t nElements = (subbuffer[0] << 16) + (subbuffer[1] << 8) + (subbuffer[2]);
    if ( nElements == 0 ) {
        nElements++;
    }
    subbuffer += 3;

    double nFPRate = (double)((subbuffer[0] << 16) + (subbuffer[1] << 8) + (subbuffer[2]));
    subbuffer += 3;
    nFPRate /= 100.0;



    CBloomFilter filter(nElements, (double)nFPRate, 0, subbuffer[0] & 1 ? BLOOM_UPDATE_ALL : BLOOM_UPDATE_NONE);

    /* Split input data into two chunks */
    std::vector<unsigned char> vec1(data, data+(size/2));
    std::vector<unsigned char> vec2(data+(size/2), data+size);

    /* insert() first chunk */
    filter.insert(vec1);

    /* contains() second chunk */
    filter.contains(vec2);

    /* contains() first chunk */
    filter.contains(vec1);

    filter.clear();

    // deserialize
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << filter;

    // serialize
    CBloomFilter filter2;
    ss >> filter2;

    
    return 0;
}
