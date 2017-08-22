#include "fuzzer.h"
#include "script/script.h"

enum TEST_ID {
    SER_INT64,
    SER_OPCODE,
    SER_CSCRIPTNUM,
    SER_VECTOR,
    OPER_ADD,
    GETOP,
    FIND,
    GETSIGOPCOUNT,
    ISWITNESSPROGRAM,
    ISPUSHONLY,
    GETSIGOPCOUNT2,
};
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    CScript cs;

    while ( size > 0 ) {
        uint8_t choice = data[0];
        size--;
        data++;

        switch ( choice ) {
            case    SER_INT64:
                {
                    if ( size < sizeof(int64_t) ) break;
                    int64_t i;
                    memcpy(&i, data, sizeof(i));
                    size -= sizeof(i);
                    data += sizeof(i);

                    cs << i;
                }
                break;
            case    SER_OPCODE:
                {
                    if ( size == 0 ) break;

                    enum opcodetype ot = (enum opcodetype)data[0];
                    size--;
                    data++;

                    cs << ot;
                }
                break;
            case SER_CSCRIPTNUM:
                {
                    /* TODO */
                }
                break;
            case SER_VECTOR:
                {
                    if ( size < sizeof(uint16_t) ) break;
                    uint16_t vector_size = (data[0] << 8) + data[1];
                    size -= sizeof(uint16_t);
                    data += sizeof(uint16_t);
                    std::vector<uint8_t> v(vector_size, 0);

                    cs << v;
                }
                break;
            case OPER_ADD:
                {
                   cs += cs; 
                }
                break;
            case GETOP:
                {
                    CScript::const_iterator pc = cs.begin();
                    std::vector<unsigned char> vch;
                    opcodetype opcode;
                    cs.GetOp(pc, opcode, vch);
                }
                break;
            case FIND:
                {
                    if ( size == 0 ) break;

                    enum opcodetype ot = (enum opcodetype)data[0];
                    size--;
                    data++;

                    cs.Find(ot);
                }
                break;
            case GETSIGOPCOUNT:
                {
                    cs.GetSigOpCount(true);
                    cs.GetSigOpCount(false);
                }
                break;
            case ISWITNESSPROGRAM:
                {
                    int version;
                    std::vector<unsigned char> program;
                    if ( cs.IsWitnessProgram(version, program) == true ) {
                        printf("X\n");
                    }
                }
            case ISPUSHONLY:
                {
                    cs.IsPushOnly();
                }
                break;
            case GETSIGOPCOUNT2:
                {
                    cs.GetSigOpCount(cs);
                }
                break;
        }
    }

    return 0;
}
