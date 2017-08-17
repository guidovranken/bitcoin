#include "fuzzer.h"
#include "utilmoneystr.h"
#include <string.h>

static std::string getstring(const uint8_t* data, size_t size)
{
    std::string s;
    s.append((const char*)data, size);
    return s;
}

#define GETSTRING getstring(data, size)

/* Fuzzes the functions defined in src/utilstrencodings.cpp */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string s;

    SanitizeString(GETSTRING);

    IsHex(GETSTRING);

    ParseHex(GETSTRING);

    s = EncodeBase64(data, size);

    DecodeBase64(GETSTRING);
    
    s = EncodeBase32(data, size);

    DecodeBase32(GETSTRING);

    {
        int32_t out;
        ParseInt32(GETSTRING, &out);
    }

    {
        int64_t out;
        ParseInt64(GETSTRING, &out);
    }

    {
        uint32_t out;
        ParseUInt32(GETSTRING, &out);
    }

    {
        uint64_t out;
        ParseUInt64(GETSTRING, &out);
    }

    {
        double out;
        ParseDouble(GETSTRING, &out);
    }

    {
        int64_t out;
        ParseFixedPoint(GETSTRING, 8, &out);
    }

    {
        CAmount out;
        if ( ParseMoney(GETSTRING, out) == true ) {
            FormatMoney(out);
        }
    }

    {
        base_blob<160> bb;
        bb.SetHex(GETSTRING);
        if ( strlen(bb.GetHex().c_str()) == 10240 ) {
            abort();
        }
    }

    {
        base_blob<256> bb;
        bb.SetHex(GETSTRING);
        if ( strlen(bb.GetHex().c_str()) == 10240 ) {
            abort();
        }
    }

    {
        base_uint<256> bu;
        bu.SetHex(GETSTRING);
        bu.getdouble();
    }

    return 0;
}
