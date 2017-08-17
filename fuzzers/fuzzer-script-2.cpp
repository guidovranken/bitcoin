#include "fuzzer.h"
#include "core_io.h"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string s;
    s.append((const char*)data, size);
    CScript script;
    try {
        script = ParseScript(s);
    } catch ( std::runtime_error &e ) {
        return 0;
    }
    ScriptError err;
    std::vector<std::vector<unsigned char> > directStack, directStack2;
    EvalScript(directStack, script, SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SIGVERSION_BASE, &err);
    EvalScript(directStack2, script, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), SIGVERSION_BASE, &err);
    return 0;
}
