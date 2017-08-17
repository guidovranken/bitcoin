#include "fuzzer.h"

/* Fuzzers EvalScript() with fuzzer input data.
 * Once with flags == SCRIPT_VERIFY_P2SH,
 * once with flags == SCRIPT_VERIFY_STRICTENC
 */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ScriptError err;
    std::vector<std::vector<unsigned char> > directStack, directStack2;
    EvalScript(directStack, CScript(data, data + size), SCRIPT_VERIFY_P2SH, BaseSignatureChecker(), SIGVERSION_BASE, &err);
    EvalScript(directStack2, CScript(data, data + size), SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), SIGVERSION_BASE, &err);
    return 0;
}
