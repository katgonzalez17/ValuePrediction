#include <unistd.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include "pin.H"
#include <vector>

using std::vector;
using std::string;
using std::endl;
using std::cerr;

std::ostream * out = &cerr;

// KNOBs
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,         "pintool",
                            "outfile", "tool.out", "Output file for the pintool");

KNOB<BOOL>   KnobPid(KNOB_MODE_WRITEONCE,                "pintool",
                            "pid", "0", "Append pid to output");

// STRUCTS
int vpt_depth = 1;
int vpt_length = 1;
int ct_length = 1;

UINT64 ct_mask;
UINT64 vpt_mask;

struct ct_entry {
    bool valid;
    UINT64 addr;
    UINT8 counter;
};

ct_entry* ClassTable;

struct vpt_entry {
    bool valid;
    UINT64 addr;
    vpt_entry() : val_hist(vpt_depth, 0){}
    vector<UINT64> val_hist;
};

vpt_entry* VPTable;

VOID CT_init()
{
    for(int i = 0; i < ct_length; i++) {
        ClassTable[i].valid = false;
        ClassTable[i].addr = 0;
        ClassTable[i].counter = 0;
    }
}

VOID VPT_init()
{
    for(int i = 0; i < vpt_depth; i++) {
        VPTable[i].valid = false;
        VPTable[i].addr = 0;
    }
}

static INT32 Usage() {
    cerr << "This pin tool collects a profile of the Lipasti value predictor\n";
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}

void PrintResults(bool limit_reached) {
    string output_file = KnobOutputFile.Value();
    if(KnobPid.Value()) output_file += "." + getpid();

    if (!output_file.empty()) { out = new std::ofstream(output_file.c_str());}

    if(limit_reached) {
        *out << "Reason: limit reached\n";
    }
    else {
        *out << "Reason: fini\n";
    }
}

// For non-Load instructions we need to use their Opcodes (no built-in functions)
// Found using https://www.felixcloutier.com/x86/ and https://intelxed.github.io/ref-manual/xed-iclass-enum_8h.html
bool is_fp_add(INS ins) {
    OPCODE opcode = INS_Opcode(ins);
    if (opcode == XED_ICLASS_ADDPD  // Add Packed Double-Precision Floating-Point Values
        || opcode == XED_ICLASS_ADDPS  // Add Packed Single-Precision Floating-Point Values
        || opcode == XED_ICLASS_ADDSD  // Add Scalar Double-Precision Floating-Point Values
        || opcode == XED_ICLASS_ADDSS  // Add Scalar Single-Precision Floating-Point Values
       ) {
        return true;
    }
    return false;
}

bool is_fp_sub(INS ins) {
    OPCODE opcode = INS_Opcode(ins);
    if (opcode == XED_ICLASS_SUBPD  // Subtract Packed Double-Precision Floating-Point Values
        || opcode == XED_ICLASS_SUBPS  // Subtract Packed Single-Precision Floating-Point Values
        || opcode == XED_ICLASS_SUBSD  // Subtract Scalar Double-Precision Floating-Point Values
        || opcode == XED_ICLASS_SUBSS  // Subtract Scalar Single-Precision Floating-Point Values
       ) {
        return true;
    }
    return false;
}

bool is_fp_mul(INS ins) {
    OPCODE opcode = INS_Opcode(ins);
    if (opcode == XED_ICLASS_MULPD  // Multiply Packed Double-Precision Floating-Point Values
        || opcode == XED_ICLASS_MULPS  // Multiply Packed Single-Precision Floating-Point Values
        || opcode == XED_ICLASS_MULSD  // Multiply Scalar Double-Precision Floating-Point Values
        || opcode == XED_ICLASS_MULSS  // Multiply Scalar Single-Precision Floating-Point Values
       ) {
        return true;
    }
    return false;
}

bool is_fp_div(INS ins) {
    OPCODE opcode = INS_Opcode(ins);
    if (opcode == XED_ICLASS_DIVPD  // Divide Packed Double-Precision Floating-Point Values
        || opcode == XED_ICLASS_DIVPS  // Divide Packed Single-Precision Floating-Point Values
        || opcode == XED_ICLASS_DIVSD  // Divide Scalar Double-Precision Floating-Point Values
        || opcode == XED_ICLASS_DIVSS  // Divide Scalar Single-Precision Floating-Point Values
       ) {
        return true;
    }
    return false;
}

bool is_int_mul(INS ins) {
    OPCODE opcode = INS_Opcode(ins);
    if (opcode == XED_ICLASS_MUL  // Unsigned divide
        || opcode == XED_ICLASS_IMUL  // Signed divide
       ) {
        return true;
    }
    return false;
}

bool is_int_div(INS ins) {
    OPCODE opcode = INS_Opcode(ins);
    if (opcode == XED_ICLASS_DIV  // Unsigned divide
        || opcode == XED_ICLASS_IDIV  // Signed divide
       ) {
        return true;
    }
    return false;
}

void Instruction(INS ins, void *v)
{
    //if (INS_IsMemoryRead(ins))
    //if (is_fp_add(ins))
    //if (is_fp_sub(ins))
    //if (is_fp_mul(ins))
    //if (is_fp_div(ins))
    //if (is_int_mul(ins))
    //if (is_int_div(ins))
}

/* ===================================================================== */
void fini(int n, void *v) {
    PrintResults(false);
}

/* ===================================================================== */
int main(int argc, char *argv[]) {
    if( PIN_Init(argc,argv) ) {
        return Usage();
    }

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(fini, 0);

    PIN_StartProgram();

    return 0;
}
