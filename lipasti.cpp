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

KNOB<UINT64> KnobInstLimit(KNOB_MODE_WRITEONCE,        "pintool",
                            "inst_limit", "0", "Limit of instructions analyzed");
// GLOBALS

enum Ins_Types {int_mul, fp_add, fp_sub, fp_mul, fp_div, int_div};

UINT64 count_correct;
UINT64 count_seen;

UINT64 count_int_mul_corr;
UINT64 count_int_mul_seen;

UINT64 count_fp_add_corr;
UINT64 count_fp_add_seen;

UINT64 count_fp_sub_corr;
UINT64 count_fp_sub_seen;

UINT64 count_fp_mul_corr;
UINT64 count_fp_mul_seen;

UINT64 count_fp_div_corr;
UINT64 count_fp_div_seen;

UINT64 count_int_div_corr;
UINT64 count_int_div_seen;

// STRUCTS
int vpt_depth = 1;
int vpt_size = 1024;
int ct_size = 1024;

UINT64 ct_mask;
UINT64 vpt_mask;

struct ct_entry {
    bool valid;
    ADDRINT addr;
    UINT8 counter;
};

ct_entry* ClassTable;

struct val_hist_entry {
    bool is_xmm;
    union {
        ADDRINT non_xmm_entry;
        PIN_REGISTER xmm_entry;
   } u;
};

struct vpt_entry {
    bool valid;
    ADDRINT addr;
    vector<val_hist_entry> val_hist;
};

vpt_entry* VPTable;

void CT_init()
{
    for(int i = 0; i < ct_size; i++) {
        ClassTable[i].valid = false;
        ClassTable[i].addr = 0;
        ClassTable[i].counter = 0;
    }
}

void VPT_init()
{
    for(int i = 0; i < vpt_size; i++) {
        VPTable[i].valid = false;
        VPTable[i].addr = 0;
    }
}

// PRINT RESULTS HERE

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
    *out << "Count Seen: " << count_seen << endl;
    *out << "Count Correct: " << count_correct << endl;
}

bool in_tables(ADDRINT ins_ptr) {
    UINT64 ct_index = ins_ptr & ct_mask;
    UINT64 vpt_index = ins_ptr & vpt_mask;

    if (!ClassTable[ct_index].valid || !VPTable[vpt_index].valid) {
        return false;
    }

    if (ClassTable[ct_index].addr != ins_ptr || VPTable[vpt_index].addr != ins_ptr) {
        return false;
    }
    return true;
}

ADDRINT non_xmm_prediction(ADDRINT ins_ptr, bool is_xmm) {
    // index into ct and vpt
    UINT64 ct_index = ins_ptr & ct_mask;
    UINT64 vpt_index = ins_ptr & vpt_mask;
    if (!ClassTable[ct_index].valid || ClassTable[ct_index].counter < 4) {
        return 0;
    } else {
        return VPTable[vpt_index].val_hist.back().u.non_xmm_entry;
    }
}

void insert(ADDRINT ins_ptr) {
    UINT64 ct_index = ins_ptr & ct_mask;
    UINT64 vpt_index = ins_ptr & vpt_mask;

    ClassTable[ct_index].valid = true;
    ClassTable[ct_index].counter = 0;
    ClassTable[ct_index].addr = ins_ptr;

    VPTable[vpt_index].valid = true;
    VPTable[vpt_index].addr = ins_ptr;
    std::fill(VPTable[vpt_index].val_hist.begin(), VPTable[vpt_index].val_hist.end(), NULL);
}

void update(ADDRINT ins_ptr, ADDRINT actual_val) {
    val_hist_entry actual_entry = val_hist_entry{false, actual_val};

    // need to iterate through vector and see if actual value contained
    UINT64 ct_index = ins_ptr & ct_mask;
    UINT64 vpt_index = ins_ptr & vpt_mask;

    ADDRINT pred_val;
    if (VPTable[vpt_index].val_hist.size() > 0) {
        pred_val = VPTable[vpt_index].val_hist.back().u.non_xmm_entry;
    }
    else {
        pred_val = actual_val - 1;
    }

    // 3 bit counter resolution
    if (ClassTable[ct_index].counter > 0 && pred_val != actual_val) {
        ClassTable[ct_index].counter--;
    }
    if (ClassTable[ct_index].counter < 7 && pred_val == actual_val) {
        ClassTable[ct_index].counter++;
    }

    bool in_vpt = false;

    for (long int i = 0; i < (long int)VPTable[vpt_index].val_hist.size(); i++) {
        if (!VPTable[vpt_index].val_hist[i].is_xmm && actual_val == VPTable[vpt_index].val_hist[i].u.non_xmm_entry) {
            in_vpt = true;
            VPTable[vpt_index].val_hist.erase(VPTable[vpt_index].val_hist.begin()+i);
            VPTable[vpt_index].val_hist.push_back(actual_entry);
        }
    }
    if (!in_vpt && VPTable[vpt_index].val_hist.size() < (UINT64)vpt_depth) {
        VPTable[vpt_index].val_hist.push_back(actual_entry);
    } else if (!in_vpt && VPTable[vpt_index].val_hist.size() >= (UINT64)vpt_depth) {
        // delete the front of the vector, then push_back
        VPTable[vpt_index].val_hist.erase(VPTable[vpt_index].val_hist.begin());
        VPTable[vpt_index].val_hist.push_back(actual_entry);
    }
}

void predictValNonXmm(ADDRINT ins_ptr, ADDRINT actual_value, UINT64 ins_type) {
    count_seen++;
    if (in_tables(ins_ptr)) {
        if(non_xmm_prediction(ins_ptr, false) == actual_value) {
            count_correct++;
	    // switchcase here
	    switch(ins_type) {
		case int_mul : count_int_mul_corr++; break;
		case fp_add  : count_fp_add_corr++; break;
		case fp_sub  : count_fp_sub_corr++; break;
		case fp_mul  : count_fp_mul_corr++; break;
		case fp_div  : count_fp_div_corr++; break;
		case int_div : count_int_div_corr++; break;
	    }
        }
        update(ins_ptr, actual_value);
    }
    else {
        insert(ins_ptr);
        update(ins_ptr, actual_value);
    }

    if (count_seen == KnobInstLimit.Value()) {
        PrintResults(true);
        PIN_ExitProcess(EXIT_SUCCESS);
    }
}

static INT32 Usage() {
    cerr << "This pin tool collects a profile of the Lipasti value predictor\n";
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
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
    // TODO: we need a way to get the destination register
    /*if (INS_IsMemoryRead(ins)) {
        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR) PredictVal,
                       IARG_INST_PTR, IARG_REG_VALUE,  IARG_END);
    }
    */
    if (is_int_mul(ins)) {
        // Second operand is our dest reg; if it isn't we don't yet support it
        assert(INS_OperandIsReg(ins,0));
        count_int_mul_seen++;
        if (INS_OperandIsReg(ins,0)) {
            // First register in a multiply instruction is dest reg
            REG dest_reg = INS_OperandReg(ins,0);
	    UINT64 ins_type = int_mul;
            if (dest_reg) {
                // TODO: create an Xmm predictValue function
                if (REG_is_xmm(dest_reg)) {

                }
                else {
                    INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR) predictValNonXmm,
                                   IARG_INST_PTR, IARG_REG_VALUE, dest_reg, IARG_UINT64, ins_type, IARG_END);
                }
            }
        }
    }
    if (is_fp_add(ins)) {
        // Second operand is our dest reg; if it isn't we don't yet support it
        assert(INS_OperandIsReg(ins,0));
        count_fp_add_seen++;
        if (INS_OperandIsReg(ins,0)) {
            // First register in a multiply instruction is dest reg
            REG dest_reg = INS_OperandReg(ins,0);
	    UINT64 ins_type = fp_add;
            if (dest_reg) {
                // TODO: create an Xmm predictValue function
                if (REG_is_xmm(dest_reg)) {

                }
                else {
                    INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR) predictValNonXmm,
                                   IARG_INST_PTR, IARG_REG_VALUE, dest_reg, IARG_UINT64, ins_type, IARG_END);
                }
            }
        }
    }
    if (is_fp_sub(ins)) {
        // Second operand is our dest reg; if it isn't we don't yet support it
        assert(INS_OperandIsReg(ins,0));
        count_fp_sub_seen++;
        // *out << INS_Disassemble(ins) <<endl;
        // First register in a multiply instruction is dest reg
        REG dest_reg = INS_OperandReg(ins,0);
	UINT64 ins_type = fp_sub;
        if (dest_reg) {
            // TODO: create an Xmm predictValue function
            if (REG_is_xmm(dest_reg)) {

            }
            else {
                INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR) predictValNonXmm,
                               IARG_INST_PTR, IARG_REG_VALUE, dest_reg, IARG_UINT64, ins_type, IARG_END);
            }
        }
    }
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
    ct_mask = ct_size - 1;
    vpt_mask = vpt_size - 1;
    ClassTable = new ct_entry[ct_size];
    CT_init();
    VPTable = new vpt_entry[vpt_size];
    VPT_init();
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(fini, 0);

    PIN_StartProgram();

    return 0;
}
