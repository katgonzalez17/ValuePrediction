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

enum InsType {unsupported_ins, fp_add, fp_sub, fp_mul, fp_div, int_mul, int_div, load};

UINT64 count_correct = 0;
UINT64 count_seen = 0;

UINT64 count_fp_add_corr = 0;
UINT64 count_fp_add_seen = 0;

UINT64 count_fp_sub_corr = 0;
UINT64 count_fp_sub_seen = 0;

UINT64 count_fp_mul_corr = 0;
UINT64 count_fp_mul_seen = 0;

UINT64 count_fp_div_corr = 0;
UINT64 count_fp_div_seen = 0;

UINT64 count_int_mul_corr = 0;
UINT64 count_int_mul_seen = 0;

UINT64 count_int_div_corr = 0;
UINT64 count_int_div_seen = 0;

UINT64 count_load_corr = 0;
UINT64 count_load_seen = 0;

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
    *out << "-------------------------------------" << endl;

    *out << "Count fp_add Seen: " << count_fp_add_seen << endl;
    *out << "Count fp_add Correct: " << count_fp_add_corr << endl;

    *out << "Count fp_sub Seen: " << count_fp_sub_seen << endl;
    *out << "Count fp_sub Correct: " << count_fp_sub_corr << endl;

    *out << "Count fp_mul Seen: " << count_fp_mul_seen << endl;
    *out << "Count fp_mul Correct: " << count_fp_mul_corr << endl;

    *out << "Count fp_div Seen: " << count_fp_div_seen << endl;
    *out << "Count fp_div Correct: " << count_fp_div_corr << endl;

    *out << "Count int_mul Seen: " << count_int_mul_seen << endl;
    *out << "Count int_mul Correct: " << count_int_mul_corr << endl;

    *out << "Count int_div Seen: " << count_int_div_seen << endl;
    *out << "Count int_div Correct: " << count_int_div_corr << endl;

    *out << "Count load Seen: " << count_load_seen << endl;
    *out << "Count load Correct: " << count_load_corr << endl;
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

ADDRINT non_xmm_prediction(ADDRINT ins_ptr) {
    // index into ct and vpt
    UINT64 ct_index = ins_ptr & ct_mask;
    UINT64 vpt_index = ins_ptr & vpt_mask;
    if (!ClassTable[ct_index].valid || ClassTable[ct_index].counter < 4) {
        return 0;
    } else {
        return VPTable[vpt_index].val_hist.back().u.non_xmm_entry;
    }
}

PIN_REGISTER xmm_prediction(ADDRINT ins_ptr) {
    // index into ct and vpt
    UINT64 ct_index = ins_ptr & ct_mask;
    UINT64 vpt_index = ins_ptr & vpt_mask;
    if (!ClassTable[ct_index].valid || ClassTable[ct_index].counter < 4) {
        return (PIN_REGISTER{0});
    } else {
        return VPTable[vpt_index].val_hist.back().u.xmm_entry;
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
    std::fill(VPTable[vpt_index].val_hist.begin(), VPTable[vpt_index].val_hist.end(), val_hist_entry{false, 0});
}

// For comparing PIN_REGISTERs to each other
bool operator == (const PIN_REGISTER &a, const PIN_REGISTER &b) {
    for(unsigned int i=0; i < MAX_DWORDS_PER_PIN_REG; i++) {
        if (a.dword[i] != b.dword[i]) {
            return false;
        }
    }
    return true;
}

bool operator != (const PIN_REGISTER &a, const PIN_REGISTER &b) {
    return !(a==b);
}

void update(ADDRINT ins_ptr, PIN_REGISTER actual_val) {
    val_hist_entry actual_entry = val_hist_entry{true, {xmm_entry: actual_val}};

    UINT64 ct_index = ins_ptr & ct_mask;
    UINT64 vpt_index = ins_ptr & vpt_mask;

    PIN_REGISTER pred_val;
    if (VPTable[vpt_index].val_hist.size() > 0) {
        pred_val = VPTable[vpt_index].val_hist.back().u.xmm_entry;
    }
    else {
        pred_val = actual_val;
        pred_val.dword[0] -= 1;
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
        if (VPTable[vpt_index].val_hist[i].is_xmm && actual_val == VPTable[vpt_index].val_hist[i].u.xmm_entry) {
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

void update(ADDRINT ins_ptr, ADDRINT actual_val) {
    val_hist_entry actual_entry = val_hist_entry{false, actual_val};

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

InsType get_ins_type(INS ins) {
    if (is_fp_add(ins)) {
        return fp_add;
    }
    if (is_fp_sub(ins)) {
        return fp_sub;
    }
    if (is_fp_mul(ins)) {
        return fp_mul;
    }
    if (is_fp_div(ins)) {
        return fp_div;
    }
    if (is_int_mul(ins)) {
        return int_mul;
    }
    if (is_int_div(ins)) {
        return int_div;
    }
    if (INS_IsMemoryRead(ins)) {
        return load;
    }
    return unsupported_ins;
}

void update_seen_count(UINT64 ins_type) {
    switch(ins_type) {
        case fp_add  : count_fp_add_seen++; break;
        case fp_sub  : count_fp_sub_seen++; break;
        case fp_mul  : count_fp_mul_seen++; break;
        case fp_div  : count_fp_div_seen++; break;
        case int_mul : count_int_mul_seen++; break;
        case int_div : count_int_div_seen++; break;
        case load : count_load_seen++; break;
    }
}

void predictValNormalReg(ADDRINT ins_ptr, ADDRINT actual_value, UINT64 ins_type) {
    update_seen_count(ins_type);
    if (in_tables(ins_ptr)) {
        if(non_xmm_prediction(ins_ptr) == actual_value) {
            count_correct++;
            switch(ins_type) {
                case fp_add  : count_fp_add_corr++; break;
                case fp_sub  : count_fp_sub_corr++; break;
                case fp_mul  : count_fp_mul_corr++; break;
                case fp_div  : count_fp_div_corr++; break;
                case int_mul : count_int_mul_corr++; break;
                case int_div : count_int_div_corr++; break;
                case load : count_load_corr++; break;
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

void predictValLargeReg(ADDRINT ins_ptr, const CONTEXT* context, REG dest_reg, UINT64 ins_type) {
    update_seen_count(ins_type);
    PIN_REGISTER actual_value;
    PIN_GetContextRegval(context, dest_reg, reinterpret_cast<UINT8*>(&actual_value));

    if (in_tables(ins_ptr)) {
        if(xmm_prediction(ins_ptr) == actual_value) {
            count_correct++;
            switch(ins_type) {
                case fp_add  : count_fp_add_corr++; break;
                case fp_sub  : count_fp_sub_corr++; break;
                case fp_mul  : count_fp_mul_corr++; break;
                case fp_div  : count_fp_div_corr++; break;
                case int_mul : count_int_mul_corr++; break;
                case int_div : count_int_div_corr++; break;
                case load : count_load_corr++; break;
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

void docount() {
    count_seen++;
}

void Instruction(INS ins, void *v) {
    // Increment count seen
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) docount, IARG_END);

    InsType ins_type = get_ins_type(ins);

    if (ins_type != unsupported_ins) {
        // Second operand is our dest reg; if it isn't we don't yet support it
        if (!INS_OperandIsReg(ins,0)) {
            *out << INS_Disassemble(ins) << endl;
            return;
        }

        // First register in a multiply instruction is dest reg
        REG dest_reg = INS_OperandReg(ins,0);
        assert(dest_reg);
        // The intstruction uses larger registers
        if (REG_is_xmm(dest_reg) || REG_is_st(dest_reg)) {
            INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR) predictValLargeReg,
                           IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_UINT64, dest_reg, IARG_UINT64, ins_type, IARG_END);
        }
        else {
            INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR) predictValNormalReg,
                           IARG_INST_PTR, IARG_REG_VALUE, dest_reg, IARG_UINT64, ins_type, IARG_END);
        }
    }
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
