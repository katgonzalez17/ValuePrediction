#include <unistd.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include "pin.H"
#include <functional>

using std::string;
using std::endl;
using std::cerr;
using std::size_t;
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
enum PredictionStatus {incorrect=0, correct=1};

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

// Bits tracking global history. Most recent history at at rightmost bit
UINT64 history = 0;

const int lvp_size = 8192;

const int counter_max = 7; // 3 bit saturating counter

struct lvp_entry {
    bool is_large_value;
    union {
        ADDRINT non_large_value;
        PIN_REGISTER large_value;
    } u;
    UINT8 counter;
};

const int vt_table_size = 1024;
const int num_vt_tables = 6;

struct vt_entry {
    bool is_large_value;
    union {
        ADDRINT non_large_value;
        PIN_REGISTER large_value;
    } u;
    UINT8 counter;
    ADDRINT tag;
    // Usefulness counter
    bool useful;
};

// Array of pointers, each pointer is to a vt_table, ordered according to their
// rank (0th table is first rank, 1st table is second rank, etc.)
vt_entry* vt_tables[num_vt_tables];

void vt_tables_init() {
    for (int i = 0; i < num_vt_tables; i++) {
        vt_tables[i] = new vt_entry[vt_table_size];
    }
    for (int table_index = 0; table_index < num_vt_tables; table_index++) {
        for (int table_entry = 0; table_entry < vt_table_size; table_entry++) {
            vt_tables[table_index][table_entry].is_large_value = false;
            vt_tables[table_index][table_entry].u.non_large_value = 0;
            vt_tables[table_index][table_entry].counter = 0;
            vt_tables[table_index][table_entry].tag = 0;
            vt_tables[table_index][table_entry].useful = false;
        }
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

UINT64 getRelevantHistoryBits(UINT64 table_index) {
    // Handle possible overflow
    if (table_index == 5) {
        return history & UINT64(-1);
    }
    UINT64 num_bits = 1UL << (table_index + 1UL);
    return history & ((1UL << num_bits) - 1UL);
}

void update_vt_c_and_u(int table_index, size_t vt_index, PredictionStatus prediction_status) {
    if (prediction_status == correct) {
        if (vt_tables[table_index][vt_index].counter < counter_max) {
            vt_tables[table_index][vt_index].counter++;
        }
        vt_tables[table_index][vt_index].useful = true;
    }
    else {
        if (vt_tables[table_index][vt_index].counter > 0) {
            vt_tables[table_index][vt_index].counter--;
        }
        vt_tables[table_index][vt_index].useful = false;
    }
}

size_t compute_vt_index (ADDRINT ins_ptr, int table_index) {
    // Compute index into this vt_table
    unsigned long long history_bits = getRelevantHistoryBits(table_index);
    size_t history_hash = std::hash<unsigned long long>{}(history_bits);
    size_t ins_ptr_hash = std::hash<unsigned long long>{}(ins_ptr);
    // Szudzik's function
    size_t combined = (history_hash >= ins_ptr_hash
                            ? history_hash * history_hash + history_hash + ins_ptr_hash
                            : history_hash + ins_ptr_hash * ins_ptr_hash);
    size_t vt_index = (std::hash<unsigned long long>{}(combined) % vt_table_size);
    return vt_index;
}

// Finds a VT above the `provider_index` VT for which ins_ptr hashes to
// a non-useful (useful bit = 0) entry. Returns this VT index or -1 if none
// found
int find_upper_non_useful_vt(ADDRINT ins_ptr, int provider_index) {
    std::vector<int> upper_tables;
    for (int i = provider_index + 1; i < num_vt_tables; i++) {
        upper_tables.push_back(i);
    }
    std::random_shuffle (upper_tables.begin(), upper_tables.end());

    for (std::vector<int>::iterator it = upper_tables.begin() ; it != upper_tables.end(); ++it) {
        size_t vt_index = compute_vt_index(ins_ptr, *it);
        if (vt_tables[*it][vt_index].useful == false) {
            return *it;
        }
    }
    return -1;
}

void reset_upper_vt_usefulness(ADDRINT ins_ptr, int provider_index) {
    std::vector<int> upper_tables;
    for (int i = provider_index + 1; i < num_vt_tables; i++) {
        upper_tables.push_back(i);
    }
    for (std::vector<int>::iterator it = upper_tables.begin() ; it != upper_tables.end(); ++it) {
        size_t vt_index = compute_vt_index(ins_ptr, *it);
        vt_tables[*it][vt_index].useful = false;
    }
}

void handle_vt_misprediction(ADDRINT ins_ptr, int table_index, size_t vt_index, ADDRINT actual_value) {
    if (vt_tables[table_index][vt_index].counter == 0) {
        vt_tables[table_index][vt_index].u.non_large_value = actual_value;
    }
    int new_provider_index = find_upper_non_useful_vt(ins_ptr, table_index);
    // Didn't find non-useful entry
    if (new_provider_index == -1) {
        // Reset the usefulness counter of all matching entries in the upper VT's
        reset_upper_vt_usefulness(ins_ptr, table_index);
    }
    // Found an upper VT for which ins_ptr hashes to a non-useful entry
    else {
        size_t new_vt_index = compute_vt_index(ins_ptr, new_provider_index);
        vt_tables[new_provider_index][new_vt_index].is_large_value = false;
        vt_tables[new_provider_index][new_vt_index].u.non_large_value = actual_value;
        vt_tables[new_provider_index][new_vt_index].counter = 0;
        vt_tables[new_provider_index][new_vt_index].tag = ins_ptr;
        vt_tables[new_provider_index][new_vt_index].useful = 0;
    }
}

ADDRINT non_large_vt_prediction(ADDRINT ins_ptr, int table_index, size_t vt_index) {
    return vt_tables[table_index][vt_index].u.non_large_value;
}

void predictValNormalReg(ADDRINT ins_ptr, ADDRINT actual_value, UINT64 ins_type) {
    update_seen_count(ins_type);
    bool found_entry = false;
    int table_index;
    size_t vt_index;
    for (table_index = num_vt_tables - 1; table_index >= 0; table_index--) {
        vt_index = compute_vt_index(ins_ptr, table_index);

        // Check if this vt entry's tag matches ins_ptr
        if (vt_tables[table_index][vt_index].tag == ins_ptr) {
            // This vt_table has the longest history match
            found_entry = true;
            break;
        }
    }

    if (found_entry) {
        // Use the `table_index` vt_table to predict
        if (non_large_vt_prediction(ins_ptr, table_index, vt_index) == actual_value) {
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
            update_vt_c_and_u(table_index, vt_index, correct);
        }
        else {
            update_vt_c_and_u(table_index, vt_index, incorrect);
            handle_vt_misprediction(ins_ptr, table_index, vt_index, actual_value);
        }
    }
    else {
        // Use the base predictor
        // TODO
    }

    if (count_seen == KnobInstLimit.Value()) {
        PrintResults(true);
        PIN_ExitProcess(EXIT_SUCCESS);
    }
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

PIN_REGISTER large_vt_prediction(ADDRINT ins_ptr, int table_index, size_t vt_index) {
    return vt_tables[table_index][vt_index].u.large_value;
}

void handle_vt_misprediction_large(ADDRINT ins_ptr, int table_index, size_t vt_index, PIN_REGISTER actual_value) {
    if (vt_tables[table_index][vt_index].counter == 0) {
        vt_tables[table_index][vt_index].is_large_value = true;
        vt_tables[table_index][vt_index].u.large_value = actual_value;
    }
    int new_provider_index = find_upper_non_useful_vt(ins_ptr, table_index);
    // Didn't find non-useful entry
    if (new_provider_index == -1) {
        // Reset the usefulness counter of all matching entries in the upper VT's
        reset_upper_vt_usefulness(ins_ptr, table_index);
    }
    // Found an upper VT for which ins_ptr hashes to a non-useful entry
    else {
        size_t new_vt_index = compute_vt_index(ins_ptr, new_provider_index);
        vt_tables[new_provider_index][new_vt_index].is_large_value = true;
        vt_tables[new_provider_index][new_vt_index].u.large_value = actual_value;
        vt_tables[new_provider_index][new_vt_index].counter = 0;
        vt_tables[new_provider_index][new_vt_index].tag = ins_ptr;
        vt_tables[new_provider_index][new_vt_index].useful = 0;
    }
}

void predictValLargeReg(ADDRINT ins_ptr, const CONTEXT* context, REG dest_reg, UINT64 ins_type) {
    update_seen_count(ins_type);
    PIN_REGISTER actual_value;
    PIN_GetContextRegval(context, dest_reg, reinterpret_cast<UINT8*>(&actual_value));

    bool found_entry = false;
    int table_index;
    size_t vt_index;
    for (table_index = num_vt_tables - 1; table_index >= 0; table_index--) {
        vt_index = compute_vt_index(ins_ptr, table_index);

        // Check if this vt entry's tag matches ins_ptr
        if (vt_tables[table_index][vt_index].tag == ins_ptr) {
            // This vt_table has the longest history match
            found_entry = true;
            break;
        }
    }

    if (found_entry) {
        // Use the `table_index` vt_table to predict
        if (large_vt_prediction(ins_ptr, table_index, vt_index) == actual_value) {
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
            update_vt_c_and_u(table_index, vt_index, correct);
        }
        else {
            update_vt_c_and_u(table_index, vt_index, incorrect);
            handle_vt_misprediction_large(ins_ptr, table_index, vt_index, actual_value);
        }
    }
    else {
        // Use the base predictor
        // TODO
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
    vt_tables_init();
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(fini, 0);

    PIN_StartProgram();

    return 0;
}
