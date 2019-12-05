#include <unistd.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include "pin.H"

UINT64 history = 0; // bits tracking global history

const int lvp_size = 8192;

struct lvp_entry {
    bool is_xmm_value;
    union {
        ADDRINT non_xmm_value;
        PIN_REGISTER xmm_value;
    } u;
    UINT8 counter;
};

const int vt_table_size = 1024;
const int num_vt_tables = 6;

struct vt_entry {
    bool is_xmm_value;
    union {
        ADDRINT non_xmm_value;
        PIN_REGISTER xmm_value;
    } u;
    UINT8 counter;
    ADDRINT addr;
    // Usefulness counter
    bool u;
};
