#include <unistd.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include "pin.H"

using std::vector;

/*
STRUCTS
*/

int vpt_depth = 1;
int vpt_depth = 1;
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
    vector<UINT64> val_hist(vpt_depth, NULL);
};

vpt_entry* VPTable;

VOID CT_init()
{
    int i;
    for(i = 0; i < ct_length; i++) {
	ClassTable[i].valid = false;
	ClassTable[i].addr = 0;
	ClassTable[i].counter = 0;
    }
}

VOID VPT_init()
{
    int i;
    for(i = 0; i < vpt_depth; i++) {
	VPTable[i].valid = false;
	VPTable[i].addr = 0;
    }
}
