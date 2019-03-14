#include "pin.H"
#include <iostream>
#include <fstream>

#define LIBC "/lib/x86_64-linux-gnu/libc.so.6"

// static int g_count = 0;
static int c_count = 0;
static int r_count = 0;
static bool trace = 0;

static ADDRINT libcLow;
static ADDRINT libcHigh;
static ADDRINT execLow;
static ADDRINT execHigh;
static ADDRINT start_main;
static ADDRINT mainLow;
static ADDRINT mainHigh;

#define RET 1
#define CALL 2
#define BRANCH 4

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage() {
	cerr << "This tool detects ROP attacks.\n"; 
	cerr << endl;
	return -1;
}

/* ===================================================================== */
VOID ImageLoad(IMG img, VOID *v) {
	if(IMG_Name(img).compare(LIBC) == 0) {
		libcLow = IMG_LowAddress(img);
		libcHigh = IMG_HighAddress(img);

		// consider __libc_start_main+229 the begining of trace
		RTN rtn__libc_start_main = RTN_FindByName(img, "__libc_start_main");
		start_main = RTN_Address(rtn__libc_start_main) + 229;
	}

	if(IMG_IsMainExecutable(img)) {
		execLow = IMG_LowAddress(img);
		execHigh = IMG_HighAddress(img);
		// cerr << std::hex << "MainImg loaded: 0x" << execLow << " - 0x" << execHigh << endl;

		// consider the last ins of main the terminal of trace
		RTN rtn_main = RTN_FindByName(img, "main");
		mainLow  = RTN_Address(rtn_main);
		mainHigh = mainLow + RTN_Size(rtn_main) - 1 ;

		// cerr << std::hex << "Func Main: 0x" << mainLow << " - 0x" << mainHigh << endl;
	}
}

// Pin calls this function every time a new rtn is executed
// VOID Routine(RTN rtn, VOID *v) {
//     rc->_name = RTN_Name(rtn);
//     rc->_image = StripPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
//     rc->_address = RTN_Address(rtn);
//     rc->_icount = 0;
//     rc->_rtnCount = 0;
//     // Add to list of routines
//     rc->_next = RtnList;
//     RtnList = rc;
//     RTN_Open(rtn);
//     // Insert a call at the entry point of a routine to increment the call count
//     RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_rtnCount), IARG_END);
//     // For each instruction of the routine
//     for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
//         // Insert a call to docount to increment the instruction counter for this rtn
//         INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_icount), IARG_END);
//     }
//     RTN_Close(rtn);
// }

/* ===================================================================== */
// VOID g_counter(){g_count++;}

// count the number of call ins
VOID c_counter(ADDRINT ip, ADDRINT next){
	//if ins is call and it's next address is in below range (ignore other unrelated place), count it.
	if((next < execHigh && next > execLow) || (next < libcHigh && next > libcLow)){
		c_count++;
		cerr << "call[" << std::dec << c_count  << "] @ 0x"<< std::hex << ip << endl;
		cerr << "next: 0x" << std::hex << next << endl;
	}
}

// count the number of ret ins
VOID r_counter(ADDRINT ip, ADDRINT next){
	//if ins is ret and it would return in below range of address (ignore other unrelated place), count it.
	if((next < execHigh && next > execLow) || (next < libcHigh && next > libcLow)){
		r_count++;
		cerr << "ret[" << std::dec << r_count  << "] @ 0x"<< std::hex << next << endl;
	}
}

INT32 check(INS ins){
	return(INS_IsRet(ins) | INS_IsCall(ins) << 1 | INS_IsBranch(ins) << 2);
}

// print pc and next pc
// VOID printip(VOID *ip, VOID *next) { 
//     cerr << "[--] " << std::hex << ip << endl;
// 	cerr << "[->] " << std::hex << next << endl << endl;
// }

VOID Instruction(INS ins, VOID *v) {
	int flag = check(ins);
	ADDRINT ip = INS_Address(ins);
	if (ip == start_main){
		trace = 1;
	}
	if (trace){
		if(flag & CALL){
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)c_counter, 
				IARG_INST_PTR, 
				IARG_ADDRINT, (ADDRINT)INS_NextAddress(ins),
				IARG_END);
		}
		if(flag & RET){
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_counter, 
				IARG_INST_PTR, 
				IARG_BRANCH_TARGET_ADDR, 
				IARG_END);
		}
	}
	if (ip == mainHigh){
		trace = 0;
	}
	if(r_count > c_count){
		cerr << "WARNNING!" << endl;
	}
	// if(xxx jop? ){
	// 	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)xxxx, IARG_END);
	// }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v) {
    cerr <<  "===============================================" << endl;
    cerr <<  "MyPinTool done." << endl;
    cerr <<  "===============================================" << endl;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[]) {

	PIN_InitSymbols();

	if( PIN_Init(argc,argv) ) {
		return Usage();
	}

	IMG_AddInstrumentFunction(ImageLoad, 0);
	// RTN_AddInstrumentFunction(Routine, 0);
	INS_AddInstrumentFunction(Instruction, 0);

	PIN_AddFiniFunction(Fini, 0);

    cerr <<  "===============================================" << endl;
    cerr <<  " This application is instrumented by MyPinTool" << endl;
    cerr <<  "===============================================" << endl;

	// Never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
