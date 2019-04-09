#include "pin.H"
#include "stack.H"
#include <iostream>
#include <fstream>

#define LIBC "/lib/x86_64-linux-gnu/libc.so.6" // 64-bit
// #define LIBC "/lib/i386-linux-gnu/libc.so.6" //32-bit
#define RET 1
#define CALL 2
#define BRANCH 4

#define STK_DECT 1
#define CRB_DECT 1
#define DEBUG 1

static int c_count = 0;
static int r_count = 0;
static int trace = 0;

static ADDRINT libcLow;
static ADDRINT libcHigh;
static ADDRINT execLow;
static ADDRINT execHigh;
static ADDRINT mainLow;
static ADDRINT mainHigh;

static LinkStack* lstack;
static LinkStack* symbols;

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
		cerr << "libc loaded: 0x" << hex << libcLow << " - 0x" << libcHigh << endl;
	}
	if(IMG_IsMainExecutable(img)) {
		execLow = IMG_LowAddress(img);
		execHigh = IMG_HighAddress(img);
		cerr << "text section: 0x" << hex << execLow << " - 0x" << execHigh << endl;

		// consider the last ins of main the terminal of trace
		RTN rtn_main = RTN_FindByName(img, "main");
		mainLow  = RTN_Address(rtn_main);
		mainHigh = mainLow + RTN_Size(rtn_main) - 1 ;

		// Forward pass over all symbols in an image
		for( SYM sym= IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) ){
			cerr << "symbol: " << SYM_Name(sym) << " @ " ;
			cerr << hex << "0x" << SYM_Address(sym) << endl;
			STK_Push(symbols, SYM_Address(sym));
		}
		STK_Show(symbols);
	}
}

// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID *v) {
    // rc->_name = RTN_Name(rtn);
    // rc->_image = StripPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
    // rc->_address = RTN_Address(rtn);
    // rc->_icount = 0;
    // rc->_rtnCount = 0;
    // // Add to list of routines
    // rc->_next = RtnList;
    // RtnList = rc;
    // RTN_Open(rtn);
    // // Insert a call at the entry point of a routine to increment the call count
    // RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_rtnCount), IARG_END);
    // // For each instruction of the routine
    // for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
    //     // Insert a call to docount to increment the instruction counter for this rtn
    //     INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(rc->_icount), IARG_END);
    // }
    // RTN_Close(rtn);
}

/* ===================================================================== */

// count the number of call ins
VOID c_counter(ADDRINT ip, ADDRINT target, ADDRINT next){
	//if ins is call and it's next address is in below range (ignore other unrelated place), count it.
	if(next < execHigh && next > execLow){
		if(STK_Search(symbols, target)){
			if(next < libcHigh && next > libcLow){
				return ; // do not trace call inside of function@libc
			}
			c_count++;
			if(STK_DECT){
				STK_Push(lstack ,next);
				if(DEBUG) {
					cerr << "Pushed: 0x" << std::hex << next << endl;
					STK_Show(lstack);
				}
			}
			if(DEBUG){
				cerr << "call[" << std::dec << c_count  << "] @ 0x"<< std::hex << ip << endl;
				cerr << "call for 0x" << target << endl;
				cerr << "next: 0x" << std::hex << next << endl;
			}
		}else{
			cerr << "COP attack detected !!!";
			cerr << "call for 0x" << target << " is invaild!!!" << endl;
		}
	}
}

// count the number of ret ins
VOID r_counter(ADDRINT ip, ADDRINT target){
	//if ins is ret and it would return in below range of address (ignore other unrelated place), count it.
	// if((target < execHigh && target > execLow) || (target < libcHigh && target > libcLow)){
	if((target < execHigh && target > execLow)){
		r_count++;
		if(STK_DECT){
			ADDRINT ret = STK_Pop(lstack);
			if(DEBUG) {
				STK_Show(lstack);
				cerr << "Poped: 0x" << std::hex << ret << endl;
			}
			if(ret != target){
				cerr << "[STK] Gadget Found!!! addr: 0x" << std::hex << target << endl;
				// exit(0);
			}
		}
		if(DEBUG){
			cerr << "ret[" << std::dec << r_count  << "] @ 0x"<< std::hex << target << endl;
		}
	}
}

// count the number of branch ins
VOID b_check(ADDRINT ip, ADDRINT next){
	//if ins is ret and it would return in below range of address (ignore other unrelated place), count it.
	if((ip < execHigh && ip > execLow) || (ip < libcHigh && ip > libcLow)){
		// cerr << "branch @ 0x" << hex << ip << " -> 0x" << next << endl;
		
	}
}

// consider ins calling main the begining of trace
VOID start_trace(ADDRINT ip, ADDRINT target, ADDRINT next){
	if (target == mainLow){
		trace = 1;
		c_counter(ip, target, next);
	}
}

INT32 check(INS ins){
	return(INS_IsRet(ins) | INS_IsCall(ins) << 1 | INS_IsBranch(ins) << 2);
}

VOID Instruction(INS ins, VOID *v) {
	int flag = check(ins);
	ADDRINT ip = INS_Address(ins);
	if(trace == 0 && flag){
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)start_trace, 
			IARG_INST_PTR, 
			IARG_BRANCH_TARGET_ADDR, 
			IARG_ADDRINT, INS_NextAddress(ins),
			IARG_END);
	}
	if (trace == 1){
		if(flag & CALL){
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)c_counter, 
				IARG_INST_PTR, 
				IARG_BRANCH_TARGET_ADDR, 
				IARG_ADDRINT, INS_NextAddress(ins),
				IARG_END);
		}
		if(flag & RET){
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_counter, 
				IARG_INST_PTR, 
				IARG_BRANCH_TARGET_ADDR, 
				IARG_END);
		}
		if(flag & BRANCH){
			INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)b_check, 
				IARG_INST_PTR, 
				IARG_BRANCH_TARGET_ADDR, 
				IARG_END);
		}
	}
	if (ip == mainHigh){
		trace = -1;
	}
	// xop attack detector
	// if(STK_IsEmpty(lstack) && trace == 1){
	if( CRB_DECT && r_count > c_count ){
		cerr << "[CRB] WARNNING!!!" << endl;
		// exit(0);
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
	lstack = new(LinkStack);
	symbols = new(LinkStack);
	STK_Init(lstack);
	STK_Init(symbols);

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
// pin rop fram
// - ins dect pos 
// - method 
// 1.addr cmp
// 2.ins count
// 3.gadget length
// handel
// ROP JOP return-into-libc

// shadowstack cannot handle jop
// what to do when pin has vulnerability?

// trace point set? 
// some func(e.g. printf) in libc do not obey call-ret balance 
