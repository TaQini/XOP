#include "pin.H"
#include "stack.H"
#include <iostream>
#include <fstream>

// #define LIBC "/lib/x86_64-linux-gnu/libc.so.6" // 64-bit
// #define LIBC "/lib/i386-linux-gnu/libc.so.6" //32-bit
#define LIBC "libc.so.6" //general
#define RET 1
#define CALL 2
#define BRANCH 4

#define STK_DECT 1
#define CRB_DECT 1
#define JOP_DECT 1
#define DEBUG 1

static int c_count = 0;
static int r_count = 0;
static bool libcAcc;

static ADDRINT libcLow;
static ADDRINT libcHigh;
static ADDRINT execLow;
static ADDRINT execHigh;

static LinkStack* lstack;
static LinkStack* symbols;
static LinkStack* symbols_libc;

/* ===================================================================== */

INT32 Usage() {
	cerr << "This tool detects ROP attacks.\n"; 
	cerr << endl;
	return -1;
}

/* ===================================================================== */
VOID ImageLoad(IMG img, VOID *v) {
	cerr << "Loading " << IMG_Name(img) << ", Image id = " << IMG_Id(img) << endl;
	if(IMG_Name(img).find(LIBC) != string::npos) {
		libcAcc = 1;
		libcLow = IMG_LowAddress(img);
		libcHigh = IMG_HighAddress(img);
		if(DEBUG) cerr << "libc loaded: 0x" << hex << libcLow << " - 0x" << libcHigh << endl;
		for( SYM sym= IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) ){
			STK_Push2(symbols_libc, SYM_Name(sym), SYM_Address(sym));
			if(DEBUG){
				// cerr << "symbol: " << SYM_Name(sym) << " @ " ;
				// cerr << hex << "0x" << SYM_Address(sym) << endl;
			}
		}
		// if(DEBUG) STK_Show2(symbols_libc);
	}
	if(IMG_IsMainExecutable(img)) {
		execLow = IMG_LowAddress(img);
		execHigh = IMG_HighAddress(img);
		if(DEBUG) cerr << "text section: 0x" << hex << execLow << " - 0x" << execHigh << endl;

		// Forward pass over all symbols in an image
		for( SYM sym= IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) ){
			STK_Push2(symbols, SYM_Name(sym), SYM_Address(sym));
			if(DEBUG){
				// cerr << "symbol: " << SYM_Name(sym) << " @ " ;
				// cerr << hex << "0x" << SYM_Address(sym) << endl;				
			}
		}
		// if(DEBUG) STK_Show2(symbols);
	}
}

VOID ImageUnload(IMG img, VOID *v) {
    cerr << "Unloading " << IMG_Name(img) << endl;
}

/* ===================================================================== */

// count the number of call ins
VOID c_counter(ADDRINT ip, ADDRINT target, ADDRINT next){
	//if ins is call and it's next address is in below range (ignore other unrelated place), count it.
	if(next < execHigh && next > execLow){
		if(STK_Search(symbols, target)){
			if(libcAcc && target < libcHigh && target > libcLow){
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
		}
		// else if(COP_DECT){ // attacker call func@libc directly from text section is disable, but overwrite got is able. 
		// 	cerr << "[COP] attack detected !!!";
		// 	cerr << "call for 0x" << target << " is invaild!!!" << endl;
		// 	// exit(0);
		// 	// need another method to defend got overwrite attack(JOP??)
		// }
	}
	if(libcAcc && next < libcHigh && next > libcLow){
		c_count++;
	}
}

// count the number of ret ins
VOID r_counter(ADDRINT ip, ADDRINT target){
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
			cerr << "ret[" << std::dec << r_count  << "] to 0x" << hex << target << " @ 0x"<< std::hex << ip << endl;
		}
	}
	if(libcAcc && target < libcHigh && target > libcLow){
		r_count++;
	}
}

// count the number of branch ins
VOID b_check(ADDRINT ip, ADDRINT target){
	if(STK_Search(symbols, ip) && JOP_DECT && libcAcc){
		cerr << hex << "jmp @ 0x" << ip << " to 0x" << target << endl;
		// got can be modified only 1 time
		if(target < execHigh && target > execLow){
			// cerr << "branch @ 0x" << hex << ip << " -> 0x" << next << endl;
		}
		else{
			string a = STK_QueryNameByAddr(symbols_libc, target);
			string b = STK_QueryNameByAddr(symbols, ip);
			cerr << "a: " << a << " | b: " << b << endl;
			if( b == a+"@plt"){
				// compare symbols name 
			}
			else{
				cerr << "[JOP] got overwrite dect!!!!!" << endl;
			}
		}
	}
	//if ins is ret and it would return in below range of address (ignore other unrelated place), count it.
}

INT32 check(INS ins){
	return(INS_IsRet(ins) | INS_IsCall(ins) << 1 | INS_IsBranch(ins) << 2);
}

VOID Instruction(INS ins, VOID *v) {
	int flag = check(ins);
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
	if( libcAcc && CRB_DECT && r_count > c_count ){
		cerr << "[CRB] WARNNING!!!" << endl;
		// exit(0);
	}
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
	symbols_libc = new(LinkStack);

	STK_Init(lstack);
	STK_Init(symbols);
	STK_Init(symbols_libc);

	PIN_InitSymbols();

	if( PIN_Init(argc,argv) ) {
		return Usage();
	}

	// Register ImageLoad to be called when an image is loaded
	printf("done\n");
	IMG_AddInstrumentFunction(ImageLoad, 0);

	// Register ImageUnload to be called when an image is unloaded
    IMG_AddUnloadFunction(ImageUnload, 0);

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
// 3.gadget length ?
// 4.got protect

// handel
// ROP JOP return-into-libc

// shadowstack cannot handle jop
// what to do when pin has vulnerability? protect got

// trace point set? 
// some func(e.g. printf) in libc do not obey call-ret balance 
// it still difficult to deal with by shadow stack... because of setjmp etc
