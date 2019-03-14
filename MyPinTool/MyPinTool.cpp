/*BEGIN_LEGAL
Intel Open Source License

Copyright (c) 2002-2017 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/*! @file
*  This file contains an ISA-portable PIN tool for counting dynamic instructions
*/

#include "pin.H"
#include <iostream>
#include <fstream>

#define G_SIZE 7
#define LIBC "/lib/x86_64-linux-gnu/libc.so.6"
#define BALANCE c_count-r_count

static int g_count = 0;
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

// static bool libcAcc = 0;
// static bool execAcc = 0;

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
	// 	cerr << "Libc (" << IMG_Name(img).c_str() << ")" ;
	// 	cerr << "loaded: 0x" << hex << IMG_LowAddress(img);
	// 	cerr << " - 0x" << hex << IMG_HighAddress(img) << endl;
	// 	libcAcc = 1;

		libcLow = IMG_LowAddress(img);
		libcHigh = IMG_HighAddress(img);

		RTN rtn__libc_start_main = RTN_FindByName(img, "__libc_start_main");
		start_main = RTN_Address(rtn__libc_start_main) + 229;
		// mainHigh = mainLow + RTN_Size(rtn_main) - 1 ;
	}

	if(IMG_IsMainExecutable(img)) {
		// cerr << "Main Executable (" << IMG_Name(img).c_str() << ")" ;
		// cerr << "loaded: 0x" << hex << IMG_LowAddress(img);
		// cerr << " - 0x" << hex << IMG_HighAddress(img) << endl;

		// libcAcc = 1;
		// execAcc = 1;

		execLow = IMG_LowAddress(img);
		execHigh = IMG_HighAddress(img);

		RTN rtn_main = RTN_FindByName(img, "main");

		mainLow  = RTN_Address(rtn_main);
		mainHigh = mainLow + RTN_Size(rtn_main) - 1 ;

		// cerr << std::hex << "0x" << mainLow << " - 0x" << mainHigh << endl;
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
VOID g_counter(){
	g_count++;
}

VOID c_counter(ADDRINT ip, ADDRINT next){
	if((next < execHigh && next > execLow) || (next < libcHigh && next > libcLow)){
		c_count++;
		cerr << "call[" << std::dec << c_count  << "] @ 0x"<< std::hex << ip << endl;
		cerr << "next: 0x" << std::hex << next << endl;
	}
}

VOID r_counter(ADDRINT ip, ADDRINT next){
	if((next < execHigh && next > execLow) || (next < libcHigh && next > libcLow)){
		r_count++;
		cerr << "ret[" << std::dec << r_count  << "] @ 0x"<< std::hex << next << endl;
	}
	if(r_count > c_count){
		cerr << "WARNNING!" << endl;
	}
}

INT32 check(INS ins){
	return(INS_IsRet(ins) | INS_IsCall(ins) << 1 | INS_IsBranch(ins) << 2);
}

// print pc and next pc
VOID printip(VOID *ip, VOID *next) { 
    cerr << "[--] " << std::hex << ip << endl;
	cerr << "[->] " << std::hex << next << endl << endl;
}

// VOID logic(ADDRINT adr, ADDRINT next){
// 	g_counter();

// 	bool lib = 1;
// 	bool exe = 1;

// 	if((next < libcLow || next > libcHigh) && libcAcc){ 
// 		// if ins is not in libc, we do not consider it part of a gadget
// 		lib = 0;
// 	}

// 	if((next < execLow || next > execHigh) && execAcc){ 
// 		// if ins is not in elf, we do not consider it part of a gadget
// 		exe = 0;
// 	}

// 	if(!lib && !exe){
// 		g_count = 0;
// 		return;
// 	}

// 	if(g_count > G_SIZE){
// 		// not gadget. reset counters.
// 		g_count = 0;
// 	}
// 	else{
// 		//if g_count < glength, a would-be gadget detected.
// 		g_count = 0;

// 		// cerr << "[--] " << std::hex << adr << endl;
// 		// cerr << "[->] " << std::hex << next << endl;

// 		if(BALANCE != 0){
// 			// cerr << "NAIVE! - " << BALANCE << endl << endl;
// 		}
// 	}
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
			// INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_counter, IARG_BRANCH_TARGET_ADDR, IARG_END);
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_counter, 
				IARG_INST_PTR, 
				IARG_BRANCH_TARGET_ADDR, 
				IARG_END);
		}
	}
	if (ip == mainHigh){
		trace = 0;
	}
	// if(flag){
	// 	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)logic, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);
	// }
	// else{
	// 	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)g_counter, IARG_END);
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
