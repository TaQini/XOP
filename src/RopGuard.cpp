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

#define G_SIZE 6
#define S_LENGTH 4
#define LIBC "/lib/i386-linux-gnu/libc.so.6"

static int gcount = 0;
static int scount = 0;
static ADDRINT addresses [S_LENGTH];
static ADDRINT libcLow;
static ADDRINT libcHigh;
static ADDRINT execLow;
static ADDRINT execHigh;
//ofstream OutFile;
static bool libcAcc = 0;
static bool execAcc = 0;
static bool isret = false;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr <<
        "This tool detects ROP attacks.\n"
        "\n";

    cerr << endl;

    return -1;
}

/* ===================================================================== */
VOID ImageLoad(IMG img, VOID *v)
{
                if(IMG_Name(img).compare(LIBC) == 0) {
                                printf("Libc (%s) loaded: 0x%x - 0x%x\n", IMG_Name(img).c_str(), IMG_LowAddress(img), IMG_HighAddress(img));
                                libcAcc = 1;

                libcLow = IMG_LowAddress(img);
                libcHigh = IMG_HighAddress(img);
                }

                if(IMG_IsMainExecutable(img)) {
                                printf("Main Executable (%s) loaded: 0x%x - 0x%x\n", IMG_Name(img).c_str(), IMG_LowAddress(img), IMG_HighAddress(img));
                                execAcc = 1;

                execLow = IMG_LowAddress(img);
                execHigh = IMG_HighAddress(img);
                }
}

/* ===================================================================== */

VOID gcounter(){
        gcount++;
}

VOID logic(ADDRINT adr){
        gcounter();

        bool lib = 1;
        bool exe = 1;

        if(adr < libcLow || adr > libcHigh && libcAcc){ // if ins is not in libc, we do not consider it part of a gadget
                lib = 0;
        }

        if(adr < execLow || adr > execHigh && execAcc){ // if ins is not in libc, we do not consider it part of a gadget
                exe = 0;
        }

        if(!lib && !exe){
                gcount = 0;
                scount = 0;
                return;
        }

        addresses[scount] = adr;

//check if instruction is ret
                if(gcount > G_SIZE){
                        gcount = 0;
                        scount = 0;
                }//if gcount > glength, no gadget. reset counters.

                else{
                        //if gcount < glength, gadget detected. Reset gcount, increment scount,
                        // and check scount vs slength.
                        gcount = 0;
                        scount ++;
                        if(scount >= S_LENGTH){
 //                               cout << "Rop detected. Gadget Addresses at: " << endl;

                                for(int i=0; i< S_LENGTH; ++i){
                                         char hex[40];
                                        sprintf(hex, "%x", addresses[i]);
 //                                       cout << hex << endl;
                                 }

 //                               exit(0);
                        }//if scount >= slength, ROP detected. Terminate program and print output.

                }//if gcount <= glength

}
VOID Instruction(INS ins, VOID *v)
{

        isret = LEVEL_CORE::INS_IsRet(ins);
        if(isret){
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)logic, IARG_BRANCH_TARGET_ADDR, IARG_END);
        }
        else{
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)gcounter, IARG_BRANCH_TARGET_ADDR, IARG_END);
        }

}//Instruction
// (gconut+++++) --> ret -| gcount > G_SIZE -> normal ins
//                       -| gcount < G-SIZE -> gadget

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

