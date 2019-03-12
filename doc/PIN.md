# Example of APIs

## Register Instruction to be called to instrument instructions
```
	VOID Instruction(INS ins, VOID *v){

		//...

		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)xxxFunc, IARG_END);

		/*
		INS_InsertCall( INS ins,
						IPOINT action,
						AFUNPTR funptr,
						...)
		*/
	}

    INS_AddInstrumentFunction(Instruction, 0);
```

## Register Routine to be called to instrument rtn
```
	// Pin calls this function every time a new rtn is executed
	VOID Routine(RTN rtn, VOID *v){

		//...
		
		// Insert a call at the entry point of a routine
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)xxxFunc, IARG_PTR, xxxargs, IARG_END);

	}

    RTN_AddInstrumentFunction(Routine, 0);
```

## 
```
	VOID ImageLoad(IMG img, VOID *v){
    	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        // RTN_InsertCall() and INS_InsertCall() are executed in order of
        // appearance.  In the code sequence below, the IPOINT_AFTER is
        // executed before the IPOINT_BEFORE.
        	for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)){
            	// Open the RTN.
            	RTN_Open( rtn );
                // IPOINT_AFTER is implemented by instrumenting each return
            	// instruction in a routine.  Pin tries to find all return
            	// instructions, but success is not guaranteed.
            	RTN_InsertCall( rtn, IPOINT_AFTER, (AFUNPTR)After, IARG_CONTEXT, IARG_END);
             
			 	// Examine each instruction in the routine.
            	for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) ){
                	if( INS_IsRet(ins) ){
                    	// instrument each return instruction.
                    	// IPOINT_TAKEN_BRANCH always occurs last.
                    	INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)Before,
                        	           IARG_CONTEXT, IARG_END);
                    	INS_InsertCall( ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)Taken,
                            	       IARG_CONTEXT, IARG_END);
                	}
            	}
            	// Close the RTN.
            	RTN_Close( rtn );
        	}
    	}
	}
```
## Example for set up Condition
```
    if (INS_Opcode(ins) == XED_ICLASS_MOV &&
        INS_IsMemoryRead(ins) &&
        INS_OperandIsReg(ins, 0) &&
        INS_OperandIsMemory(ins, 1))
```

## Probe mode (statical analysis)
Get symbols of application
``` 
	PIN_InitSymbols();
```

## layer of application
  - Image -> routine -> instruction

## useful APIs 
 - `INS_Rtn(INS)`		指令所在的函数
 - `INS_Address(INS)`	指令的地址
 - `INS_IsNop/IsCall/IsBranch/IsCall/IsRet(INS)`
 - 
