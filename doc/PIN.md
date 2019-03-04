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

